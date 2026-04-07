#!/usr/bin/env python3
"""Garmin Auth Add-on: HTTP API for browser-based Garmin Connect authentication.

Runs a lightweight aiohttp server on port 8099 that the Garmin Connect
integration calls during its config flow and for ongoing API requests.
Browser operations (Selenium) run in a thread pool to keep the event loop
responsive.

Supports multiple Garmin accounts via per-user browser profiles.  Only one
browser instance runs at a time to conserve RAM; when a request arrives for
a different user the current browser is saved and a new one is opened with
the target user's profile (fast session restore, ~10-15 s).
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aiohttp import web

# Read add-on options (HA writes them to /data/options.json)
_OPTIONS_FILE = Path("/data/options.json")
_log_level_str = "info"
if _OPTIONS_FILE.exists():
    try:
        _opts = json.loads(_OPTIONS_FILE.read_text())
        _log_level_str = _opts.get("log_level", "info")
    except Exception:
        pass

logging.basicConfig(
    level=getattr(logging, _log_level_str.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("garmin_auth")

SESSIONS_DIR = Path("/data/sessions")
API_PORT = 8099

# Browser idle timeout — close after 10 min of no API calls to save RAM
BROWSER_IDLE_TIMEOUT = 600

_executor = ThreadPoolExecutor(max_workers=1)
_login_lock = asyncio.Lock()

# ── Per-user session registry ────────────────────────────────────
#
# Each registered user gets an isolated directory under SESSIONS_DIR
# containing a browser_profile/, session.json, and credentials.json.
# Only ONE browser can be active at a time (_active_email).

_sessions: dict[str, dict] = {}
_active_email: str | None = None
_active_gc = None
_last_api_call: float = 0.0


def _user_key(email: str) -> str:
    """Normalise email to a consistent dict key."""
    return email.strip().lower()


def _user_dir(email: str) -> Path:
    """Return the per-user storage directory, creating it if needed."""
    d = SESSIONS_DIR / _user_key(email).replace("@", "_at_").replace(".", "_")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _profile_dir(email: str) -> Path:
    return _user_dir(email) / "browser_profile"


def _session_file(email: str) -> Path:
    return _user_dir(email) / "session.json"


def _credentials_file(email: str) -> Path:
    return _user_dir(email) / "credentials.json"


def _save_credentials(email: str, password: str) -> None:
    """Persist credentials for a user (survives add-on restart)."""
    try:
        f = _credentials_file(email)
        f.write_text(json.dumps({"email": email, "password": password}))
        f.chmod(0o600)
    except Exception:
        log.debug("Could not save credentials for %s", email, exc_info=True)


def _load_all_credentials() -> None:
    """Scan SESSIONS_DIR for saved credentials and register sessions."""
    if not SESSIONS_DIR.exists():
        return
    for user_d in SESSIONS_DIR.iterdir():
        cred_file = user_d / "credentials.json"
        if cred_file.exists():
            try:
                creds = json.loads(cred_file.read_text())
                email = creds.get("email", "")
                password = creds.get("password", "")
                if email:
                    key = _user_key(email)
                    _sessions[key] = {
                        "email": email,
                        "password": password,
                        "last_api_call": 0.0,
                    }
                    log.info("Loaded stored credentials for %s", email)
            except Exception:
                log.debug(
                    "Could not load credentials from %s", cred_file, exc_info=True
                )


def _register_session(email: str, password: str) -> None:
    """Register or update a user session in the registry."""
    key = _user_key(email)
    _sessions[key] = {
        "email": email,
        "password": password,
        "last_api_call": time.time(),
    }
    _save_credentials(email, password)


# ── Blocking browser operations (run in executor) ───────────────


def _do_login(email: str, password: str) -> dict:
    """Perform browser-based Garmin login (blocking).

    Uses a per-user browser profile so each account's cookies are isolated.
    On success the GarminClient is returned (key ``_gc``).
    """
    from garmin_client import GarminClient

    profile = _profile_dir(email)
    session = _session_file(email)

    gc = GarminClient(
        email=email,
        password=password,
        headless=True,
        profile_dir=profile,
        session_file=session,
        install_signal_handlers=False,
    )

    try:
        result = gc.login(return_on_mfa=True)
    except Exception as e:
        gc.close()
        return {"status": "error", "message": f"Login failed: {e}"}

    if result == "needs_mfa":
        return {"status": "needs_mfa", "_gc": gc}

    if not result:
        gc.close()
        return {"status": "error", "message": "Browser login failed"}

    tokens = gc.get_auth_tokens()
    return {"status": "ok", "tokens": tokens, "_gc": gc}


def _do_mfa(gc, code: str) -> dict:
    """Submit MFA code via the browser (blocking)."""
    try:
        result = gc.submit_mfa(code)
    except Exception as e:
        gc.close()
        return {"status": "error", "message": f"MFA failed: {e}"}

    if not result:
        gc.close()
        return {"status": "error", "message": "MFA verification failed"}

    tokens = gc.get_auth_tokens()
    return {"status": "ok", "tokens": tokens, "_gc": gc}


def _do_api_fetch(gc, path: str, method: str = "GET") -> dict:
    """Proxy an API request through the browser's fetch context (blocking)."""
    gc._ensure_on_garmin()
    csrf = gc._ensure_csrf()

    try:
        result = gc._driver.execute_async_script(
            """
            var callback = arguments[arguments.length - 1];
            var url = arguments[0];
            var csrf = arguments[1];
            var method = arguments[2];
            (async function() {
                try {
                    var resp = await fetch(url, {
                        method: method,
                        credentials: 'include',
                        headers: {
                            'connect-csrf-token': csrf || '',
                            'Accept': 'application/json',
                            'NK': 'NT'
                        }
                    });
                    var body = await resp.text();
                    return {status: resp.status, body: body};
                } catch(e) {
                    return {error: e.toString()};
                }
            })().then(callback).catch(function(e) {
                callback({error: e.toString()});
            });
        """,
            path,
            csrf,
            method,
        )
    except Exception as e:
        return {"error": str(e)}

    return result or {"error": "No response from browser"}


def _do_close_browser(gc) -> None:
    """Close the browser session (blocking)."""
    try:
        gc.close()
    except Exception:
        pass


# ── Session switching ────────────────────────────────────────────


async def _switch_to_user(email: str) -> bool:
    """Switch the active browser to *email*'s session.

    Closes the current browser (saving cookies via the per-user profile),
    then opens a new browser with the target user's profile for a fast
    session restore.  Must be called inside ``_login_lock``.

    Returns True on success; False if the target user has no stored
    credentials and cannot be logged in.
    """
    global _active_email, _active_gc, _last_api_call

    loop = asyncio.get_event_loop()

    # Pre-flight: verify the target has credentials BEFORE tearing down
    # the current browser, so a failed switch doesn't orphan the active session.
    key = _user_key(email)
    sess = _sessions.get(key)
    if not sess or not sess.get("password"):
        log.error("No stored credentials for %s — cannot switch", email)
        return False

    # Close current browser (profile auto-saves cookies on exit)
    if _active_gc is not None:
        log.info("Saving session for %s before switching", _active_email)
        await loop.run_in_executor(_executor, _do_close_browser, _active_gc)
        _active_gc = None

    log.info("Switching browser session to %s", email)
    result = await loop.run_in_executor(
        _executor, _do_login, sess["email"], sess["password"]
    )

    if result.get("status") == "ok":
        _active_gc = result.pop("_gc")
        _active_email = email
        _last_api_call = time.time()
        sess["last_api_call"] = _last_api_call
        log.info("Session switch to %s complete", email)
        return True

    if result.get("status") == "needs_mfa":
        # MFA needed — can't auto-switch.  Close the half-started browser.
        gc = result.pop("_gc", None)
        if gc:
            await loop.run_in_executor(_executor, _do_close_browser, gc)
        log.warning("Cannot auto-switch to %s — MFA required", email)
        return False

    log.error("Session switch to %s failed: %s", email, result.get("message"))
    return False


# ── HTTP handlers ────────────────────────────────────────────────


async def handle_health(request):
    """GET /api/health — liveness check with browser status."""
    return web.json_response(
        {
            "status": "ok",
            "browser_active": _active_gc is not None,
            "logged_in_email": _active_email,
            "registered_users": list(_sessions.keys()),
        }
    )


async def handle_login(request):
    """POST /api/login — start browser-based login.

    Body: {"email": "...", "password": "..."}
    Returns: {"status": "ok", "tokens": {...}} or {"status": "needs_mfa"}

    After successful login the browser stays alive for API proxying.
    The user's profile and credentials are stored for future fast switching.
    """
    global _active_gc, _active_email, _last_api_call

    data = await request.json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return web.json_response(
            {"status": "error", "message": "email and password required"},
            status=400,
        )

    async with _login_lock:
        loop = asyncio.get_event_loop()

        # Close any existing browser session
        if _active_gc is not None:
            log.info("Closing previous browser session (%s)", _active_email)
            await loop.run_in_executor(_executor, _do_close_browser, _active_gc)
            _active_gc = None

        log.info("Starting browser login for %s", email)
        result = await loop.run_in_executor(_executor, _do_login, email, password)

        if result["status"] == "needs_mfa":
            _active_gc = result.pop("_gc")
            _active_email = email
            _register_session(email, password)
            log.info("MFA required — browser kept alive for code submission")
            return web.json_response({"status": "needs_mfa"})

        if result["status"] == "ok":
            _active_gc = result.pop("_gc")
            _active_email = email
            _last_api_call = time.time()
            _register_session(email, password)
            log.info("Login successful — browser kept alive for API proxying")
        else:
            log.warning("Login failed: %s", result.get("message"))

        return web.json_response(result)


async def handle_mfa(request):
    """POST /api/mfa — submit MFA code to the waiting browser.

    Body: {"code": "123456"}
    Returns: {"status": "ok", "tokens": {...}}
    """
    global _active_gc, _last_api_call

    data = await request.json()
    code = data.get("code")

    if not code:
        return web.json_response(
            {"status": "error", "message": "code required"},
            status=400,
        )

    if _active_gc is None:
        return web.json_response(
            {"status": "error", "message": "No pending MFA session"},
            status=400,
        )

    gc = _active_gc

    log.info("Submitting MFA code (%d chars)", len(code))
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(_executor, _do_mfa, gc, code)

    if result["status"] == "ok":
        _active_gc = result.pop("_gc")
        _last_api_call = time.time()
        log.info("MFA successful — browser kept alive for API proxying")
    else:
        _active_gc = None
        log.warning("MFA failed: %s", result.get("message"))

    return web.json_response(result)


async def handle_fetch(request):
    """POST /api/fetch — proxy an API request through the browser.

    Body: {"path": "/gc-api/...", "method": "GET", "email": "user@example.com"}
    Returns: the upstream response (status code + JSON body).

    When ``email`` is provided and differs from the active session, the
    add-on automatically switches to that user's browser profile (fast
    session restore via per-user cookies).
    """
    global _active_gc, _active_email, _last_api_call

    data = await request.json()
    path = data.get("path")
    method = data.get("method", "GET").upper()
    requested_email = data.get("email")

    if not path:
        return web.json_response(
            {"status": "error", "message": "path required"}, status=400
        )

    async with _login_lock:
        # Switch users if the request is for a different account
        if requested_email and _user_key(requested_email) != _user_key(
            _active_email or ""
        ):
            if _user_key(requested_email) in _sessions:
                ok = await _switch_to_user(requested_email)
                if not ok:
                    return web.json_response(
                        {
                            "status": "error",
                            "message": f"Cannot switch to {requested_email}",
                        },
                        status=401,
                    )
            else:
                # User never logged in via /api/login — don't disrupt the
                # current session; just tell the caller this user isn't set up.
                return web.json_response(
                    {
                        "status": "error",
                        "message": (
                            f"User {requested_email} not registered — "
                            "log in via the add-on first"
                        ),
                    },
                    status=401,
                )

        # Re-establish session if the browser was closed (idle timeout, etc.)
        if _active_gc is None:
            target = requested_email or _active_email
            if target and _user_key(target) in _sessions:
                log.info("Browser closed — re-establishing session for %s", target)
                ok = await _switch_to_user(target)
                if not ok:
                    return web.json_response(
                        {
                            "status": "error",
                            "message": "Browser session expired, re-login required",
                        },
                        status=401,
                    )
            else:
                return web.json_response(
                    {
                        "status": "error",
                        "message": "No active browser session — login first",
                    },
                    status=401,
                )

        _last_api_call = time.time()
        key = _user_key(_active_email) if _active_email else None
        if key and key in _sessions:
            _sessions[key]["last_api_call"] = _last_api_call

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            _executor, _do_api_fetch, _active_gc, path, method
        )

    if result.get("error"):
        log.warning("Browser fetch failed for %s: %s", path, result["error"])
        return web.json_response(result, status=502)

    status = result.get("status", 500)
    body = result.get("body", "")
    log.debug("Browser fetch %s %s → %d (%d bytes)", method, path, status, len(body))

    return web.Response(
        status=status,
        body=body,
        content_type="application/json",
    )


# ── Idle browser cleanup ────────────────────────────────────────


async def _idle_browser_cleanup(app):
    """Periodically close the browser if idle to conserve RAM."""
    global _active_gc
    while True:
        await asyncio.sleep(60)
        if (
            _active_gc is not None
            and _last_api_call > 0
            and time.time() - _last_api_call > BROWSER_IDLE_TIMEOUT
        ):
            log.info(
                "Browser idle for %ds — closing to save RAM",
                int(time.time() - _last_api_call),
            )
            gc = _active_gc
            _active_gc = None
            # Don't clear _active_email — it tracks the last user for re-login
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(_executor, _do_close_browser, gc)


# ── Application ──────────────────────────────────────────────────


VERSION = "0.4.1"


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api/health", handle_health)
    app.router.add_post("/api/login", handle_login)
    app.router.add_post("/api/mfa", handle_mfa)
    app.router.add_post("/api/fetch", handle_fetch)
    app.on_startup.append(_on_startup)
    return app


async def _on_startup(app):
    """Log readiness and start idle cleanup."""
    log.info("Garmin Auth API v%s ready — listening on port %d", VERSION, API_PORT)
    routes = [r.resource.canonical for r in app.router.routes() if r.resource]
    log.info("Registered routes: %s", ", ".join(sorted(set(routes))))
    asyncio.ensure_future(_idle_browser_cleanup(app))


if __name__ == "__main__":
    _load_all_credentials()
    log.info("Starting Garmin Auth API v%s on port %d", VERSION, API_PORT)
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=API_PORT)
