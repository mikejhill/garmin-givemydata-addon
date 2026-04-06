#!/usr/bin/env python3
"""Garmin Auth Add-on: HTTP API for browser-based Garmin Connect authentication.

Runs a lightweight aiohttp server on port 8099 that the Garmin Connect
integration calls during its config flow and for ongoing API requests.
Browser operations (Selenium) run in a thread pool to keep the event loop
responsive.

The browser session is kept alive after login so that subsequent API calls
can be proxied through the browser's authenticated fetch context — the same
pattern garmin-givemydata uses for all its API calls.
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

BROWSER_PROFILE_DIR = Path("/data/browser_profile")
SESSION_FILE = Path("/data/garmin_session.json")
CREDENTIALS_FILE = Path("/data/.credentials.json")
API_PORT = 8099

# Browser idle timeout — close after 10 min of no API calls to save RAM
BROWSER_IDLE_TIMEOUT = 600

_executor = ThreadPoolExecutor(max_workers=1)
_login_lock = asyncio.Lock()

# Persistent browser state — kept alive for API proxying
_browser_client = None
_browser_email = None
_browser_password = None
_last_api_call = 0.0


def _load_stored_credentials() -> None:
    """Load credentials saved from a previous login (survives add-on restart)."""
    global _browser_email, _browser_password
    if CREDENTIALS_FILE.exists():
        try:
            creds = json.loads(CREDENTIALS_FILE.read_text())
            _browser_email = creds.get("email")
            _browser_password = creds.get("password")
            if _browser_email:
                log.info("Loaded stored credentials for %s", _browser_email)
        except Exception:
            log.debug("Could not load stored credentials", exc_info=True)


def _save_credentials(email: str, password: str) -> None:
    """Persist credentials so the add-on can re-login after restart."""
    try:
        CREDENTIALS_FILE.write_text(json.dumps({"email": email, "password": password}))
        CREDENTIALS_FILE.chmod(0o600)
    except Exception:
        log.debug("Could not save credentials", exc_info=True)


# ── Blocking browser operations (run in executor) ───────────────


def _do_login(email: str, password: str) -> dict:
    """Perform browser-based Garmin login (blocking).

    On success the GarminClient is returned (key ``_gc``) so the caller
    can keep the browser alive for API proxying.
    """
    from garmin_client import GarminClient

    gc = GarminClient(
        email=email,
        password=password,
        headless=True,
        profile_dir=BROWSER_PROFILE_DIR,
        session_file=SESSION_FILE,
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
    """Proxy an API request through the browser's fetch context (blocking).

    Uses the same pattern as garmin-givemydata's api_fetch(): runs
    JavaScript fetch() inside the authenticated browser page so that
    all cookies and TLS fingerprinting are handled by Chrome.
    """
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


# ── HTTP handlers ────────────────────────────────────────────────


async def handle_health(request):
    """GET /api/health — liveness check with browser status."""
    return web.json_response(
        {
            "status": "ok",
            "browser_active": _browser_client is not None,
        }
    )


async def handle_login(request):
    """POST /api/login — start browser-based login.

    Body: {"email": "...", "password": "..."}
    Returns: {"status": "ok", "tokens": {...}} or {"status": "needs_mfa"}

    After successful login the browser stays alive for API proxying.
    """
    global _browser_client, _browser_email, _browser_password, _last_api_call

    data = await request.json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return web.json_response(
            {"status": "error", "message": "email and password required"},
            status=400,
        )

    async with _login_lock:
        # Close any existing browser session
        if _browser_client is not None:
            log.info("Closing previous browser session")
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(_executor, _do_close_browser, _browser_client)
            _browser_client = None

        log.info("Starting browser login for %s", email)
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(_executor, _do_login, email, password)

        if result["status"] == "needs_mfa":
            _browser_client = result.pop("_gc")
            _browser_email = email
            _browser_password = password
            _save_credentials(email, password)
            log.info("MFA required — browser kept alive for code submission")
            return web.json_response({"status": "needs_mfa"})

        if result["status"] == "ok":
            _browser_client = result.pop("_gc")
            _browser_email = email
            _browser_password = password
            _save_credentials(email, password)
            _last_api_call = time.time()
            log.info("Login successful — browser kept alive for API proxying")
        else:
            log.warning("Login failed: %s", result.get("message"))

        return web.json_response(result)


async def handle_mfa(request):
    """POST /api/mfa — submit MFA code to the waiting browser.

    Body: {"code": "123456"}
    Returns: {"status": "ok", "tokens": {...}}
    """
    global _browser_client, _last_api_call

    data = await request.json()
    code = data.get("code")

    if not code:
        return web.json_response(
            {"status": "error", "message": "code required"},
            status=400,
        )

    if _browser_client is None:
        return web.json_response(
            {"status": "error", "message": "No pending MFA session"},
            status=400,
        )

    gc = _browser_client

    log.info("Submitting MFA code (%d chars)", len(code))
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(_executor, _do_mfa, gc, code)

    if result["status"] == "ok":
        _browser_client = result.pop("_gc")
        _last_api_call = time.time()
        log.info("MFA successful — browser kept alive for API proxying")
    else:
        _browser_client = None
        log.warning("MFA failed: %s", result.get("message"))

    return web.json_response(result)


async def handle_fetch(request):
    """POST /api/fetch — proxy an API request through the browser.

    Body: {"path": "/gc-api/...", "method": "GET"}
    Returns: the upstream response (status code + JSON body).

    The request is executed via the browser's JavaScript fetch() context,
    which automatically includes all cookies and TLS fingerprinting.
    """
    global _browser_client, _last_api_call

    data = await request.json()
    path = data.get("path")
    method = data.get("method", "GET").upper()

    if not path:
        return web.json_response(
            {"status": "error", "message": "path required"}, status=400
        )

    if _browser_client is None:
        # Try to re-establish browser session with stored credentials
        if _browser_email and _browser_password:
            log.info("Browser closed — re-establishing session")
            async with _login_lock:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    _executor, _do_login, _browser_email, _browser_password
                )
                if result["status"] == "ok":
                    _browser_client = result.pop("_gc")
                    _last_api_call = time.time()
                    log.info("Browser session re-established")
                else:
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
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        _executor, _do_api_fetch, _browser_client, path, method
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
    global _browser_client
    while True:
        await asyncio.sleep(60)
        if (
            _browser_client is not None
            and _last_api_call > 0
            and time.time() - _last_api_call > BROWSER_IDLE_TIMEOUT
        ):
            log.info(
                "Browser idle for %ds — closing to save RAM",
                int(time.time() - _last_api_call),
            )
            gc = _browser_client
            _browser_client = None
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(_executor, _do_close_browser, gc)


# ── Application ──────────────────────────────────────────────────


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api/health", handle_health)
    app.router.add_post("/api/login", handle_login)
    app.router.add_post("/api/mfa", handle_mfa)
    app.router.add_post("/api/fetch", handle_fetch)
    app.on_startup.append(lambda app: asyncio.ensure_future(_idle_browser_cleanup(app)))
    return app


if __name__ == "__main__":
    _load_stored_credentials()
    log.info("Starting Garmin Auth API on port %d", API_PORT)
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=API_PORT)
