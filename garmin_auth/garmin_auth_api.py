#!/usr/bin/env python3
"""Garmin Auth Add-on: HTTP API for browser-based Garmin Connect authentication.

Runs a lightweight aiohttp server on port 8099 that the Garmin Connect
integration calls during its config flow.  Browser operations (Selenium)
run in a thread pool to keep the event loop responsive.

Auth-only model: the browser is used solely for login and DI token extraction.
After tokens are extracted, the browser is closed and the integration uses
them via normal HTTP calls to Garmin's APIs.

Supports multiple Garmin accounts via per-user browser profiles.
"""

import asyncio
import base64
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests as http_requests
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

_executor = ThreadPoolExecutor(max_workers=1)
_login_lock = asyncio.Lock()

# ── Per-user session registry ────────────────────────────────────
#
# Each registered user gets an isolated directory under SESSIONS_DIR
# containing a browser_profile/, session.json, and credentials.json.

_sessions: dict[str, dict] = {}
_active_email: str | None = None
_active_gc = None


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

# Constants matching python-garminconnect for DI token exchange
SSO_BASE = "https://sso.garmin.com"
PORTAL_SSO_CLIENT_ID = "GarminConnect"
PORTAL_SSO_SERVICE_URL = "https://connect.garmin.com/app"
DI_TOKEN_URL = "https://diauth.garmin.com/di-oauth2-service/oauth/token"
DI_GRANT_TYPE = (
    "https://connectapi.garmin.com/di-oauth2-service/oauth/grant/service_ticket"
)
DI_CLIENT_IDS = (
    "GARMIN_CONNECT_MOBILE_ANDROID_DI_2025Q2",
    "GARMIN_CONNECT_MOBILE_ANDROID_DI_2024Q4",
    "GARMIN_CONNECT_MOBILE_ANDROID_DI",
)


def _wait_for_cf_clearance(driver, timeout: int = 45) -> bool:
    """Poll the browser until the Cloudflare challenge resolves.

    Returns True once the page title no longer contains 'Just a moment'
    (the CF challenge indicator) and the DOM is ready.
    """
    start = time.time()
    while time.time() - start < timeout:
        try:
            title = driver.execute_script("return document.title || ''")
            if "just a moment" not in title.lower():
                ready = driver.execute_script(
                    "return document.readyState === 'complete'"
                )
                if ready:
                    return True
        except Exception:
            # UC mode may disconnect CDP during CF handling — that's OK
            pass
        time.sleep(1)
    return False


def _extract_di_tokens(gc, email: str = "", password: str = "") -> dict:
    """Get DI OAuth2 tokens using the browser to bypass Cloudflare.

    Navigates the already-open Selenium browser to the SSO sign-in page
    using SeleniumBase UC mode (which handles CF challenges automatically),
    then uses a same-origin JS fetch() to POST credentials to the portal
    login API.  The resulting service ticket is exchanged server-side for
    DI OAuth2 Bearer tokens.

    This avoids the 30-45 second server-side CF delay entirely.
    """
    if not email or not password:
        log.warning("Email/password not provided for DI token extraction")
        return {}

    driver = getattr(gc, "_driver", None)
    if driver is None:
        log.warning("No browser driver available for DI extraction")
        return {}

    # Step 1: Navigate to SSO sign-in page (UC mode handles CF challenge)
    signin_url = (
        f"{SSO_BASE}/portal/sso/en-US/sign-in"
        f"?clientId={PORTAL_SSO_CLIENT_ID}"
        f"&service={PORTAL_SSO_SERVICE_URL}"
    )
    log.debug("Navigating browser to SSO for DI token extraction")
    try:
        driver.uc_open_with_reconnect(signin_url, 12)
    except Exception as e:
        log.debug("UC navigate to SSO failed: %s", e)
        return {}

    # Step 2: Wait for CF challenge to resolve
    if not _wait_for_cf_clearance(driver, timeout=45):
        log.warning("CF challenge did not resolve within timeout")
        return {}

    log.debug("CF challenge resolved — posting credentials via JS fetch")

    # Step 3: POST credentials via same-origin JS fetch (no CORS issues)
    login_api = (
        f"/portal/api/login"
        f"?clientId={PORTAL_SSO_CLIENT_ID}"
        f"&locale=en-US"
        f"&service={PORTAL_SSO_SERVICE_URL}"
    )

    js_fetch = """
    var callback = arguments[arguments.length - 1];
    (async function() {
        try {
            var resp = await fetch(arguments[0], {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json, text/plain, */*'
                },
                body: JSON.stringify({
                    username: arguments[1],
                    password: arguments[2],
                    rememberMe: true,
                    captchaToken: ''
                })
            });
            var text = await resp.text();
            return {status: resp.status, body: text};
        } catch(e) {
            return {error: e.toString()};
        }
    })().then(callback).catch(function(e) {
        callback({error: e.toString()});
    });
    """

    try:
        result = driver.execute_async_script(js_fetch, login_api, email, password)
    except Exception as e:
        log.debug("JS portal login fetch failed: %s", e)
        return {}

    if not result or result.get("error"):
        log.debug("Portal login JS error: %s", result)
        return {}

    status = result.get("status", 0)
    body = result.get("body", "")

    if status == 429:
        log.warning("Portal login rate limited (429)")
        return {}

    try:
        data = json.loads(body)
    except Exception:
        log.debug("Portal login returned non-JSON (HTTP %d): %.200s", status, body)
        return {}

    resp_type = data.get("responseStatus", {}).get("type")
    ticket = data.get("serviceTicketId")

    if resp_type != "SUCCESSFUL" or not ticket:
        log.debug("Portal login: type=%s (expected SUCCESSFUL)", resp_type)
        return {}

    log.debug("Got CAS service ticket via browser: %s...", ticket[:20])

    # Step 4: Exchange service ticket for DI tokens (server-side)
    for client_id in DI_CLIENT_IDS:
        auth = "Basic " + base64.b64encode(f"{client_id}:".encode()).decode()
        try:
            r = http_requests.post(
                DI_TOKEN_URL,
                headers={
                    "Authorization": auth,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
                data={
                    "client_id": client_id,
                    "service_ticket": ticket,
                    "grant_type": DI_GRANT_TYPE,
                    "service_url": PORTAL_SSO_SERVICE_URL,
                },
                timeout=30,
            )
        except Exception as e:
            log.debug("DI exchange request failed for %s: %s", client_id, e)
            continue

        if not r.ok:
            log.debug(
                "DI exchange failed for %s: %d %s",
                client_id,
                r.status_code,
                r.text[:200],
            )
            continue

        try:
            data = r.json()
            log.info("DI token obtained via client %s", client_id)
            return {
                "di_token": data["access_token"],
                "di_refresh_token": data.get("refresh_token"),
                "di_client_id": client_id,
            }
        except Exception as e:
            log.debug("DI token parse failed for %s: %s", client_id, e)
            continue

    log.warning("DI token extraction failed for all client IDs")
    return {}


def _do_login(email: str, password: str) -> dict:
    """Perform browser-based Garmin login (blocking).

    Uses a per-user browser profile so each account's cookies are isolated.
    On success extracts both JWT_WEB/CSRF and DI Bearer tokens.
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

    # Try to extract DI tokens (needed for connectapi.garmin.com)
    di_tokens = _extract_di_tokens(gc, email=email, password=password)
    if di_tokens:
        tokens.update(di_tokens)
    else:
        log.warning(
            "Could not extract DI tokens — API calls may fail with 403. "
            "JWT_WEB fallback will be attempted."
        )

    return {"status": "ok", "tokens": tokens, "_gc": gc}


def _do_mfa(gc, code: str, email: str = "", password: str = "") -> dict:
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

    # Try to extract DI tokens (needed for connectapi.garmin.com)
    di_tokens = _extract_di_tokens(gc, email=email, password=password)
    if di_tokens:
        tokens.update(di_tokens)
    else:
        log.warning(
            "Could not extract DI tokens after MFA — API calls may fail with 403."
        )

    return {"status": "ok", "tokens": tokens, "_gc": gc}


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
            "browser_active": _active_gc is not None,
            "logged_in_email": _active_email,
            "registered_users": list(_sessions.keys()),
        }
    )


async def handle_login(request):
    """POST /api/login — start browser-based login.

    Body: {"email": "...", "password": "..."}
    Returns: {"status": "ok", "tokens": {...}} or {"status": "needs_mfa"}

    After successful login, tokens are extracted and the browser is closed.
    The user's profile and credentials are stored for future logins.
    """
    global _active_gc, _active_email

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
            gc = result.pop("_gc")
            _register_session(email, password)
            # Close the browser immediately — tokens have been extracted
            # and the integration uses them via normal HTTP calls.
            await loop.run_in_executor(_executor, _do_close_browser, gc)
            _active_gc = None
            _active_email = email
            log.info("Login successful — tokens extracted, browser closed")
        else:
            log.warning("Login failed: %s", result.get("message"))

        return web.json_response(result)


async def handle_mfa(request):
    """POST /api/mfa — submit MFA code to the waiting browser.

    Body: {"code": "123456"}
    Returns: {"status": "ok", "tokens": {...}}
    """
    global _active_gc

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

    # Get credentials for DI token extraction
    mfa_email = _active_email or ""
    mfa_password = ""
    if mfa_email:
        key = _user_key(mfa_email)
        sess_data = _sessions.get(key, {})
        mfa_password = sess_data.get("password", "")

    log.info("Submitting MFA code (%d chars)", len(code))
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        _executor, _do_mfa, gc, code, mfa_email, mfa_password
    )

    if result["status"] == "ok":
        gc = result.pop("_gc")
        await loop.run_in_executor(_executor, _do_close_browser, gc)
        _active_gc = None
        log.info("MFA successful — tokens extracted, browser closed")
    else:
        _active_gc = None
        log.warning("MFA failed: %s", result.get("message"))

    return web.json_response(result)


# ── Application ──────────────────────────────────────────────────


VERSION = "0.8.0"


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api/health", handle_health)
    app.router.add_post("/api/login", handle_login)
    app.router.add_post("/api/mfa", handle_mfa)
    app.on_startup.append(_on_startup)
    return app


async def _on_startup(app):
    """Log readiness."""
    log.info("Garmin Auth API v%s ready — listening on port %d", VERSION, API_PORT)
    routes = [r.resource.canonical for r in app.router.routes() if r.resource]
    log.info("Registered routes: %s", ", ".join(sorted(set(routes))))


if __name__ == "__main__":
    _load_all_credentials()
    log.info("Starting Garmin Auth API v%s on port %d", VERSION, API_PORT)
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=API_PORT)
