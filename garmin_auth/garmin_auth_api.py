#!/usr/bin/env python3
"""Garmin Auth Add-on: HTTP API for browser-based Garmin Connect authentication.

Runs a lightweight aiohttp server on port 8099 that the Garmin Connect
integration calls during its config flow.  Browser operations (Selenium)
run in a thread pool to keep the event loop responsive.
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aiohttp import web

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("garmin_auth")

BROWSER_PROFILE_DIR = Path("/data/browser_profile")
SESSION_FILE = Path("/data/garmin_session.json")
API_PORT = 8099

_executor = ThreadPoolExecutor(max_workers=1)
_login_lock = asyncio.Lock()
_browser_client = None


# ── Blocking browser operations (run in executor) ───────────────


def _do_login(email: str, password: str) -> dict:
    """Perform browser-based Garmin login (blocking)."""
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
    gc.close()
    return {"status": "ok", "tokens": tokens}


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
    gc.close()
    return {"status": "ok", "tokens": tokens}


# ── HTTP handlers ────────────────────────────────────────────────


async def handle_health(request):
    """GET /api/health — liveness check."""
    return web.json_response({"status": "ok"})


async def handle_login(request):
    """POST /api/login — start browser-based login.

    Body: {"email": "...", "password": "..."}
    Returns: {"status": "ok", "tokens": {...}} or {"status": "needs_mfa"}
    """
    global _browser_client

    data = await request.json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return web.json_response(
            {"status": "error", "message": "email and password required"},
            status=400,
        )

    async with _login_lock:
        if _browser_client is not None:
            log.info("Closing lingering browser from previous attempt")
            try:
                _browser_client.close()
            except Exception:
                pass
            _browser_client = None

        log.info("Starting browser login for %s", email)
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(_executor, _do_login, email, password)

        if result["status"] == "needs_mfa":
            _browser_client = result.pop("_gc")
            log.info("MFA required — browser kept alive for code submission")
            return web.json_response({"status": "needs_mfa"})

        if result["status"] == "ok":
            log.info("Login successful — tokens extracted")
        else:
            log.warning("Login failed: %s", result.get("message"))

        return web.json_response(result)


async def handle_mfa(request):
    """POST /api/mfa — submit MFA code to the waiting browser.

    Body: {"code": "123456"}
    Returns: {"status": "ok", "tokens": {...}}
    """
    global _browser_client

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
    _browser_client = None

    log.info("Submitting MFA code (%d chars)", len(code))
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(_executor, _do_mfa, gc, code)

    if result["status"] == "ok":
        log.info("MFA successful — tokens extracted")
    else:
        log.warning("MFA failed: %s", result.get("message"))

    return web.json_response(result)


# ── Application ──────────────────────────────────────────────────


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api/health", handle_health)
    app.router.add_post("/api/login", handle_login)
    app.router.add_post("/api/mfa", handle_mfa)
    return app


if __name__ == "__main__":
    log.info("Starting Garmin Auth API on port %d", API_PORT)
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=API_PORT)
