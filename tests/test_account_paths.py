"""Regression tests for account storage containment; no real accounts or browser."""

import asyncio
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

_SPEC = importlib.util.spec_from_file_location(
    "garmin_auth_api", Path(__file__).parents[1] / "garmin_auth" / "garmin_auth_api.py"
)
api = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(api)


class AccountPathTests(unittest.TestCase):
    """Keep account-owned files inside temporary session storage."""

    def test_path_syntax_is_rejected_without_creating_storage(self):
        """Absolute paths, separators, drive prefixes and controls fail closed."""
        for email in ("/tmp/account@example.invalid", "../account", r"..\account",
                      r"C:\account", "user:stream", "bad\x00name", "bad\nname", " ", 123):
            with self.subTest(email=email), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "sessions"
                with patch.object(api, "SESSIONS_DIR", root):
                    with self.assertRaises(ValueError):
                        api._user_dir(email)
                self.assertFalse(root.exists(), "Rejected accounts must not create storage")

    def test_normalized_account_keeps_existing_directory_and_contents(self):
        """Existing normal account paths remain compatible without migration."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            existing = root / "user_at_example_com"
            existing.mkdir()
            marker = existing / "session.json"
            marker.write_text("existing-session", encoding="utf-8")
            with patch.object(api, "SESSIONS_DIR", root):
                actual = api._user_dir(" User@Example.COM ")
            self.assertEqual(actual, existing, "Existing normalized account must keep its path")
            self.assertEqual(marker.read_text(encoding="utf-8"), "existing-session",
                             "Looking up an account must preserve existing content")

    def test_symlink_outside_storage_is_rejected(self):
        """An existing account symlink cannot redirect writes outside storage."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "sessions"
            outside = Path(tmp) / "sessions_other"
            root.mkdir()
            outside.mkdir()
            try:
                (root / "user_at_example_com").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Symlinks unavailable: {exc}")
            with patch.object(api, "SESSIONS_DIR", root), self.assertRaises(ValueError):
                api._user_dir("user@example.com")
            self.assertEqual(list(outside.iterdir()), [], "Rejected symlink must not write outside")

    def test_login_rejects_path_before_browser_or_session_changes(self):
        """Invalid account input returns 400 without launching authentication."""
        request = AsyncMock()
        request.json.return_value = {"email": "/tmp/account@example.invalid", "password": "synthetic"}
        with patch.object(api, "_do_login") as login:
            response = asyncio.run(api.handle_login(request))
        self.assertEqual(response.status, 400, "Path-shaped accounts must produce HTTP 400")
        login.assert_not_called()


class AuthenticationDiagnosticTests(unittest.TestCase):
    """Synthetic responses exercise real token extraction without browser/network."""

    def test_ticket_and_failed_exchange_body_are_not_logged(self):
        """Neither a valid service ticket nor failed token body may enter logs."""
        driver = Mock()
        driver.execute_async_script.return_value = {
            "status": 200,
            "body": '{"responseStatus":{"type":"SUCCESSFUL"},"serviceTicketId":"synthetic-ticket"}',
        }
        browser = Mock(_driver=driver)
        response = Mock(ok=False, status_code=403, text="synthetic-response")
        with patch.object(api, "_wait_for_cf_clearance", return_value=True), \
             patch.object(api.http_requests, "post", return_value=response), \
             self.assertLogs(api.log, level="DEBUG") as captured:
            result = api._extract_di_tokens(browser, "user@example.invalid", "synthetic-password")
        self.assertEqual(result, {}, "Failed exchanges must not yield tokens")
        self.assertNotIn("synthetic-", " ".join(captured.output), "Auth artifacts must not be logged")

    def test_malformed_portal_body_is_not_logged(self):
        """Unexpected authentication response text may include private data."""
        driver = Mock()
        driver.execute_async_script.return_value = {"status": 200, "body": "synthetic-private-response"}
        with patch.object(api, "_wait_for_cf_clearance", return_value=True), \
             self.assertLogs(api.log, level="DEBUG") as captured:
            result = api._extract_di_tokens(Mock(_driver=driver), "user@example.invalid", "synthetic-password")
        self.assertEqual(result, {}, "Malformed responses must not yield tokens")
        self.assertNotIn("synthetic-", " ".join(captured.output), "Raw auth response must not be logged")


class CredentialStorageTests(unittest.TestCase):
    """Passwords stay in memory; only the account email reaches disk."""

    def setUp(self):
        self.sessions = {}
        patcher = patch.object(api, "_sessions", self.sessions)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_registered_password_is_not_written_to_disk(self):
        """Registering a session records the account without its password."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(api, "SESSIONS_DIR", root):
                api._register_session("User@Example.com", "synthetic-password")
            stored = (root / "user_at_example_com" / "credentials.json").read_text(encoding="utf-8")
        self.assertEqual(json.loads(stored), {"email": "User@Example.com"})
        self.assertNotIn("synthetic-password", stored, "Passwords must never be persisted")
        self.assertEqual(self.sessions["user@example.com"]["password"], "synthetic-password",
                         "The in-memory session keeps the password for the MFA exchange")

    def test_legacy_stored_password_is_removed_on_load(self):
        """Accounts saved by older versions load, and their password is scrubbed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            account = root / "user_at_example_com"
            account.mkdir()
            legacy = account / "credentials.json"
            legacy.write_text(json.dumps({"email": "user@example.com", "password": "synthetic-password"}),
                              encoding="utf-8")
            with patch.object(api, "SESSIONS_DIR", root):
                api._load_all_credentials()
            stored = legacy.read_text(encoding="utf-8")
        self.assertEqual(json.loads(stored), {"email": "user@example.com"})
        self.assertEqual(self.sessions["user@example.com"]["password"], "",
                         "A stored password must not be loaded back into memory")

    def test_client_values_cannot_forge_log_lines(self):
        """Line breaks in client-supplied values are removed before logging."""
        self.assertEqual(api._log_safe("user@example.com\r\nINFO forged"), "user@example.comINFO forged")
