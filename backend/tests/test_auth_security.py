"""Focused tests for login sessions and brute-force rate limiting."""

import json
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from backend.app import create_app
from backend.app.extensions import db
from backend.app.models import User
from backend.app.security import clear_login_failures


class AuthSecurityTestCase(unittest.TestCase):
    """Exercise the main authentication protections in an isolated test app."""

    def setUp(self):
        """Create a temporary app, database, admin user, and CSRF token."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sqlite_path = Path(self.temp_dir.name) / "webshield-test.sqlite"
        self.env_keys = [
            "DATABASE_URL",
            "AUTO_CREATE_TABLES",
            "SECRET_KEY",
            "LAB_MODE",
            "FRONTEND_ORIGINS",
            "ERROR_LOG_PATH",
            "PERMANENT_SESSION_MINUTES",
            "LOGIN_RATE_LIMIT_ATTEMPTS",
            "LOGIN_RATE_LIMIT_WINDOW_SECONDS",
            "LOGIN_RATE_LIMIT_LOCKOUT_SECONDS",
        ]
        self.original_env = {key: os.environ.get(key) for key in self.env_keys}

        os.environ["DATABASE_URL"] = f"sqlite:///{self.sqlite_path}"
        os.environ["AUTO_CREATE_TABLES"] = "false"
        os.environ["SECRET_KEY"] = "test-secret-key"
        os.environ["LAB_MODE"] = "secure"
        os.environ["FRONTEND_ORIGINS"] = "http://127.0.0.1:5000"
        os.environ["ERROR_LOG_PATH"] = str(Path(self.temp_dir.name) / "error.log")
        os.environ.pop("PERMANENT_SESSION_MINUTES", None)
        os.environ["LOGIN_RATE_LIMIT_ATTEMPTS"] = "5"
        os.environ["LOGIN_RATE_LIMIT_WINDOW_SECONDS"] = "600"
        os.environ["LOGIN_RATE_LIMIT_LOCKOUT_SECONDS"] = "300"

        clear_login_failures()
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()
            # The seeded admin account gives the tests a real user to log in with.
            admin = User(
                username="admin",
                email="admin@gmail.com",
                role="admin",
                is_active=True,
            )
            admin.set_password("StrongPass123")
            db.session.add(admin)
            db.session.commit()

        self.csrf_token = self.client.get("/api/auth/csrf-token").get_json()["csrfToken"]

    def tearDown(self):
        """Clean up the temporary database and restore previous environment values."""
        try:
            with self.app.app_context():
                db.session.remove()
                db.drop_all()
        finally:
            clear_login_failures()
            for key, value in self.original_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            self.temp_dir.cleanup()

    def post_json(self, path, payload):
        """Send JSON to the API with the stored CSRF token attached."""
        return self.client.post(
            path,
            data=json.dumps(payload),
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": self.csrf_token,
            },
        )

    def test_successful_login_creates_authenticated_session(self):
        """A valid login should be visible through the session-status endpoint."""
        login_response = self.post_json(
            "/api/auth/login",
            {
                "email": "admin@gmail.com",
                "password": "StrongPass123",
            },
        )

        self.assertEqual(login_response.status_code, 200)

        session_response = self.client.get("/api/auth/session")
        session_data = session_response.get_json()

        self.assertEqual(session_response.status_code, 200)
        self.assertTrue(session_data["authenticated"])
        self.assertEqual(session_data["user"]["username"], "admin")
        self.assertEqual(session_data["user"]["role"], "admin")

    def test_default_session_timeout_is_ten_minutes_of_inactivity(self):
        """Permanent sessions should expire after 10 minutes unless config overrides it."""
        self.assertEqual(
            self.app.config["PERMANENT_SESSION_LIFETIME"],
            timedelta(minutes=10),
        )
        self.assertTrue(self.app.config["SESSION_REFRESH_EACH_REQUEST"])

    def test_login_is_locked_after_configured_failed_attempts(self):
        """Repeated bad passwords should trigger the configured rate-limit lockout."""
        for _ in range(4):
            failed_response = self.post_json(
                "/api/auth/login",
                {
                    "email": "admin@gmail.com",
                    "password": "WrongPassword123",
                },
            )
            self.assertEqual(failed_response.status_code, 401)

        locked_response = self.post_json(
            "/api/auth/login",
            {
                "email": "admin@gmail.com",
                "password": "WrongPassword123",
            },
        )
        locked_data = locked_response.get_json()

        self.assertEqual(locked_response.status_code, 429)
        self.assertEqual(locked_data["code"], "login_rate_limited")
        self.assertEqual(locked_response.headers.get("Retry-After"), "300")


if __name__ == "__main__":
    unittest.main()
