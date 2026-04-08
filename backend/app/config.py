"""Central application settings loaded during Flask app startup."""

from datetime import timedelta
import os
from pathlib import Path


def _normalise_database_url(raw_url: str | None) -> str:
    """Clean different Postgres URL formats into the SQLAlchemy form the app expects."""
    if not raw_url:
        return "postgresql+psycopg://postgres:postgres@localhost:5432/webshield_lab"

    cleaned = raw_url.strip()

    if cleaned.startswith("psql "):
        cleaned = cleaned[5:].strip()

    if (cleaned.startswith("'") and cleaned.endswith("'")) or (
        cleaned.startswith('"') and cleaned.endswith('"')
    ):
        cleaned = cleaned[1:-1]

    if cleaned.startswith("postgres://"):
        cleaned = "postgresql://" + cleaned[len("postgres://") :]

    if cleaned.startswith("postgresql://") and "+psycopg" not in cleaned:
        cleaned = "postgresql+psycopg://" + cleaned[len("postgresql://") :]

    return cleaned


def _is_vercel_environment() -> bool:
    """Detect whether the app is running inside Vercel's serverless runtime."""
    return os.getenv("VERCEL") == "1" or bool(os.getenv("VERCEL_ENV"))


class Config:
    """Default settings for sessions, database access, lab mode, and logging."""

    BACKEND_ROOT = Path(__file__).resolve().parents[1]
    SECRET_KEY = "development-secret-key"
    SQLALCHEMY_DATABASE_URI = (
        "postgresql+psycopg://postgres:postgres@localhost:5432/webshield_lab"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOCAL_FRONTEND_ORIGINS = [
        "http://127.0.0.1:5000",
        "http://localhost:5000",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ]
    FRONTEND_ORIGINS = list(LOCAL_FRONTEND_ORIGINS)
    SESSION_COOKIE_NAME = "webshield_lab_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _is_vercel_environment()
    SESSION_REFRESH_EACH_REQUEST = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=10)
    JSON_SORT_KEYS = False
    AUTO_CREATE_TABLES = not _is_vercel_environment()
    LAB_MODE = "secure"
    CSRF_HEADER_NAME = "X-CSRF-Token"
    LOGIN_RATE_LIMIT_ATTEMPTS = 5
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = 600
    LOGIN_RATE_LIMIT_LOCKOUT_SECONDS = 300
    ERROR_LOG_PATH = (
        "/tmp/webshield-error.log"
        if _is_vercel_environment()
        else str(BACKEND_ROOT / "logs" / "error.log")
    )
    ERROR_LOG_MAX_BYTES = 1_048_576
    ERROR_LOG_BACKUP_COUNT = 3

    @classmethod
    def init_app(cls, app) -> None:
        """Copy environment-driven settings into the live Flask app config."""
        app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", cls.SECRET_KEY)
        app.config["SQLALCHEMY_DATABASE_URI"] = _normalise_database_url(
            os.getenv("DATABASE_URL", cls.SQLALCHEMY_DATABASE_URI)
        )
        frontend_origins = os.getenv("FRONTEND_ORIGINS")
        if frontend_origins is None:
            # Production serves the frontend and API from the same host, so
            # cross-origin access is only needed during local development.
            app.config["FRONTEND_ORIGINS"] = (
                [] if _is_vercel_environment() else list(cls.LOCAL_FRONTEND_ORIGINS)
            )
        else:
            app.config["FRONTEND_ORIGINS"] = [
                origin.strip()
                for origin in frontend_origins.split(",")
                if origin.strip()
            ]
        app.config["AUTO_CREATE_TABLES"] = (
            os.getenv("AUTO_CREATE_TABLES", str(cls.AUTO_CREATE_TABLES)).lower()
            == "true"
        )
        app.config["LAB_MODE"] = os.getenv("LAB_MODE", cls.LAB_MODE)
        app.config["SESSION_COOKIE_NAME"] = os.getenv(
            "SESSION_COOKIE_NAME", cls.SESSION_COOKIE_NAME
        )
        app.config["SESSION_COOKIE_HTTPONLY"] = (
            os.getenv("SESSION_COOKIE_HTTPONLY", str(cls.SESSION_COOKIE_HTTPONLY)).lower()
            == "true"
        )
        app.config["SESSION_COOKIE_SAMESITE"] = os.getenv(
            "SESSION_COOKIE_SAMESITE", cls.SESSION_COOKIE_SAMESITE
        )
        app.config["SESSION_COOKIE_SECURE"] = (
            os.getenv("SESSION_COOKIE_SECURE", str(cls.SESSION_COOKIE_SECURE)).lower()
            == "true"
        )
        app.config["SESSION_REFRESH_EACH_REQUEST"] = (
            os.getenv(
                "SESSION_REFRESH_EACH_REQUEST",
                str(cls.SESSION_REFRESH_EACH_REQUEST),
            ).lower()
            == "true"
        )
        session_minutes = int(
            os.getenv(
                "PERMANENT_SESSION_MINUTES",
                int(cls.PERMANENT_SESSION_LIFETIME.total_seconds() // 60),
            )
        )
        app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=session_minutes)
        app.config["CSRF_HEADER_NAME"] = os.getenv(
            "CSRF_HEADER_NAME", cls.CSRF_HEADER_NAME
        )
        app.config["LOGIN_RATE_LIMIT_ATTEMPTS"] = int(
            os.getenv(
                "LOGIN_RATE_LIMIT_ATTEMPTS", cls.LOGIN_RATE_LIMIT_ATTEMPTS
            )
        )
        app.config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"] = int(
            os.getenv(
                "LOGIN_RATE_LIMIT_WINDOW_SECONDS",
                cls.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
            )
        )
        app.config["LOGIN_RATE_LIMIT_LOCKOUT_SECONDS"] = int(
            os.getenv(
                "LOGIN_RATE_LIMIT_LOCKOUT_SECONDS",
                cls.LOGIN_RATE_LIMIT_LOCKOUT_SECONDS,
            )
        )
        app.config["ERROR_LOG_PATH"] = os.getenv(
            "ERROR_LOG_PATH",
            cls.ERROR_LOG_PATH,
        )
        app.config["ERROR_LOG_MAX_BYTES"] = int(
            os.getenv("ERROR_LOG_MAX_BYTES", cls.ERROR_LOG_MAX_BYTES)
        )
        app.config["ERROR_LOG_BACKUP_COUNT"] = int(
            os.getenv("ERROR_LOG_BACKUP_COUNT", cls.ERROR_LOG_BACKUP_COUNT)
        )
