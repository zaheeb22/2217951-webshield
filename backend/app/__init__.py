"""Flask app factory and global request behavior for WebShield Lab."""

import click
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, Response, abort, current_app, g, jsonify, request, send_from_directory, session
from sqlalchemy import inspect
from sqlalchemy import or_
from sqlalchemy import text
from werkzeug.exceptions import HTTPException

from .config import Config
from .extensions import cors, db
from .models import User
from .routes import admin_bp, auth_bp, lab_bp, tickets_bp
from .security import api_error, ensure_csrf_token, validate_csrf_request
from .validators import ValidationError, validate_password

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
FRONTEND_ROOT = PROJECT_ROOT / "frontend"


def _content_security_policy() -> str:
    """Return a tight CSP for both HTML pages and JSON responses."""
    return "; ".join(
        [
            "default-src 'self'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'self'",
            "object-src 'none'",
            "style-src 'self'",
            "script-src 'self'",
            "connect-src 'self'",
        ]
    )


def create_app() -> Flask:
    """Build the Flask app, attach extensions, and register routes."""
    load_dotenv(BACKEND_ROOT / ".env", override=False)
    load_dotenv(PROJECT_ROOT / ".env", override=False)

    app = Flask(
        __name__,
        static_folder=str(FRONTEND_ROOT / "assets"),
        static_url_path="/assets",
    )
    app.config.from_object(Config)
    Config.init_app(app)
    _configure_logging(app)

    db.init_app(app)
    if app.config["FRONTEND_ORIGINS"]:
        cors.init_app(
            app,
            supports_credentials=True,
            resources={r"/api/*": {"origins": app.config["FRONTEND_ORIGINS"]}},
        )

    _register_hooks(app)
    _register_blueprints(app)
    _register_commands(app)

    with app.app_context():
        if app.config["AUTO_CREATE_TABLES"]:
            db.create_all()
            _sync_database_schema()

    return app


def _configure_logging(app: Flask) -> None:
    """Write backend errors to a rotating log file for later review."""
    try:
        log_path = Path(app.config["ERROR_LOG_PATH"])
        if not log_path.is_absolute():
            log_path = BACKEND_ROOT / log_path

        log_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_log_path = str(log_path.resolve())

        existing_handler = next(
            (
                handler
                for handler in app.logger.handlers
                if isinstance(handler, RotatingFileHandler)
                and getattr(handler, "baseFilename", None) == resolved_log_path
            ),
            None,
        )

        if existing_handler is None:
            handler = RotatingFileHandler(
                resolved_log_path,
                maxBytes=app.config["ERROR_LOG_MAX_BYTES"],
                backupCount=app.config["ERROR_LOG_BACKUP_COUNT"],
                encoding="utf-8",
            )
            handler.setLevel(logging.ERROR)
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)s [%(name)s] %(message)s in %(pathname)s:%(lineno)d"
                )
            )
            app.logger.addHandler(handler)
    except OSError as exc:
        # Serverless environments can restrict writes inside the deployed bundle.
        # Falling back to the default stderr logger keeps the app alive.
        app.logger.warning("File logging disabled: %s", exc)

    if app.logger.level == logging.NOTSET or app.logger.level > logging.INFO:
        app.logger.setLevel(logging.INFO)


def _register_hooks(app: Flask) -> None:
    """Attach request hooks for session loading, CSRF checks, and headers."""

    # Load the current user once per request so routes can rely on `g.current_user`.
    @app.before_request
    def load_current_user():
        user_id = session.get("user_id")
        g.current_user = db.session.get(User, user_id) if user_id else None
        if g.current_user is not None and not g.current_user.is_active:
            session.clear()
            g.current_user = None
        if user_id:
            session.permanent = True

        if request.path.startswith("/api/"):
            ensure_csrf_token()

            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                csrf_error = validate_csrf_request()
                if csrf_error is not None:
                    return csrf_error

    # Add common browser hardening headers to both API and HTML responses.
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = _content_security_policy()
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # Turn validation errors into clean JSON for the frontend.
    @app.errorhandler(ValidationError)
    def handle_validation_error(error):
        if request.path.startswith("/api/"):
            return api_error(str(error), 400, code="validation_error")
        return str(error), 400

    # Keep HTTP errors in one predictable format for API consumers.
    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        if request.path.startswith("/api/"):
            return api_error(
                error.description or error.name,
                error.code or 500,
                code=(error.name or "http_error").lower().replace(" ", "_"),
            )
        return error

    # Hide raw stack traces from users but still record them in the error log.
    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        current_app.logger.exception("Unhandled server error: %s", error)
        if request.path.startswith("/api/"):
            return api_error(
                "An unexpected server error occurred. Please try again.",
                500,
                code="server_error",
            )
        return (
            "<h1>Server error</h1><p>An unexpected server error occurred.</p>",
            500,
        )


def _register_blueprints(app: Flask) -> None:
    """Attach backend API groups and simple frontend file-serving routes."""
    app.register_blueprint(auth_bp)
    app.register_blueprint(tickets_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(lab_bp)

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_ROOT, "index.html")

    @app.get("/<path:page_name>")
    def serve_frontend(page_name: str):
        if page_name.startswith("api/"):
            abort(404)
        return send_from_directory(FRONTEND_ROOT, page_name)

    @app.get("/api/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "application": "WebShield Lab API",
                "mode": app.config["LAB_MODE"],
                "demoEnabled": app.config["LAB_MODE"].lower() == "demo",
            }
        )


def _register_commands(app: Flask) -> None:
    """Expose small Flask CLI helpers used during local development."""
    @app.cli.command("seed-admin")
    @click.option("--username", default="admin", show_default=True)
    @click.option("--email", default="admin@gmail.com", show_default=True)
    @click.option(
        "--password",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
    )
    def seed_admin(username: str, email: str, password: str) -> None:
        """Create the first admin account without using the browser UI."""
        try:
            validated_password = validate_password(password)
        except ValidationError as exc:
            click.echo(str(exc))
            return

        # Running the seed command should also repair or create the current schema
        # so older local databases do not break before the admin check runs.
        db.create_all()
        _sync_database_schema()

        existing_user = User.query.filter(
            or_(User.username == username, User.email == email)
        ).first()

        if existing_user:
            click.echo("A user with that username or email already exists.")
            return

        admin_user = User(username=username, email=email.lower().strip(), role="admin")
        admin_user.set_password(validated_password)
        db.session.add(admin_user)
        db.session.commit()
        click.echo(f"Admin account created for {admin_user.email}.")


def _sync_database_schema() -> None:
    """Apply lightweight schema fixes when auto-create is enabled locally."""
    inspector = inspect(db.engine)

    if inspector.has_table("users"):
        user_columns = {
            column["name"]
            for column in inspector.get_columns("users")
        }

        user_statements = []
        if "username" not in user_columns:
            user_statements.append("ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(50)")
            user_statements.append(
                """
                UPDATE users
                SET username = LEFT('user_' || id::text, 50)
                WHERE username IS NULL OR BTRIM(username) = ''
                """
            )
        if "email" not in user_columns:
            user_statements.append("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255)")
            user_statements.append(
                """
                UPDATE users
                SET email = 'user_' || id::text || '@legacy.local'
                WHERE email IS NULL OR BTRIM(email) = ''
                """
            )
        if "password_hash" not in user_columns:
            user_statements.append("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255)")
            if "password" in user_columns:
                user_statements.append(
                    """
                    UPDATE users
                    SET password_hash = password
                    WHERE password_hash IS NULL OR BTRIM(password_hash) = ''
                    """
                )
            user_statements.append(
                """
                UPDATE users
                SET password_hash = '!'
                WHERE password_hash IS NULL OR BTRIM(password_hash) = ''
                """
            )
        if "role" not in user_columns:
            user_statements.append("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20)")
            if "is_admin" in user_columns:
                user_statements.append(
                    """
                    UPDATE users
                    SET role = CASE WHEN is_admin THEN 'admin' ELSE 'user' END
                    WHERE role IS NULL OR BTRIM(role) = ''
                    """
                )
            user_statements.append(
                """
                UPDATE users
                SET role = 'user'
                WHERE role IS NULL OR BTRIM(role) = ''
                """
            )
        if "is_active" not in user_columns:
            user_statements.append(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE"
            )
            user_statements.append("UPDATE users SET is_active = TRUE WHERE is_active IS NULL")
        if "created_at" not in user_columns:
            user_statements.append(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
            )
        if "last_login_at" not in user_columns:
            user_statements.append("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ")
        if "last_password_changed_at" not in user_columns:
            user_statements.append(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_password_changed_at TIMESTAMPTZ"
            )

        for statement in user_statements:
            db.session.execute(text(statement))

    # Support tickets still use the older table names so existing databases do not
    # need a destructive rebuild just to adopt the renamed workflow.
    if inspector.has_table("feedback"):
        feedback_columns = {
            column["name"]
            for column in inspector.get_columns("feedback")
        }

        feedback_statements = []
        if "status" not in feedback_columns:
            feedback_statements.append(
                "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'pending'"
            )
        if "admin_note" not in feedback_columns:
            feedback_statements.append("ALTER TABLE feedback ADD COLUMN IF NOT EXISTS admin_note TEXT")
        if "updated_at" not in feedback_columns:
            feedback_statements.append(
                "ALTER TABLE feedback ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
            )

        for statement in feedback_statements:
            db.session.execute(text(statement))

    statements = [
        """
        CREATE TABLE IF NOT EXISTS feedback_status_history (
            id SERIAL PRIMARY KEY,
            feedback_id INTEGER NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
            actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            previous_status VARCHAR(20),
            next_status VARCHAR(20) NOT NULL,
            note TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
    ]

    for statement in statements:
        db.session.execute(text(statement))
    db.session.commit()
