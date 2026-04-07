"""Security helpers shared by auth routes, admin routes, and request hooks."""

import hmac
from datetime import datetime, timezone
from functools import wraps
from math import ceil
import secrets
import time

from flask import current_app, g, jsonify, request, session

from .extensions import db
from .models import AuditLog, sanitize_audit_text

# This keeps track of failed logins in memory for the current app process.
_login_failures: dict[str, dict[str, float | int]] = {}


def current_user():
    """Return the user loaded into Flask's request context for this request."""
    return getattr(g, "current_user", None)


def api_error(
    message: str,
    status: int = 400,
    code: str | None = None,
    details: dict | None = None,
    retry_after: int | None = None,
):
    """Build a consistent JSON error response used by all API routes."""
    payload = {"error": message}
    if code:
        payload["code"] = code
    if details:
        payload["details"] = details

    response = jsonify(payload)
    response.status_code = status
    if retry_after is not None:
        response.headers["Retry-After"] = str(retry_after)
    return response


def ensure_csrf_token() -> str:
    """Make sure the current session has a CSRF token and return it."""
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def rotate_csrf_token() -> str:
    """Replace the CSRF token after sensitive auth actions like login or logout."""
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def validate_csrf_request():
    """Check that unsafe requests include the session's CSRF token."""
    expected_token = session.get("csrf_token")
    provided_token = request.headers.get(current_app.config["CSRF_HEADER_NAME"])

    if not expected_token or not provided_token:
        return api_error(
            "CSRF token missing or invalid.",
            400,
            code="csrf_failed",
        )

    if not hmac.compare_digest(provided_token, expected_token):
        return api_error(
            "CSRF token missing or invalid.",
            400,
            code="csrf_failed",
        )

    return None


def _client_ip() -> str:
    """Find the best client IP value available for rate-limit tracking."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "local"


def login_rate_limit_key(email: str) -> str:
    """Combine email and IP so repeated login failures can be tracked safely."""
    return f"{(email or 'unknown').lower()}|{_client_ip()}"


def _prune_login_failures(now: float) -> None:
    """Drop old rate-limit entries once their window and lock period have passed."""
    window = current_app.config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"]
    expired = [
        key
        for key, value in _login_failures.items()
        if value.get("locked_until", 0) <= now
        and now - float(value["first_failed_at"]) > window
    ]
    for key in expired:
        _login_failures.pop(key, None)


def check_login_rate_limit(identifier: str) -> int | None:
    """Return remaining lockout seconds when this login key is currently blocked."""
    now = time.time()
    _prune_login_failures(now)

    attempt = _login_failures.get(identifier)
    if not attempt:
        return None

    locked_until = float(attempt.get("locked_until", 0))
    if locked_until > now:
        return max(1, ceil(locked_until - now))

    return None


def register_failed_login(identifier: str) -> int | None:
    """Record a failed login and start a lockout when the limit is reached."""
    now = time.time()
    _prune_login_failures(now)

    window = current_app.config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"]
    max_attempts = current_app.config["LOGIN_RATE_LIMIT_ATTEMPTS"]
    lockout_seconds = current_app.config["LOGIN_RATE_LIMIT_LOCKOUT_SECONDS"]
    current_attempt = _login_failures.get(identifier)

    if current_attempt and now - float(current_attempt["first_failed_at"]) <= window:
        current_attempt["count"] = int(current_attempt["count"]) + 1
    else:
        current_attempt = {"count": 1, "first_failed_at": now, "locked_until": 0}
        _login_failures[identifier] = current_attempt

    if int(current_attempt["count"]) >= max_attempts:
        current_attempt["locked_until"] = now + lockout_seconds
        return lockout_seconds

    return None


def clear_login_failures(identifier: str | None = None) -> None:
    """Clear one rate-limit entry, one email group, or the whole tracker."""
    if identifier is None:
        _login_failures.clear()
        return
    if "|" not in identifier:
        matching_keys = [
            key
            for key in _login_failures
            if key.partition("|")[0] == identifier.lower()
        ]
        for key in matching_keys:
            _login_failures.pop(key, None)
        return
    _login_failures.pop(identifier, None)


def get_login_attempt_snapshot() -> list[dict]:
    """Return the tracked login-failure data in a shape the admin UI can show."""
    now = time.time()
    _prune_login_failures(now)

    snapshot = []
    for identifier, value in _login_failures.items():
        email, _, ip_address = identifier.partition("|")
        locked_until = float(value.get("locked_until", 0))
        first_failed_at = float(value["first_failed_at"])
        snapshot.append(
            {
                "identifier": identifier,
                "email": email,
                "ipAddress": ip_address,
                "count": int(value["count"]),
                "firstFailedAt": datetime.fromtimestamp(
                    first_failed_at, tz=timezone.utc
                ).isoformat(),
                "lockedUntil": (
                    datetime.fromtimestamp(locked_until, tz=timezone.utc).isoformat()
                    if locked_until > 0
                    else None
                ),
                "remainingLockSeconds": (
                    max(0, ceil(locked_until - now)) if locked_until > now else 0
                ),
                "isLocked": locked_until > now,
            }
        )

    snapshot.sort(
        key=lambda item: (
            0 if item["isLocked"] else 1,
            -item["remainingLockSeconds"],
            -item["count"],
            item["email"],
        )
    )
    return snapshot


def login_required(view):
    """Decorator that blocks API routes unless a user session is present."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if current_user() is None:
            return api_error(
                "Authentication required.",
                401,
                code="auth_required",
            )
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    """Decorator that blocks routes unless the signed-in user is an admin."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if user is None:
            return api_error(
                "Authentication required.",
                401,
                code="auth_required",
            )
        if user.role != "admin":
            record_audit_event(
                action="admin_access_denied",
                target_type="route",
                detail=f"Blocked non-admin access to {request.path}",
                actor_id=user.id,
            )
            db.session.commit()
            return api_error(
                "Administrator access required.",
                403,
                code="admin_required",
            )
        return view(*args, **kwargs)

    return wrapped_view


def record_audit_event(
    action: str,
    target_type: str,
    target_id: int | None = None,
    detail: str | None = None,
    actor_id: int | None = None,
) -> None:
    """Add a new audit log row so security-relevant actions leave evidence."""
    user = current_user()
    resolved_actor_id = actor_id if actor_id is not None else (user.id if user else None)
    db.session.add(
        AuditLog(
            actor_id=resolved_actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=sanitize_audit_text(detail),
        )
    )
