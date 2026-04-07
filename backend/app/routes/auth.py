"""Authentication routes used by the login, register, and dashboard pages."""

from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request, session
from sqlalchemy import or_

from ..extensions import db
from ..models import User
from ..security import (
    api_error,
    check_login_rate_limit,
    clear_login_failures,
    current_user,
    ensure_csrf_token,
    login_rate_limit_key,
    login_required,
    record_audit_event,
    register_failed_login,
    rotate_csrf_token,
)
from ..validators import (
    ValidationError,
    validate_email,
    validate_password,
    validate_username,
)

# All authentication endpoints live under `/api/auth`.
bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@bp.get("/csrf-token")
def csrf_token():
    """Return the current CSRF token so frontend forms can send safe write requests."""
    return jsonify(
        {
            "csrfToken": ensure_csrf_token(),
            "labMode": current_app.config["LAB_MODE"],
        }
    )


@bp.post("/register")
def register():
    """Create a new standard user account after validating the submitted fields."""
    payload = request.get_json(silent=True) or {}
    try:
        username = validate_username(payload.get("username") or "")
        email = validate_email(payload.get("email") or "")
        password = validate_password(payload.get("password") or "")
    except ValidationError as exc:
        return api_error(str(exc), 400, code="validation_error")

    existing_user = User.query.filter(
        or_(User.username == username, User.email == email)
    ).first()
    if existing_user:
        return api_error(
            "That username or email address is already in use.",
            400,
            code="duplicate_user",
        )

    user = User(username=username, email=email, role="user", is_active=True)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    record_audit_event(
        action="register",
        target_type="user",
        target_id=user.id,
        detail=f"Created account for {email}",
        actor_id=user.id,
    )
    db.session.commit()

    return (
        jsonify(
            {
                "message": "Registration successful.",
                "user": user.to_dict(),
                "csrfToken": ensure_csrf_token(),
            }
        ),
        201,
    )


@bp.post("/login")
def login():
    """Start a session when the email and password are valid and not rate-limited."""
    payload = request.get_json(silent=True) or {}
    submitted_email = (payload.get("email") or "").strip().lower()
    try:
        email = validate_email(submitted_email)
        audit_email = email
        rate_limit_identifier = email
    except ValidationError:
        email = submitted_email
        audit_email = "invalid email input"
        rate_limit_identifier = "invalid-email-input"
    password = payload.get("password") or ""
    rate_limit_id = login_rate_limit_key(rate_limit_identifier)

    retry_after = check_login_rate_limit(rate_limit_id)
    if retry_after is not None:
        return api_error(
            f"Too many failed login attempts. Try again in {retry_after} seconds.",
            429,
            code="login_rate_limited",
            retry_after=retry_after,
        )

    user = User.query.filter_by(email=email).first()
    if user is None or not user.check_password(password):
        retry_after = register_failed_login(rate_limit_id)
        record_audit_event(
            action="login_failed",
            target_type="session",
            detail=f"Failed login attempt for {audit_email or 'unknown email'}",
            actor_id=user.id if user else None,
        )
        db.session.commit()
        if retry_after is not None:
            return api_error(
                f"Too many failed login attempts. Try again in {retry_after} seconds.",
                429,
                code="login_rate_limited",
                retry_after=retry_after,
            )
        return api_error(
            "Invalid email or password.",
            401,
            code="invalid_credentials",
        )

    if not user.is_active:
        record_audit_event(
            action="login_blocked_inactive_account",
            target_type="user",
            target_id=user.id,
            detail=f"Blocked login for disabled account {email}",
            actor_id=user.id,
        )
        db.session.commit()
        return api_error(
            "This account is disabled. Contact an administrator.",
            403,
            code="account_disabled",
        )

    clear_login_failures(rate_limit_id)
    session.clear()
    session["user_id"] = user.id
    session.permanent = True
    csrf_token_value = rotate_csrf_token()
    user.last_login_at = datetime.now(timezone.utc)
    record_audit_event(
        action="login",
        target_type="session",
        detail=f"Logged in as {email}",
        actor_id=user.id,
    )
    db.session.commit()

    return jsonify(
        {
            "message": "Login successful.",
            "user": user.to_dict(),
            "csrfToken": csrf_token_value,
        }
    )


@bp.post("/logout")
def logout():
    """End the current session and rotate the CSRF token."""
    user = current_user()
    if user is not None:
        record_audit_event(
            action="logout",
            target_type="session",
            detail=f"Logged out {user.email}",
            actor_id=user.id,
        )
        db.session.commit()

    session.clear()
    return jsonify(
        {
            "message": "Logout successful.",
            "csrfToken": rotate_csrf_token(),
        }
    )


@bp.post("/change-password")
@login_required
def change_password():
    """Let the signed-in user replace their own password safely."""
    payload = request.get_json(silent=True) or {}
    user = current_user()
    current_password = payload.get("currentPassword") or ""
    new_password = payload.get("newPassword") or ""
    confirm_password = payload.get("confirmPassword") or ""

    if not user.check_password(current_password):
        return api_error(
            "Current password is incorrect.",
            400,
            code="invalid_current_password",
        )

    if new_password != confirm_password:
        return api_error(
            "New password and confirmation do not match.",
            400,
            code="password_confirmation_mismatch",
        )

    if user.check_password(new_password):
        return api_error(
            "New password must be different from the current password.",
            400,
            code="password_reuse",
        )

    try:
        validated_password = validate_password(new_password)
    except ValidationError as exc:
        return api_error(str(exc), 400, code="validation_error")

    user.set_password(validated_password)
    record_audit_event(
        action="password_changed",
        target_type="user",
        target_id=user.id,
        detail=f"Password updated for {user.email}",
        actor_id=user.id,
    )
    db.session.commit()

    return jsonify(
        {
            "message": "Password changed successfully.",
            "csrfToken": rotate_csrf_token(),
            "user": user.to_dict(),
        }
    )


@bp.get("/session")
def session_status():
    """Describe the current session so the frontend can adjust the UI."""
    user = current_user()
    if user is None:
        return jsonify(
            {
                "authenticated": False,
                "user": None,
                "csrfToken": ensure_csrf_token(),
                "labMode": current_app.config["LAB_MODE"],
            }
        )
    return jsonify(
        {
            "authenticated": True,
            "user": user.to_dict(),
            "csrfToken": ensure_csrf_token(),
            "labMode": current_app.config["LAB_MODE"],
        }
    )
