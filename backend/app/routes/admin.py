"""Administrator routes for ticket review, audit review, and evidence export."""

import csv
from datetime import datetime, timedelta, timezone
import io

from flask import Blueprint, Response, current_app, jsonify, request
from sqlalchemy import func, or_

from ..extensions import db
from ..models import AuditLog, Feedback as SupportTicket, User, sanitize_audit_text
from ..models import FeedbackStatusHistory as SupportTicketStatusHistory
from ..security import (
    admin_required,
    api_error,
    clear_login_failures,
    current_user,
    get_login_attempt_snapshot,
    record_audit_event,
    record_validation_rejection,
)
from ..validators import ValidationError, validate_admin_note
from ..validators import validate_password

bp = Blueprint("admin", __name__, url_prefix="/api/admin")

ALLOWED_STATUSES = {"pending", "reviewed", "resolved"}
ALLOWED_ROLES = {"user", "admin"}


def _parse_datetime(value: str | None) -> datetime | None:
    """Convert optional ISO date strings from filter forms into datetime objects."""
    if not value:
        return None

    candidate = value.strip()
    if not candidate:
        return None

    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"

    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _csv_response(filename: str, headers: list[str], rows: list[list[str]]) -> Response:
    """Build a simple CSV download used by audit and security exports."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    writer.writerows(rows)
    csv_content = buffer.getvalue()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


def _serialise_security_scenarios() -> list[dict]:
    """Describe the built-in secure-vs-demo scenarios shown on the admin page."""
    demo_enabled = current_app.config["LAB_MODE"].lower() == "demo"
    return [
        {
            "id": "sql_injection",
            "vulnerability": "SQL Injection",
            "reviewMethod": "SQLMap or crafted query strings",
            "demoRoute": "/api/lab/insecure-search",
            "beforeState": "Demo mode builds a SQL query with string concatenation and may expose data or raw errors.",
            "afterState": "Secure mode uses SQLAlchemy ORM queries and validated input on support ticket routes.",
            "mitigation": "Use ORM or parameterized queries and validate user input.",
            "demoEnabled": demo_enabled,
        },
        {
            "id": "xss",
            "vulnerability": "Cross-Site Scripting (XSS)",
            "reviewMethod": "Manual payload injection and browser rendering checks",
            "demoRoute": "/api/lab/echo-preview",
            "beforeState": "Demo mode reflects raw HTML back into the page without sanitization.",
            "afterState": "Secure routes reject script-like markup and render user content as text nodes.",
            "mitigation": "Validate input, block script-like payloads, and avoid unsafe DOM insertion.",
            "demoEnabled": demo_enabled,
        },
        {
            "id": "idor",
            "vulnerability": "Insecure Direct Object Reference (IDOR)",
            "reviewMethod": "Manual URL manipulation",
            "demoRoute": "/api/lab/public-tickets/<id>",
            "beforeState": "Demo mode exposes support tickets without object-level authorization checks.",
            "afterState": "Secure user routes only return tickets belonging to the authenticated user.",
            "mitigation": "Apply object-level authorization and role checks on every record fetch.",
            "demoEnabled": demo_enabled,
        },
        {
            "id": "brute_force",
            "vulnerability": "Brute-force Login Attempts",
            "reviewMethod": "Repeated failed login attempts",
            "demoRoute": "N/A",
            "beforeState": "Without rate limiting, repeated credential guessing would continue without delay.",
            "afterState": "Secure mode tracks failed attempts and temporarily locks the login route after the configured threshold.",
            "mitigation": "Apply login rate limiting, monitoring, and lockout windows.",
            "demoEnabled": False,
        },
        {
            "id": "csrf",
            "vulnerability": "Cross-Site Request Forgery (CSRF)",
            "reviewMethod": "Manual forged POST/PATCH requests without a valid CSRF token",
            "demoRoute": "N/A",
            "beforeState": "Without CSRF tokens, state-changing requests could be replayed by another site.",
            "afterState": "Secure mode requires a valid CSRF token on state-changing API requests.",
            "mitigation": "Bind a CSRF token to the user session and verify it on unsafe methods.",
            "demoEnabled": False,
        },
        {
            "id": "weak_auth",
            "vulnerability": "Weak Authentication / Access Control",
            "reviewMethod": "Manual role and account-state checks",
            "demoRoute": "N/A",
            "beforeState": "Without role checks and account controls, privileged actions could be abused.",
            "afterState": "Secure mode enforces admin-only routes, account activation state, and password complexity rules.",
            "mitigation": "Apply least privilege, role checks, stronger passwords, and account disable controls.",
            "demoEnabled": False,
        },
    ]


def _build_audit_query():
    """Apply admin filter fields to the audit log query."""
    query = AuditLog.query.outerjoin(User, AuditLog.actor_id == User.id)
    action = (request.args.get("action") or "").strip()
    target_type = (request.args.get("targetType") or "").strip()
    actor = (request.args.get("actor") or "").strip()
    date_from = _parse_datetime(request.args.get("dateFrom"))
    date_to = _parse_datetime(request.args.get("dateTo"))

    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))
    if target_type:
        query = query.filter(AuditLog.target_type == target_type)
    if actor:
        query = query.filter(
            or_(User.email.ilike(f"%{actor}%"), User.username.ilike(f"%{actor}%"))
        )
    if date_from is not None:
        query = query.filter(AuditLog.created_at >= date_from)
    if date_to is not None:
        query = query.filter(AuditLog.created_at <= date_to)

    return query.order_by(AuditLog.created_at.desc())


def _bool_filter_value(raw_value: str | None) -> bool | None:
    """Turn a form value into True, False, or no filter."""
    if raw_value is None or raw_value == "":
        return None
    value = raw_value.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _user_list_payload(users: list[User]) -> list[dict]:
    """Add summary counts so the admin page can show richer user cards."""
    ticket_counts = dict(
        db.session.query(SupportTicket.user_id, func.count(SupportTicket.id))
        .group_by(SupportTicket.user_id)
        .all()
    )
    audit_counts = dict(
        db.session.query(AuditLog.actor_id, func.count(AuditLog.id))
        .filter(AuditLog.actor_id.isnot(None))
        .group_by(AuditLog.actor_id)
        .all()
    )

    items = []
    for user in users:
        payload = user.to_dict()
        payload["ticketCount"] = int(ticket_counts.get(user.id, 0))
        payload["auditEventCount"] = int(audit_counts.get(user.id, 0))
        items.append(payload)
    return items


def _overview_summary() -> dict:
    """Collect the top-level numbers shown across admin and audit dashboards."""
    total_users = db.session.query(func.count(User.id)).scalar() or 0
    active_users = (
        db.session.query(func.count(User.id))
        .filter(User.is_active.is_(True))
        .scalar()
        or 0
    )
    admin_users = (
        db.session.query(func.count(User.id))
        .filter(User.role == "admin")
        .scalar()
        or 0
    )
    disabled_users = total_users - active_users
    total_tickets = db.session.query(func.count(SupportTicket.id)).scalar() or 0
    pending_tickets = (
        db.session.query(func.count(SupportTicket.id))
        .filter(SupportTicket.status == "pending")
        .scalar()
        or 0
    )
    reviewed_tickets = (
        db.session.query(func.count(SupportTicket.id))
        .filter(SupportTicket.status == "reviewed")
        .scalar()
        or 0
    )
    resolved_tickets = (
        db.session.query(func.count(SupportTicket.id))
        .filter(SupportTicket.status == "resolved")
        .scalar()
        or 0
    )
    total_audit_logs = db.session.query(func.count(AuditLog.id)).scalar() or 0
    failed_logins_last_24h = (
        db.session.query(func.count(AuditLog.id))
        .filter(AuditLog.action == "login_failed")
        .filter(AuditLog.created_at >= datetime.now(timezone.utc) - timedelta(hours=24))
        .scalar()
        or 0
    )

    return {
        "totalUsers": total_users,
        "activeUsers": active_users,
        "disabledUsers": disabled_users,
        "adminUsers": admin_users,
        "totalTickets": total_tickets,
        "pendingTickets": pending_tickets,
        "reviewedTickets": reviewed_tickets,
        "resolvedTickets": resolved_tickets,
        "auditEvents": total_audit_logs,
        "failedLoginsLast24h": failed_logins_last_24h,
        "lockedLoginAttempts": len(
            [item for item in get_login_attempt_snapshot() if item["isLocked"]]
        ),
        "labMode": current_app.config["LAB_MODE"],
        "demoEnabled": current_app.config["LAB_MODE"].lower() == "demo",
    }


@bp.get("/overview")
@admin_required
def dashboard_overview():
    """Return the summary cards for the admin dashboard."""
    return jsonify({"summary": _overview_summary()})


@bp.get("/users")
@admin_required
def list_users():
    """Return users with optional search, role, and active-state filters."""
    search = (request.args.get("search") or "").strip()
    role = (request.args.get("role") or "").strip().lower()
    is_active_filter = _bool_filter_value(request.args.get("active"))

    query = User.query.order_by(User.created_at.desc())
    if search:
        query = query.filter(
            or_(User.username.ilike(f"%{search}%"), User.email.ilike(f"%{search}%"))
        )
    if role:
        query = query.filter(User.role == role)
    if is_active_filter is not None:
        query = query.filter(User.is_active.is_(is_active_filter))

    users = query.all()
    return jsonify({"items": _user_list_payload(users)})


@bp.patch("/users/<int:user_id>")
@admin_required
def update_user(user_id: int):
    """Let an admin change another user's role or active status."""
    payload = request.get_json(silent=True) or {}
    actor = current_user()
    user = db.session.get(User, user_id)

    if user is None:
        return api_error("User not found.", 404, code="not_found")

    changes = []
    if "role" in payload:
        new_role = (payload.get("role") or "").strip().lower()
        if new_role not in ALLOWED_ROLES:
            record_validation_rejection(
                "Role must be either user or admin.",
                field_names=["role"],
            )
            db.session.commit()
            return api_error(
                "Role must be either user or admin.",
                400,
                code="validation_error",
            )
        if user.id == actor.id and new_role != "admin":
            return api_error(
                "You cannot remove your own administrator role.",
                400,
                code="self_update_blocked",
            )
        if user.role != new_role:
            changes.append(f"role {user.role} -> {new_role}")
            user.role = new_role

    if "isActive" in payload:
        is_active = payload.get("isActive")
        if not isinstance(is_active, bool):
            record_validation_rejection(
                "isActive must be a boolean value.",
                field_names=["isActive"],
            )
            db.session.commit()
            return api_error(
                "isActive must be a boolean value.",
                400,
                code="validation_error",
            )
        if user.id == actor.id and is_active is False:
            return api_error(
                "You cannot deactivate your own account.",
                400,
                code="self_update_blocked",
            )
        if user.is_active != is_active:
            changes.append(f"active {user.is_active} -> {is_active}")
            user.is_active = is_active

    if not changes:
        return api_error(
            "No user changes were submitted.",
            400,
            code="no_changes",
        )

    record_audit_event(
        action="user_updated",
        target_type="user",
        target_id=user.id,
        detail="; ".join(changes),
        actor_id=actor.id,
    )
    db.session.commit()

    return jsonify(
        {
            "message": "User updated successfully.",
            "user": user.to_dict(),
        }
    )


@bp.post("/users/<int:user_id>/reset-password")
@admin_required
def reset_user_password(user_id: int):
    """Let an admin replace another user's password and clear their lockout state."""
    payload = request.get_json(silent=True) or {}
    actor = current_user()
    user = db.session.get(User, user_id)

    if user is None:
        return api_error("User not found.", 404, code="not_found")

    if user.id == actor.id:
        return api_error(
            "Use the account password change form for your own password.",
            400,
            code="self_update_blocked",
        )

    new_password = payload.get("newPassword") or ""
    confirm_password = payload.get("confirmPassword") or ""

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
        record_validation_rejection(str(exc), field_names=["newPassword"])
        db.session.commit()
        return api_error(str(exc), 400, code="validation_error")

    user.set_password(validated_password)
    clear_login_failures(user.email)
    record_audit_event(
        action="password_reset_by_admin",
        target_type="user",
        target_id=user.id,
        detail=f"Administrator reset password for {user.email}",
        actor_id=actor.id,
    )
    db.session.commit()

    return jsonify(
        {
            "message": "User password reset successfully.",
            "user": user.to_dict(),
        }
    )


@bp.get("/tickets")
@admin_required
def list_tickets():
    """Return support tickets for moderation, including author and history details."""
    status_filter = (request.args.get("status") or "").strip().lower()
    query = SupportTicket.query.order_by(SupportTicket.created_at.desc())
    if status_filter:
        query = query.filter(SupportTicket.status == status_filter)

    ticket_items = query.all()
    return jsonify(
        {
            "items": [
                item.to_dict(include_author=True, include_history=True)
                for item in ticket_items
            ]
        }
    )


@bp.patch("/tickets/<int:ticket_id>")
@admin_required
def update_ticket_status(ticket_id: int):
    """Update ticket status or note and record the change in history and audit logs."""
    payload = request.get_json(silent=True) or {}
    actor = current_user()
    ticket_item = db.session.get(SupportTicket, ticket_id)

    if ticket_item is None:
        return api_error("Support ticket not found.", 404, code="not_found")

    incoming_status = payload.get("status")
    new_status = ticket_item.status
    if incoming_status is not None:
        new_status = (incoming_status or "").strip().lower()
        if new_status not in ALLOWED_STATUSES:
            record_validation_rejection(
                "Status must be pending, reviewed, or resolved.",
                field_names=["status"],
            )
            db.session.commit()
            return api_error(
                "Status must be pending, reviewed, or resolved.",
                400,
                code="validation_error",
            )

    try:
        admin_note = validate_admin_note(payload.get("adminNote") or "")
    except ValidationError as exc:
        record_validation_rejection(str(exc), field_names=["adminNote"])
        db.session.commit()
        return api_error(str(exc), 400, code="validation_error")

    previous_status = ticket_item.status
    previous_note = ticket_item.admin_note or ""
    changes = []

    if previous_status != new_status:
        ticket_item.status = new_status
        changes.append(f"status {previous_status} -> {new_status}")
    if previous_note != admin_note:
        ticket_item.admin_note = admin_note or None
        changes.append("admin note updated")

    if not changes:
        return api_error(
            "No ticket changes were submitted.",
            400,
            code="no_changes",
        )

    db.session.add(
        SupportTicketStatusHistory(
            feedback_id=ticket_item.id,
            actor_id=actor.id,
            previous_status=previous_status,
            next_status=ticket_item.status,
            note=ticket_item.admin_note,
        )
    )
    record_audit_event(
        action="ticket_updated",
        target_type="ticket",
        target_id=ticket_item.id,
        detail="; ".join(changes),
        actor_id=actor.id,
    )
    db.session.commit()

    return jsonify(
        {
            "message": "Support ticket updated successfully.",
            "ticket": ticket_item.to_dict(
                include_author=True,
                include_history=True,
            ),
        }
    )


@bp.get("/audit-logs")
@admin_required
def list_audit_logs():
    """Return recent audit events for the admin and audit pages."""
    limit = min(max(request.args.get("limit", default=40, type=int), 1), 200)
    audit_items = _build_audit_query().limit(limit).all()
    return jsonify(
        {
            "items": [item.to_dict() for item in audit_items],
            "limit": limit,
        }
    )


@bp.get("/audit-logs/export")
@admin_required
def export_audit_logs():
    """Download audit events as CSV or JSON for evidence and reporting."""
    export_format = (request.args.get("format") or "csv").strip().lower()
    audit_items = _build_audit_query().limit(1000).all()

    if export_format == "json":
        return jsonify({"items": [item.to_dict() for item in audit_items]})

    rows = [
        [
            item.id,
            item.action,
            item.target_type,
            item.target_id,
            sanitize_audit_text(item.actor.username) if item.actor else "",
            sanitize_audit_text(item.actor.email) if item.actor else "",
            sanitize_audit_text(item.detail) or "",
            item.created_at.isoformat() if item.created_at else "",
        ]
        for item in audit_items
    ]
    return _csv_response(
        "webshield-audit-log-export.csv",
        [
            "id",
            "action",
            "target_type",
            "target_id",
            "actor_username",
            "actor_email",
            "detail",
            "created_at",
        ],
        rows,
    )


@bp.get("/login-attempts")
@admin_required
def list_login_attempts():
    """Show the current rate-limit tracker entries to administrators."""
    return jsonify({"items": get_login_attempt_snapshot()})


@bp.post("/login-attempts/reset")
@admin_required
def reset_login_attempts():
    """Clear one or all tracked login-failure entries from the admin page."""
    payload = request.get_json(silent=True) or {}
    actor = current_user()
    identifier = (payload.get("identifier") or "").strip()
    scope = (payload.get("scope") or "").strip().lower()

    if scope == "all":
        clear_login_failures()
        detail = "Reset all tracked login attempts."
    elif identifier:
        clear_login_failures(identifier)
        detail = f"Reset login attempts for {identifier}."
    else:
        record_validation_rejection(
            "Provide either an identifier or scope=all.",
            field_names=["identifier", "scope"],
        )
        db.session.commit()
        return api_error(
            "Provide either an identifier or scope=all.",
            400,
            code="validation_error",
        )

    record_audit_event(
        action="login_attempts_reset",
        target_type="security",
        detail=detail,
        actor_id=actor.id,
    )
    db.session.commit()
    return jsonify(
        {
            "message": "Login attempt tracker updated.",
            "items": get_login_attempt_snapshot(),
        }
    )


@bp.get("/security-report")
@admin_required
def security_report():
    """Return the built-in secure-vs-demo comparison summary."""
    return jsonify(
        {
            "summary": _overview_summary(),
            "scenarios": _serialise_security_scenarios(),
        }
    )


@bp.get("/security-report/export")
@admin_required
def export_security_report():
    """Download the security comparison summary as CSV or JSON."""
    export_format = (request.args.get("format") or "csv").strip().lower()
    report = security_report().json

    if export_format == "json":
        return jsonify(report)

    rows = [
        [
            item["vulnerability"],
            item["reviewMethod"],
            item["demoRoute"],
            item["beforeState"],
            item["afterState"],
            item["mitigation"],
            "enabled" if item["demoEnabled"] else "disabled",
        ]
        for item in report["scenarios"]
    ]
    return _csv_response(
        "webshield-security-report.csv",
        [
            "vulnerability",
            "review_method",
            "demo_route",
            "before_state",
            "after_state",
            "mitigation",
            "demo_enabled",
        ],
        rows,
    )
