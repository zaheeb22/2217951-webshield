"""User support ticket routes used by the main dashboard page."""

from flask import Blueprint, jsonify, request

from ..extensions import db
from ..models import Feedback as SupportTicket
from ..models import FeedbackStatusHistory as SupportTicketStatusHistory
from ..security import (
    api_error,
    current_user,
    login_required,
    record_audit_event,
    record_validation_rejection,
)
from ..validators import ValidationError, validate_ticket_message, validate_ticket_title

# These routes belong to normal signed-in users rather than administrators.
bp = Blueprint("tickets", __name__, url_prefix="/api/tickets")


@bp.get("/mine")
@login_required
def list_my_tickets():
    """Return only the support tickets owned by the current user."""
    user = current_user()
    ticket_items = (
        SupportTicket.query.filter_by(user_id=user.id)
        .order_by(SupportTicket.created_at.desc())
        .all()
    )
    return jsonify(
        {"items": [item.to_dict(include_history=True) for item in ticket_items]}
    )


@bp.post("/")
@login_required
def create_ticket():
    """Store a new support ticket and create its first history and audit entries."""
    payload = request.get_json(silent=True) or {}
    user = current_user()

    try:
        title = validate_ticket_title(payload.get("title") or "")
        message = validate_ticket_message(payload.get("message") or "")
    except ValidationError as exc:
        record_validation_rejection(str(exc), field_names=["title", "message"])
        db.session.commit()
        return api_error(str(exc), 400, code="validation_error")

    ticket_item = SupportTicket(
        title=title,
        message=message,
        user_id=user.id,
        status="pending",
    )
    db.session.add(ticket_item)
    db.session.flush()

    # The history row links this ticket to its very first lifecycle state.
    db.session.add(
        SupportTicketStatusHistory(
            feedback_id=ticket_item.id,
            actor_id=user.id,
            previous_status=None,
            next_status="pending",
            note="Support ticket submitted by user.",
        )
    )
    record_audit_event(
        action="ticket_created",
        target_type="ticket",
        target_id=ticket_item.id,
        detail=f"Submitted support ticket titled '{title}'",
        actor_id=user.id,
    )
    db.session.commit()

    return (
        jsonify(
            {
                "message": "Support ticket submitted and stored securely.",
                "ticket": ticket_item.to_dict(include_history=True),
            }
        ),
        201,
    )
