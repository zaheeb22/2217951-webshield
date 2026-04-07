"""User feedback routes used by the main dashboard page."""

from flask import Blueprint, jsonify, request

from ..extensions import db
from ..models import Feedback, FeedbackStatusHistory
from ..security import api_error, current_user, login_required, record_audit_event
from ..validators import (
    ValidationError,
    validate_feedback_message,
    validate_feedback_title,
)

# These routes belong to normal signed-in users rather than administrators.
bp = Blueprint("feedback", __name__, url_prefix="/api/feedback")


@bp.get("/mine")
@login_required
def list_my_feedback():
    """Return only the feedback records owned by the current user."""
    user = current_user()
    feedback_items = (
        Feedback.query.filter_by(user_id=user.id)
        .order_by(Feedback.created_at.desc())
        .all()
    )
    return jsonify(
        {"items": [item.to_dict(include_history=True) for item in feedback_items]}
    )


@bp.post("/")
@login_required
def create_feedback():
    """Store a new feedback item and create its first history and audit entries."""
    payload = request.get_json(silent=True) or {}
    user = current_user()

    try:
        title = validate_feedback_title(payload.get("title") or "")
        message = validate_feedback_message(payload.get("message") or "")
    except ValidationError as exc:
        return api_error(str(exc), 400, code="validation_error")

    feedback_item = Feedback(
        title=title,
        message=message,
        user_id=user.id,
        status="pending",
    )
    db.session.add(feedback_item)
    db.session.flush()

    # The history row links this feedback item to its very first state.
    db.session.add(
        FeedbackStatusHistory(
            feedback_id=feedback_item.id,
            actor_id=user.id,
            previous_status=None,
            next_status="pending",
            note="Feedback submitted by user.",
        )
    )
    record_audit_event(
        action="feedback_created",
        target_type="feedback",
        target_id=feedback_item.id,
        detail=f"Submitted feedback titled '{title}'",
        actor_id=user.id,
    )
    db.session.commit()

    return (
        jsonify(
            {
                "message": "Feedback submitted and stored securely.",
                "feedback": feedback_item.to_dict(include_history=True),
            }
        ),
        201,
    )
