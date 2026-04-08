"""Intentionally unsafe demo routes kept separate from the secure baseline."""

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import text

from ..extensions import db
from ..models import Feedback as SupportTicket
from ..security import api_error, record_audit_event

bp = Blueprint("lab", __name__, url_prefix="/api/lab")


def _require_demo_mode():
    """Block vulnerable routes unless the app was started in demo mode."""
    if current_app.config["LAB_MODE"].lower() != "demo":
        return api_error(
            "Vulnerable demo routes are disabled. Set LAB_MODE=demo and restart the backend to use them.",
            403,
            code="lab_disabled",
        )
    return None


@bp.get("/status")
def lab_status():
    """Tell the frontend whether insecure demo routes are currently available."""
    demo_enabled = current_app.config["LAB_MODE"].lower() == "demo"
    return jsonify(
        {
            "mode": current_app.config["LAB_MODE"],
            "demoEnabled": demo_enabled,
            "warning": (
                "Intentionally vulnerable lab routes must only be used in a local, isolated environment."
            ),
        }
    )


@bp.post("/echo-preview")
def echo_preview():
    """Return raw HTML on purpose so reflected XSS can be demonstrated safely."""
    demo_error = _require_demo_mode()
    if demo_error is not None:
        return demo_error

    payload = request.get_json(silent=True) or {}
    raw_markup = (payload.get("content") or "")[:1200]
    record_audit_event(
        action="lab_echo_preview",
        target_type="lab",
        detail="Rendered intentionally unsafe reflected preview.",
    )
    db.session.commit()
    return jsonify(
        {
            "message": "Unsafe preview rendered by the vulnerable lab route.",
            "unsafeHtml": raw_markup,
        }
    )


@bp.get("/public-tickets/<int:ticket_id>")
def public_ticket(ticket_id: int):
    """Return a support ticket without ownership checks to demonstrate IDOR behavior."""
    demo_error = _require_demo_mode()
    if demo_error is not None:
        return demo_error

    ticket_item = db.session.get(SupportTicket, ticket_id)
    if ticket_item is None:
        return api_error("Support ticket not found.", 404, code="not_found")

    record_audit_event(
        action="lab_public_ticket_lookup",
        target_type="ticket",
        target_id=ticket_item.id,
        detail="Loaded a support ticket without object-level authorization checks.",
    )
    db.session.commit()
    return jsonify(
        {
            "warning": "This route intentionally skips object-level authorization checks.",
            "ticket": ticket_item.to_dict(include_author=True),
        }
    )


@bp.get("/insecure-search")
def insecure_search():
    """Run a deliberately unsafe SQL search for SQL injection demonstrations."""
    demo_error = _require_demo_mode()
    if demo_error is not None:
        return demo_error

    title = (request.args.get("title") or "").strip()
    if not title:
        return api_error("A title query is required.", 400, code="validation_error")

    insecure_query = (
        "SELECT id, title, status, user_id "
        "FROM feedback "
        f"WHERE title ILIKE '%{title}%' "
        "ORDER BY created_at DESC"
    )

    try:
        rows = db.session.execute(text(insecure_query)).mappings().all()
    except Exception as exc:
        return jsonify(
            {
                "error": str(exc),
                "query": insecure_query,
                "warning": "The vulnerable lab route exposed a raw database error.",
            }
        ), 500

    record_audit_event(
        action="lab_insecure_search",
        target_type="lab",
        detail="Executed intentionally concatenated SQL search query.",
    )
    db.session.commit()
    return jsonify(
        {
            "query": insecure_query,
            "rows": [dict(row) for row in rows],
            "warning": "This route intentionally builds SQL with string concatenation.",
        }
    )
