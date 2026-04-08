"""Database models that describe users, support tickets, and audit evidence."""

import html
import re
from datetime import datetime, timezone

from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db

AUDIT_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")


def sanitize_audit_text(value: str | None, max_length: int = 500) -> str | None:
    """Clean log text before it is stored or returned to the frontend."""
    if value is None:
        return None

    cleaned = AUDIT_CONTROL_CHAR_PATTERN.sub("", str(value))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return ""

    if len(cleaned) > max_length:
        cleaned = f"{cleaned[: max_length - 3].rstrip()}..."

    return html.escape(cleaned, quote=False)


class User(db.Model):
    """Account record used for login, role checks, and ownership of support tickets."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_password_changed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # These relationships connect a user to their support tickets, audit trail,
    # and any moderation actions they performed.
    feedback_entries = db.relationship(
        "Feedback",
        back_populates="author",
        cascade="all, delete-orphan",
    )
    audit_events = db.relationship("AuditLog", back_populates="actor")
    feedback_status_events = db.relationship(
        "FeedbackStatusHistory",
        back_populates="actor",
    )

    def set_password(self, password: str) -> None:
        """Hash and store a password instead of saving plain text."""
        self.password_hash = generate_password_hash(password)
        self.last_password_changed_at = datetime.now(timezone.utc)

    def check_password(self, password: str) -> bool:
        """Compare a plain password with the stored hash."""
        return check_password_hash(self.password_hash, password)

    def to_dict(self) -> dict:
        """Return the safe account fields the frontend is allowed to see."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "isActive": self.is_active,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "lastLoginAt": self.last_login_at.isoformat() if self.last_login_at else None,
            "lastPasswordChangedAt": (
                self.last_password_changed_at.isoformat()
                if self.last_password_changed_at
                else None
            ),
        }


class Feedback(db.Model):
    """A support ticket submitted by a normal user and reviewed by admins."""

    # The original table name is preserved so existing databases keep working.
    __tablename__ = "feedback"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    admin_note = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Each support ticket belongs to one author and can have many status updates.
    author = db.relationship("User", back_populates="feedback_entries")
    status_history = db.relationship(
        "FeedbackStatusHistory",
        back_populates="feedback",
        cascade="all, delete-orphan",
        order_by=lambda: FeedbackStatusHistory.created_at.desc(),
    )

    def to_dict(
        self,
        include_author: bool = False,
        include_history: bool = False,
    ) -> dict:
        """Return support ticket data, with optional author and history details."""
        payload = {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "status": self.status,
            "adminNote": self.admin_note,
            "userId": self.user_id,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_author and self.author:
            payload["author"] = {
                "id": self.author.id,
                "username": self.author.username,
                "email": self.author.email,
                "role": self.author.role,
                "isActive": self.author.is_active,
            }
        if include_history:
            payload["history"] = [item.to_dict() for item in self.status_history]
        return payload


class FeedbackStatusHistory(db.Model):
    """Timeline of support ticket state changes, including who made each change."""

    # The original table name is preserved so existing databases keep working.
    __tablename__ = "feedback_status_history"

    id = db.Column(db.Integer, primary_key=True)
    feedback_id = db.Column(db.Integer, db.ForeignKey("feedback.id"), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    previous_status = db.Column(db.String(20), nullable=True)
    next_status = db.Column(db.String(20), nullable=False)
    note = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # This links each history row back to the support ticket and the acting user.
    feedback = db.relationship("Feedback", back_populates="status_history")
    actor = db.relationship("User", back_populates="feedback_status_events")

    def to_dict(self) -> dict:
        """Return one moderation step in a frontend-friendly shape."""
        return {
            "id": self.id,
            "ticketId": self.feedback_id,
            "previousStatus": self.previous_status,
            "nextStatus": self.next_status,
            "note": self.note,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "actor": (
                {
                    "id": self.actor.id,
                    "username": self.actor.username,
                    "email": self.actor.email,
                    "role": self.actor.role,
                }
                if self.actor
                else None
            ),
        }


class AuditLog(db.Model):
    """Security-focused event log for authentication and admin activity."""

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    target_type = db.Column(db.String(50), nullable=False)
    target_id = db.Column(db.Integer, nullable=True)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # This relationship lets audit entries include the user who triggered them.
    actor = db.relationship("User", back_populates="audit_events")

    def to_dict(self) -> dict:
        """Return a cleaned audit entry for admin and audit pages."""
        return {
            "id": self.id,
            "action": self.action,
            "targetType": self.target_type,
            "targetId": self.target_id,
            "detail": sanitize_audit_text(self.detail),
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "actor": (
                {
                    "id": self.actor.id,
                    "username": sanitize_audit_text(self.actor.username),
                    "email": sanitize_audit_text(self.actor.email),
                    "role": self.actor.role,
                }
                if self.actor
                else None
            ),
        }
