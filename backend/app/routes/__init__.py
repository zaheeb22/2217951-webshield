"""Collect the route blueprints in one place so app creation stays simple."""

from .admin import bp as admin_bp
from .auth import bp as auth_bp
from .feedback import bp as feedback_bp
from .lab import bp as lab_bp

__all__ = ["admin_bp", "auth_bp", "feedback_bp", "lab_bp"]
