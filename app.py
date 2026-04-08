"""Vercel-friendly root entrypoint for the Flask application."""

from backend.app import create_app

# Vercel looks for a top-level WSGI app named `app` in standard files such as
# `app.py`, so this thin wrapper exposes the existing Flask factory output.
app = create_app()
