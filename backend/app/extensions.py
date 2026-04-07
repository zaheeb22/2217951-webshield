"""Shared Flask extensions used across the whole backend."""

from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

# `db` is imported by models and routes so every module talks to the same database
# session.
db = SQLAlchemy()

# `cors` is attached in app creation so the frontend can call the API safely.
cors = CORS()
