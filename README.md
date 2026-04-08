# WebShield Lab

WebShield Lab is a Flask and PostgreSQL web application built to show a secure baseline for account management, support ticket moderation, audit logging, and security reporting, while also keeping an isolated demo mode for controlled vulnerability demonstrations.

Flask serves both the frontend pages and the backend API, so local development uses a single server process. The frontend is plain HTML, CSS, and JavaScript. The backend handles authentication, validation, database access, CSRF protection, rate limiting, role checks, and audit evidence.

## What The Project Includes

- session-backed authentication with password hashing
- CSRF protection on state-changing API requests
- login rate limiting and temporary lockout after repeated failures
- role-based access control for admin-only routes
- support ticket submission, moderation, admin notes, and status history
- audit logging for authentication, moderation, admin actions, and lab activity
- admin and audit dashboards with CSV and JSON export
- isolated lab routes for XSS, IDOR, and SQL injection demonstrations
- a dissertation report, citation map, and supporting academic papers in `report/`

## Project Structure

```text
Zproject/
├── run.py
├── README.md
├── backend/
│   ├── .env.example
│   ├── requirements.txt
│   ├── run.py
│   ├── logs/
│   ├── tests/
│   │   └── test_auth_security.py
│   └── app/
│       ├── __init__.py
│       ├── config.py
│       ├── extensions.py
│       ├── models.py
│       ├── security.py
│       ├── validators.py
│       └── routes/
│           ├── admin.py
│           ├── auth.py
│           ├── tickets.py
│           └── lab.py
├── frontend/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── admin.html
│   ├── audit.html
│   ├── lab.html
│   └── assets/
│       ├── css/
│       └── js/
├── docs/
│   └── architecture.md
└── report/
    ├── WebShield_Lab_Report.docx
    ├── WebShield_Lab_Report.html
    ├── section_citation_map.md
    └── papers/
```

## Architecture Summary

The project is split into three clear layers:

- `frontend/` contains the browser pages and JavaScript modules. It renders UI, collects form input, and calls the backend API.
- `backend/app/` contains the Flask application, security logic, models, and routes. This is where validation, sessions, role checks, audit logging, and database access happen.
- PostgreSQL is the main persistent data store for users, support ticket records, audit logs, and ticket status history.

The backend exposes these main API groups:

- `/api/auth` for register, login, logout, session status, CSRF token, and password change
- `/api/tickets` for user-owned support ticket records
- `/api/admin` for user management, moderation, audit export, login-attempt review, and security-report export
- `/api/lab` for intentionally unsafe demo routes, available only when demo mode is enabled

## Requirements

- Python 3.11 or newer
- PostgreSQL
- a virtual environment for backend dependencies

No frontend build tool is required.

## Quick Start

1. Create a virtual environment in `backend/`:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

2. Copy the example environment file and update the database settings if needed:

```bash
cp .env.example .env
```

3. Create a PostgreSQL database named `webshield_lab`, or change `DATABASE_URL` in `backend/.env` to point at your own database.

4. Start the application from the project root:

```bash
cd /path/to/Zproject
python3 run.py
```

5. Open the app in the browser:

```text
http://127.0.0.1:5000
```

## Startup Notes

- `run.py` at the project root is the main entrypoint.
- `backend/run.py` is still available if you prefer to launch from inside `backend/`.
- Both launchers can re-exec with `backend/.venv` automatically when the current interpreter does not already have `Flask` and `click`.
- Flask serves the frontend pages directly, so a separate frontend dev server is not needed.

## Create An Admin Account

After the app is running, create an admin user from another terminal:

```bash
cd /path/to/Zproject
source backend/.venv/bin/activate
flask --app run.py seed-admin
```

## Main Pages

- `/` or `/index.html`: landing page with session and environment overview
- `/register.html`: new account registration
- `/login.html`: sign in page
- `/dashboard.html`: authenticated user dashboard
- `/admin.html`: admin dashboard for moderation, user management, exports, and security summary
- `/audit.html`: admin-focused audit review page
- `/lab.html`: demo-only vulnerability page

## Security Features

- `Authentication`: passwords are hashed with Werkzeug, sessions are server-backed, and password changes rotate the CSRF token
- `Session handling`: the backend resolves the current user on each request and clears the session if the account has been disabled
- `CSRF protection`: unsafe API methods require a valid session-bound CSRF token
- `Rate limiting`: repeated failed logins are tracked and temporarily locked out
- `Input validation`: usernames, emails, passwords, support ticket titles, ticket bodies, and admin notes are validated before use
- `Authorization`: decorators enforce login-only and admin-only access
- `Auditability`: registration, login success and failure, logout, password changes, moderation actions, resets, and lab events are written to the audit log
- `Safer error handling`: API errors return structured JSON instead of raw stack traces
- `Frontend safety`: secure pages use safe DOM updates, while unsafe DOM behavior is isolated to `lab.js`

## Database Coverage

The main database tables represented in the SQLAlchemy models are:

- `users`: account identity, hashed password, role, active state, and account timestamps
- `feedback`: the stored support ticket records plus moderation state
- `feedback_status_history`: a timeline of moderation changes for each support ticket
- `audit_logs`: security-relevant events for traceability and export

## Demo Mode

Set `LAB_MODE=demo` in `backend/.env` and restart the backend to unlock the intentionally unsafe lab routes:

```text
http://127.0.0.1:5000/lab.html
```

Demo mode is local-only and is meant for controlled comparison work. It includes:

- reflected unsafe HTML rendering for XSS demonstration
- missing object-level authorization on support ticket lookup for IDOR demonstration
- string-concatenated SQL search for SQL injection discussion

Keep `LAB_MODE=secure` for normal development.

## Logging And Error Storage

- backend exceptions are written to `backend/logs/error.log`
- audit events are stored in the database and exposed through admin and audit views
- admin routes can export audit data and the security scenario summary as CSV or JSON

## Testing

The repository currently includes a focused backend security test file:

```bash
source backend/.venv/bin/activate
python3 -m unittest backend/tests/test_auth_security.py
```

This test currently verifies:

- successful login creates an authenticated session
- repeated failed logins trigger the configured rate-limit lockout

Automated test coverage is intentionally smaller than the full report scope. The app is structured so additional tests can be added for CSRF enforcement, admin-route protection, validation behavior, support ticket isolation, and audit exports.

## Report Assets

The `report/` folder contains the written project material:

- `WebShield_Lab_Report.docx`: Word version of the report
- `WebShield_Lab_Report.html`: editable HTML source of the report
- `section_citation_map.md`: section-by-section citation planning notes
- `papers/`: supporting academic PDFs used for the report

## Documentation

- `docs/architecture.md` explains the intended frontend/backend/database split
- the source code now includes simple comments and docstrings to explain functions and relationships in plain terms

## Known Development Limits

- login rate limiting is currently in-memory, so it is process-local rather than shared across multiple instances
- `SESSION_COOKIE_SECURE` is left off for local HTTP development and should be enabled for real HTTPS deployment
- the repo includes built-in report/export support, but external tool evidence such as OWASP ZAP or SQLMap output is not bundled by default
