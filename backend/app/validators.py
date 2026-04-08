"""Input validation helpers for auth, support ticket, and admin forms."""

import re


class ValidationError(ValueError):
    """Raised when incoming user data breaks the secure-mode rules."""

    pass


USERNAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,31}$")
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
TICKET_TITLE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,:!?()/&-]{2,149}$")
PASSWORD_UPPER_PATTERN = re.compile(r"[A-Z]")
PASSWORD_LOWER_PATTERN = re.compile(r"[a-z]")
PASSWORD_DIGIT_PATTERN = re.compile(r"\d")
MARKUP_PATTERN = re.compile(
    r"(<[^>]+>|javascript:|on[a-z]+\s*=)",
    re.IGNORECASE,
)
SQLI_PATTERN = re.compile(
    r"(--|/\*|\*/|@@|\binformation_schema\b|\bxp_|\bunion\b\s+\bselect\b|"
    r"\b(select|insert|update|delete|drop|alter)\b.+\b(from|into|table)\b|"
    r"\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
    re.IGNORECASE,
)
COMMAND_PATTERN = re.compile(
    r"(\|\s*/|/etc/passwd|\b(cmd\.exe|powershell|bash|sh|zsh|curl|wget|cat)\b|"
    r"\$\(|`[^`]+`|&&|\|\|)",
    re.IGNORECASE,
)
EDGE_QUOTE_PATTERN = re.compile(r"(^['\"`]|['\"`]$|['\"`]{2,})")
DANGEROUS_CHAR_PATTERN = re.compile(r"[<>`|]")
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")


def _clean_single_line(value: str) -> str:
    """Remove control characters and compress spacing for one-line fields."""
    normalized = CONTROL_CHAR_PATTERN.sub("", value or "")
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _clean_multiline(value: str) -> str:
    """Normalise multi-line text while keeping line breaks meaningful."""
    raw = CONTROL_CHAR_PATTERN.sub("", value or "")
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in raw.splitlines()]
    return "\n".join(line for line in lines if line).strip()


def _reject_markup(value: str, field_name: str) -> None:
    """Block obvious HTML and script patterns in secure mode."""
    if MARKUP_PATTERN.search(value):
        raise ValidationError(
            f"{field_name} contains blocked HTML or script-like content in secure mode."
        )


def _reject_attack_payload(
    value: str,
    field_name: str,
    *,
    strict_quotes: bool = False,
) -> None:
    """Block obvious attack-shaped payloads before they reach the database or UI."""
    if SQLI_PATTERN.search(value) or COMMAND_PATTERN.search(value):
        raise ValidationError(
            f"{field_name} contains blocked attack-like content in secure mode."
        )

    if DANGEROUS_CHAR_PATTERN.search(value):
        raise ValidationError(
            f"{field_name} contains blocked special characters in secure mode."
        )

    if strict_quotes and EDGE_QUOTE_PATTERN.search(value):
        raise ValidationError(
            f"{field_name} contains blocked quote-wrapped or malformed payload content in secure mode."
        )


def validate_username(value: str) -> str:
    """Accept only simple usernames that are safe to store and display."""
    username = _clean_single_line(value)
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValidationError(
            "Username must start with a letter and contain only letters, numbers, dots, dashes, or underscores."
        )
    return username


def validate_email(value: str) -> str:
    """Normalise and validate an email address for account lookups."""
    email = _clean_single_line(value).lower()
    if len(email) > 255 or not EMAIL_PATTERN.fullmatch(email):
        raise ValidationError("A valid email address is required.")
    return email


def validate_password(value: str) -> str:
    """Enforce the minimum password rules used by the application."""
    password = value or ""
    if len(password) < 10:
        raise ValidationError("Password must be at least 10 characters long.")
    if not PASSWORD_UPPER_PATTERN.search(password):
        raise ValidationError("Password must include at least one uppercase letter.")
    if not PASSWORD_LOWER_PATTERN.search(password):
        raise ValidationError("Password must include at least one lowercase letter.")
    if not PASSWORD_DIGIT_PATTERN.search(password):
        raise ValidationError("Password must include at least one number.")
    return password


def validate_ticket_title(value: str) -> str:
    """Check that support ticket titles stay short, readable, and low-risk."""
    title = _clean_single_line(value)
    if len(title) < 3:
        raise ValidationError("Title must be at least 3 characters long.")
    if len(title) > 150:
        raise ValidationError("Title must be 150 characters or fewer.")
    if not TICKET_TITLE_PATTERN.fullmatch(title):
        raise ValidationError(
            "Title contains blocked characters. Use letters, numbers, spaces, and basic punctuation only."
        )
    _reject_markup(title, "Title")
    _reject_attack_payload(title, "Title", strict_quotes=True)
    return title


def validate_ticket_message(value: str) -> str:
    """Check that support ticket bodies are meaningful text, not markup or payloads."""
    message = _clean_multiline(value)
    if len(message) < 10:
        raise ValidationError("Message must be at least 10 characters long.")
    if len(message) > 2000:
        raise ValidationError("Message must be 2000 characters or fewer.")
    _reject_markup(message, "Message")
    _reject_attack_payload(message, "Message", strict_quotes=True)
    return message


def validate_admin_note(value: str) -> str:
    """Validate optional moderator notes stored with ticket history."""
    note = _clean_multiline(value)
    if len(note) > 1200:
        raise ValidationError("Admin note must be 1200 characters or fewer.")
    if note:
        _reject_markup(note, "Admin note")
        _reject_attack_payload(note, "Admin note", strict_quotes=True)
    return note


def validate_feedback_title(value: str) -> str:
    """Backward-compatible alias used by older feedback-named code paths."""
    return validate_ticket_title(value)


def validate_feedback_message(value: str) -> str:
    """Backward-compatible alias used by older feedback-named code paths."""
    return validate_ticket_message(value)
