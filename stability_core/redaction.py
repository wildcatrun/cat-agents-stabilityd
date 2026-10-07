"""Best-effort redaction for diagnostic text before it enters evidence or logs."""

from __future__ import annotations

import re
from typing import Any


_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)([\"']?(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|client[_-]?secret|"
    r"secret|password|passwd|authorization|cookie|private[_-]?key)[\"']?\s*[:=]\s*)"
    r"(?:Bearer\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]*")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_SENSITIVE_FLAG = re.compile(
    r"(?i)(--?(?:api[-_]?key|client[-_]?secret|access[-_]?token|refresh[-_]?token|password|passwd|secret|authorization)\s+)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_TELEGRAM_BOT_URL = re.compile(r"(?i)(https?://api\.telegram\.org/bot)[0-9]{5,}:[A-Za-z0-9_-]{20,}")
_URL_PASSWORD = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^:/\s@]+:)[^@\s]+(@)")
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.DOTALL,
)


def redact_sensitive_text(value: Any, max_chars: int = 2000) -> str:
    """Redact common credential forms, then bound output length."""
    raw = str(value or "")
    raw = _PRIVATE_KEY_BLOCK.sub("[REDACTED_PRIVATE_KEY]", raw)
    raw = _JWT.sub("[REDACTED_JWT]", raw)
    raw = _SENSITIVE_ASSIGNMENT.sub(r"\1[REDACTED]", raw)
    raw = _SENSITIVE_FLAG.sub(r"\1[REDACTED]", raw)
    raw = _BEARER.sub("Bearer [REDACTED]", raw)
    raw = _TELEGRAM_BOT_URL.sub(r"\1[REDACTED]", raw)
    raw = _URL_PASSWORD.sub(r"\1[REDACTED]\2", raw)
    try:
        limit = max(0, int(max_chars))
    except (TypeError, ValueError, OverflowError):
        limit = 2000
    return raw[-limit:] if limit else ""


def safe_error_category(value: Any) -> str:
    """Map arbitrary diagnostic text to a small non-sensitive category."""
    text = str(value or "").lower()
    if any(term in text for term in ("timeout", "timed out", "deadline")):
        return "timeout"
    if any(term in text for term in ("unauthorized", "forbidden", "401", "403", "auth")):
        return "authorization"
    if any(term in text for term in ("network", "connection", "dns", "unreachable", "reset by peer")):
        return "network"
    if any(term in text for term in ("locked", "busy", "contention")):
        return "contention"
    return "unknown"
