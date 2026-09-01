"""Honeytoken redaction before export/logging."""

from __future__ import annotations

import re

_REDACTED = "[REDACTED_HONEYTOKEN]"

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"AKIA[0-9A-Z]{16}"), _REDACTED),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), _REDACTED),
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
        _REDACTED,
    ),
    (re.compile(r"(?:postgres|mysql|mongodb)://[^\s\"']+", re.I), _REDACTED),
)


def redact(text: str) -> tuple[str, bool]:
    """Return redacted text and whether any honeytoken pattern matched."""
    found = False
    out = text
    for pattern, repl in _PATTERNS:
        if pattern.search(out):
            found = True
            out = pattern.sub(repl, out)
    return out, found


def redact_indicator_evidence(evidence: str) -> tuple[str, bool]:
    return redact(evidence)
