"""Honeytoken redaction before export/logging."""

from __future__ import annotations

import re

_REDACTED = "[REDACTED_HONEYTOKEN]"

# (family, pattern, replacement)
_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("aws_akia", re.compile(r"AKIA[0-9A-Z]{16}"), _REDACTED),
    ("aws_asia", re.compile(r"ASIA[0-9A-Z]{16}"), _REDACTED),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), _REDACTED),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
        _REDACTED,
    ),
    ("db_uri", re.compile(r"(?:postgres|mysql|mongodb)://[^\s\"']+", re.I), _REDACTED),
    ("canarytokens", re.compile(r"canarytokens\.com", re.I), _REDACTED),
    ("slack_bot", re.compile(r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+"), _REDACTED),
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36}"), _REDACTED),
)


def redact_match_families(text: str) -> list[str]:
    """Return ordered unique pattern family names that match ``text``."""
    found: list[str] = []
    seen: set[str] = set()
    for family, pattern, _ in _PATTERNS:
        if family in seen:
            continue
        if pattern.search(text or ""):
            seen.add(family)
            found.append(family)
    return found


def redact(text: str) -> tuple[str, bool]:
    """Return redacted text and whether any honeytoken pattern matched."""
    found = False
    out = text or ""
    for _family, pattern, repl in _PATTERNS:
        if pattern.search(out):
            found = True
            out = pattern.sub(repl, out)
    return out, found


def redact_indicator_evidence(evidence: str) -> tuple[str, bool]:
    return redact(evidence)
