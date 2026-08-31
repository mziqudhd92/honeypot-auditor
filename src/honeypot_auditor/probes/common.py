"""Shared helpers for per-protocol fingerprint engines."""

from __future__ import annotations

import secrets

from honeypot_auditor.config import PROBE_PASSWORD_TEMPLATE, PROBE_USERNAME_TEMPLATE
from honeypot_auditor.models import Indicator, skipped_indicator


def skip_suite(
    specs: tuple[tuple[str, str, str], ...],
    reason: str,
    *,
    protocol: str,
    error: str = "",
) -> list[Indicator]:
    return [
        skipped_indicator(i, title, cat, reason, protocol=protocol, error=error)
        for i, title, cat in specs
    ]


def random_creds() -> tuple[str, str]:
    n = 10 + secrets.randbelow(89)
    return PROBE_USERNAME_TEMPLATE.format(n=n), PROBE_PASSWORD_TEMPLATE.format(n=n + 69)
