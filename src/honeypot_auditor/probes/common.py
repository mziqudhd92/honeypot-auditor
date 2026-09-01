"""Shared helpers for per-protocol fingerprint engines."""

from __future__ import annotations

import secrets

from honeypot_auditor.config import PROBE_PASSWORD_TEMPLATE, PROBE_USERNAME_TEMPLATE
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.settings import settings


def is_safe_mode() -> bool:
    return bool(settings.safe_mode)


def safe_skip_specs(
    specs: tuple[tuple[str, str, str], ...],
    *,
    protocol: str,
    reason: str = "safe-mode: handshake-only probe",
) -> list[Indicator]:
    """Mark non-handshake strategies as skipped in safe mode."""
    return skip_suite(specs, reason, protocol=protocol)


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
