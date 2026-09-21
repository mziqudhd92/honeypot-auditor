"""Shared helpers for per-protocol fingerprint engines."""

from __future__ import annotations

import secrets
import string
import time

from honeypot_auditor.config import PROBE_PASSWORD_TEMPLATE, PROBE_USERNAME_TEMPLATE
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.settings import settings

_HIGH_ENTROPY_ALPHABET = string.ascii_letters + string.digits + "-_."


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


def entropy_varied_creds() -> tuple[tuple[str, str], tuple[str, str]]:
    """Return (low-entropy, high-entropy) synthetic credential pairs.

    Dual-auth façades often regex-match password-like strings or accept any
    garbage; probing both shapes avoids false negatives either way.
    """
    low_n = 10 + secrets.randbelow(89)
    low = (
        PROBE_USERNAME_TEMPLATE.format(n=low_n),
        PROBE_PASSWORD_TEMPLATE.format(n=low_n + 69),
    )
    high_user = "hpa_" + "".join(secrets.choice(_HIGH_ENTROPY_ALPHABET) for _ in range(20))
    high_pass = "".join(secrets.choice(_HIGH_ENTROPY_ALPHABET) for _ in range(28))
    return low, (high_user, high_pass)


def jittered_reconnect_pause(*, min_ms: int = 40, max_ms: int = 220) -> float:
    """Sleep a short random delay before a state re-check (methodology, not scored)."""
    lo = max(0, int(min_ms))
    hi = max(lo, int(max_ms))
    delay_ms = lo if lo == hi else lo + secrets.randbelow(hi - lo + 1)
    delay_s = delay_ms / 1000.0
    if delay_s > 0:
        time.sleep(delay_s)
    return delay_s


def rtt_evidence(*rtt_ms: float) -> str:
    """Format RTT samples for indicator evidence (never a standalone score)."""
    vals = [float(r) for r in rtt_ms if r is not None]
    if not vals:
        return ""
    if len(vals) == 1:
        return f"rtt_ms={vals[0]:.2f}"
    spread = max(vals) - min(vals)
    joined = ",".join(f"{v:.2f}" for v in vals)
    return f"rtt_ms=[{joined}] delta={spread:.2f}"
