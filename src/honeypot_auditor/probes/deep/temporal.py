"""Deep probe #6: temporal behavior — latency distribution and egress silence."""

from __future__ import annotations

import statistics
import time

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import tcp_transact
from honeypot_auditor.settings import settings


def probe_latency_distribution(host: str, port: int, samples: int = 8) -> list[Indicator]:
    """Low-variance response times suggest canned emulator handlers."""
    timings: list[float] = []
    for _ in range(samples):
        start = time.monotonic()
        raw, err = tcp_transact(host, port, b"", recv_first=True, timeout=settings.timeout_seconds)
        elapsed = time.monotonic() - start
        if err and not raw:
            break
        timings.append(elapsed)
        time.sleep(0.02)

    if len(timings) < 4:
        return [
            skipped_indicator(
                "deep.latency",
                "Response latency distribution unnaturally uniform",
                "temporal",
                "insufficient samples",
                protocol="tcp",
            )
        ]

    mean = statistics.mean(timings)
    stdev = statistics.pstdev(timings) if len(timings) > 1 else 0.0
    cv = (stdev / mean) if mean > 0 else 0.0
    # Coefficient of variation < 0.08 with mean < 50ms → suspiciously robotic
    triggered = mean < 0.05 and cv < 0.08
    detail = f"mean={mean*1000:.1f}ms stdev={stdev*1000:.1f}ms cv={cv:.3f} n={len(timings)}"
    return [
        Indicator(
            id="deep.latency",
            title="Response latency distribution unnaturally uniform",
            category="temporal",
            triggered=triggered,
            protocol="tcp",
            detail=detail,
            evidence=",".join(f"{t:.4f}" for t in timings),
        )
    ]


def probe_egress_silence(host: str, ssh_port: int) -> list[Indicator]:
    """
    Bait DNS lookup via shell when session exists; flag default-deny egress typical of contained honeypots.
    Skipped without shell access.
    """
    from honeypot_auditor.sshutil import random_creds, ssh_exec, try_ssh_auth

    user, password = random_creds()
    client, err = try_ssh_auth(host, ssh_port, user, password)
    if client is None:
        return [
            skipped_indicator(
                "deep.egress",
                "Contained honeypot egress silence after bait command",
                "temporal",
                "no SSH session",
                protocol="ssh",
                error=err,
            )
        ]
    token = "hpaudit-egress.invalid"
    cmd = f"getent hosts {token} 2>/dev/null || nslookup {token} 2>&1 | head -3"
    try:
        out, exec_err, _ = ssh_exec(client, cmd, timeout=max(4.0, settings.timeout_seconds))
    finally:
        try:
            client.close()
        except Exception:
            pass

    if exec_err:
        return [
            Indicator(
                id="deep.egress",
                title="Contained honeypot egress silence after bait command",
                category="temporal",
                triggered=True,
                protocol="ssh",
                detail=f"egress bait command failed: {exec_err}",
                evidence=out[:500],
            )
        ]
    # NXDOMAIN / not found is normal; immediate empty with no resolver output on nslookup bait is fine.
    triggered = "connection timed out" in out.lower() or "network is unreachable" in out.lower()
    return [
        Indicator(
            id="deep.egress",
            title="Contained honeypot egress silence after bait command",
            category="temporal",
            triggered=triggered,
            protocol="ssh",
            detail=out[:180] or "resolver output present",
            evidence=out[:800],
        )
    ]
