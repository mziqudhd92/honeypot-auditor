"""Deep probe #6: temporal behavior — latency, clock drift, and egress silence."""

from __future__ import annotations

import statistics
import time
from email.utils import parsedate_to_datetime

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import tcp_transact
from honeypot_auditor.settings import settings

_CLOCK_SKEW_ABS = 300.0  # 5 minutes


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


def probe_idle_accept(host: str, port: int, n: int = 10) -> list[Indicator]:
    """Many idle TCP handshakes with no backoff / 421 — synthetic accept loop."""
    import socket

    accepted = 0
    elapsed: list[float] = []
    socks: list[socket.socket] = []
    try:
        for _ in range(n):
            start = time.monotonic()
            try:
                sock = socket.create_connection((host, port), timeout=min(1.5, settings.timeout_seconds))
                socks.append(sock)
                accepted += 1
                elapsed.append(time.monotonic() - start)
            except OSError:
                break
        mean = statistics.mean(elapsed) if elapsed else 0.0
        triggered = accepted >= n and mean < 0.02
        return [
            Indicator(
                id="deep.idle_accept",
                title="Idle TCP handshakes accepted with no backoff",
                category="temporal",
                triggered=triggered,
                skipped=accepted < 4,
                skip_reason="" if accepted >= 4 else f"only {accepted} idle connects succeeded",
                protocol="tcp",
                detail=f"accepted {accepted}/{n} idle connects mean={mean*1000:.1f}ms",
            )
        ]
    finally:
        for sock in socks:
            try:
                sock.close()
            except Exception:
                pass


def _parse_http_date(value: str) -> float | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            from datetime import timezone

            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def _sample_http_dates(host: str, port: int, samples: int = 3) -> list[str]:
    scheme = "https" if port in (443, 8443) else "http"
    dates: list[str] = []
    from honeypot_auditor.models import optional_import
    from honeypot_auditor.proxy_transport import configure_requests_proxy

    requests = optional_import("requests")
    if requests is not None:
        for _ in range(samples):
            try:
                resp = requests.get(
                    f"{scheme}://{host}:{port}/",
                    timeout=settings.timeout_seconds,
                    allow_redirects=False,
                    verify=False,
                    proxies=configure_requests_proxy() or None,
                )
                dates.append(resp.headers.get("Date", "") or "")
            except Exception:
                break
            time.sleep(1.05)
        return dates
    for _ in range(samples):
        req = (
            b"GET / HTTP/1.1\r\nHost: "
            + host.encode("ascii", "replace")
            + b"\r\nConnection: close\r\n\r\n"
        )
        raw, _ = tcp_transact(host, port, req, recv_first=False)
        date_val = ""
        for line in raw.decode("latin-1", "replace").split("\r\n"):
            if line.lower().startswith("date:"):
                date_val = line.split(":", 1)[1].strip()
                break
        dates.append(date_val)
        time.sleep(1.05)
    return dates


def _sample_smb_system_time(host: str, port: int) -> float | None:
    """Best-effort SMB server time when negotiate facts expose it (optional)."""
    try:
        from honeypot_auditor.smbutil import smb_negotiate_facts
    except ImportError:
        return None
    try:
        facts = smb_negotiate_facts(host, port, timeout=max(1, int(settings.timeout_seconds)))
    except Exception:
        return None
    if not isinstance(facts, dict):
        return None
    for key in ("system_time", "SystemTime", "server_time"):
        raw = facts.get(key)
        if isinstance(raw, (int, float)) and raw > 0:
            if raw > 10_000_000_000_000:
                return (float(raw) / 10_000_000.0) - 11644473600.0
            return float(raw)
    return None


def probe_clock_drift(host: str, port: int, *, smb_port: int | None = None) -> list[Indicator]:
    """HTTP Date vs auditor clock; optional SMB SystemTime; static Date across samples."""
    dates = _sample_http_dates(host, port)
    if not any(dates):
        return [
            skipped_indicator(
                "deep.clock_drift",
                "Service clock skew / frozen Date vs auditor time",
                "temporal",
                "no Date headers sampled",
                protocol="http",
            )
        ]
    now = time.time()
    hits: list[str] = []
    for d in dates:
        ts = _parse_http_date(d)
        if ts is not None:
            skew = abs(ts - now)
            if skew > _CLOCK_SKEW_ABS:
                hits.append(f"HTTP Date skew {skew:.0f}s vs auditor")
    if len(dates) >= 2 and dates[0] and all(d == dates[0] for d in dates):
        hits.append("HTTP Date identical across spaced samples (frozen clock)")
    smb_ts = _sample_smb_system_time(host, smb_port) if smb_port else None
    if smb_ts is not None:
        skew = abs(smb_ts - now)
        if skew > _CLOCK_SKEW_ABS:
            hits.append(f"SMB SystemTime skew {skew:.0f}s vs auditor")
    return [
        Indicator(
            id="deep.clock_drift",
            title="Service clock skew / frozen Date vs auditor time",
            category="temporal",
            triggered=bool(hits),
            protocol="http",
            detail="; ".join(hits) if hits else f"dates={dates[:3]} look plausible",
            evidence=",".join(dates),
            requires_corroboration=True,
            remediation="Sync decoy clocks with NTP or advance Date on each response",
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
