"""Deep probe #3: HASSH and TCP stack fingerprinting."""

from __future__ import annotations

import socket
import time

from honeypot_auditor.config import claimed_os_from_banner, match_tls_stock_cert
from honeypot_auditor.hassh import capture_server_kexinit, hassh_algo_mismatch
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.settings import settings

_CLIENT_BANNER = b"SSH-2.0-honeypot_auditor_1.0\r\n"


def probe_hassh(host: str, port: int) -> list[Indicator]:
    payload = _CLIENT_BANNER
    raw, err = tcp_transact(
        host,
        port,
        payload,
        recv_first=True,
        timeout=max(4.0, settings.timeout_seconds),
        max_bytes=16384,
    )
    if err and not raw:
        return [
            skipped_indicator(
                "deep.hassh",
                "SSH HASSHServer diverges from claimed OpenSSH baseline",
                "stack_fingerprint",
                closed_reason(err),
                protocol="ssh",
                error=err,
            )
        ]
    banner, kex = capture_server_kexinit(raw)
    if kex is None:
        return [
            Indicator(
                id="deep.hassh",
                title="SSH HASSHServer diverges from claimed OpenSSH baseline",
                category="stack_fingerprint",
                triggered=False,
                protocol="ssh",
                detail=f"no KEXINIT captured; banner={banner or '?'}",
                evidence=raw[:800].decode("utf-8", "replace"),
            )
        ]
    triggered, detail = hassh_algo_mismatch(banner, kex)
    return [
        Indicator(
            id="deep.hassh",
            title="SSH HASSHServer diverges from claimed OpenSSH baseline",
            category="stack_fingerprint",
            triggered=triggered,
            protocol="ssh",
            detail=detail,
            evidence=f"banner={banner} hassh_server={kex.hassh_server} kex={kex.kex[:120]}",
        )
    ]


def probe_tcp_stack(host: str, port: int, claimed_os: str = "linux") -> list[Indicator]:
    """SYN-less stack hints via socket connect + IP TTL peek (best-effort)."""
    try:
        with socket.create_connection((host, port), timeout=settings.timeout_seconds) as sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            local = sock.getsockname()
            _ = local
    except OSError as exc:
        return [
            skipped_indicator(
                "deep.tcp_stack",
                "TCP/IP stack traits inconsistent with claimed OS",
                "stack_fingerprint",
                closed_reason(str(exc)),
                protocol="tcp",
                error=str(exc),
            )
        ]

    ttl_hint = ""
    window_hint = ""
    try:
        scapy = __import__("scapy.all", fromlist=["IP", "TCP", "sr1"])
        IP = scapy.IP
        TCP = scapy.TCP
        sr1 = scapy.sr1
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=settings.timeout_seconds, verbose=0)
        if resp is not None:
            ttl_hint = str(getattr(resp, "ttl", ""))
            window_hint = str(getattr(getattr(resp, "payload", None), "window", ""))
    except ImportError:
        return [
            skipped_indicator(
                "deep.tcp_stack",
                "TCP/IP stack traits inconsistent with claimed OS",
                "stack_fingerprint",
                "scapy not installed (pip install honeypot-auditor[full])",
                protocol="tcp",
            )
        ]
    except Exception as exc:
        return [
            skipped_indicator(
                "deep.tcp_stack",
                "TCP/IP stack traits inconsistent with claimed OS",
                "stack_fingerprint",
                str(exc),
                protocol="tcp",
                error=str(exc),
            )
        ]

    triggered = False
    detail_parts = [f"ttl={ttl_hint or '?'} window={window_hint or '?'}"]
    if ttl_hint.isdigit():
        ttl = int(ttl_hint)
        # Linux/Docker often 64, Windows 128. Claimed Windows SMB with TTL 64 is suspicious.
        if claimed_os.lower().startswith("win") and 48 <= ttl <= 72:
            triggered = True
            detail_parts.append("TTL looks Linux-like but service claims Windows")
        if claimed_os.lower() == "linux" and ttl >= 120:
            triggered = True
            detail_parts.append("TTL looks Windows-like on claimed Linux service")

    return [
        Indicator(
            id="deep.tcp_stack",
            title="TCP/IP stack traits inconsistent with claimed OS",
            category="stack_fingerprint",
            triggered=triggered,
            protocol="tcp",
            detail="; ".join(detail_parts),
            evidence=f"port={port} ttl={ttl_hint} win={window_hint}",
        )
    ]


def probe_tls_ja4s(host: str, port: int) -> list[Indicator]:
    """TLS ServerHello + certificate CN/SAN vs stock lab templates."""
    if port not in (443, 8443) and port < 1024:
        pass
    try:
        ssl = __import__("ssl")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        start = time.monotonic()
        cert_text = ""
        with socket.create_connection((host, port), timeout=settings.timeout_seconds) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cipher = tls.cipher()
                version = tls.version()
                try:
                    cert_text = ssl.get_server_certificate((host, port))
                except Exception:
                    cert_text = str(tls.getpeercert() or "")
        elapsed = time.monotonic() - start
        cn_hit = match_tls_stock_cert(cert_text)
        detail = f"tls={version} cipher={cipher}"
        if cn_hit:
            detail = f"{cn_hit}; {detail}"
        return [
            Indicator(
                id="deep.tls_ja4s",
                title="TLS ServerHello / certificate looks like a stock lure",
                category="stack_fingerprint",
                triggered=bool(cn_hit),
                protocol="tls",
                detail=detail,
                evidence=f"handshake={elapsed:.3f}s cert={cert_text[:240]!r}",
            )
        ]
    except Exception as exc:
        return [
            skipped_indicator(
                "deep.tls_ja4s",
                "TLS ServerHello / certificate looks like a stock lure",
                "stack_fingerprint",
                closed_reason(str(exc)),
                protocol="tls",
                error=str(exc),
            )
        ]


def probe_banner_vs_stack(host: str, port: int) -> list[Indicator]:
    """Banner claims Windows/Linux but TCP TTL matches the other family."""
    raw, err = tcp_transact(host, port, b"", recv_first=True)
    if err and not raw:
        return [
            skipped_indicator(
                "deep.banner_stack",
                "TCP/IP stack traits inconsistent with service banner",
                "stack_fingerprint",
                closed_reason(err),
                protocol="tcp",
                error=err,
            )
        ]
    claimed = claimed_os_from_banner(raw.decode("latin-1", "replace"))
    if not claimed:
        return [
            skipped_indicator(
                "deep.banner_stack",
                "TCP/IP stack traits inconsistent with service banner",
                "stack_fingerprint",
                "banner does not claim an OS family",
                protocol="tcp",
            )
        ]
    return probe_tcp_stack(host, port, claimed_os=claimed)
