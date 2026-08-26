"""Deep probe #5: cross-service co-tenancy / honeypot buffet detection."""

from __future__ import annotations

import socket

from honeypot_auditor.config import EXTENDED_PROBE_PORTS
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import tcp_transact
from honeypot_auditor.settings import settings

# Classic low-interaction honeypot stacks expose many IT lures on one host.
_BUFFET_PROTOCOLS = ("ssh", "telnet", "ftp", "http", "smb", "redis", "smtp", "vnc", "sip")


def _port_open(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(min(1.5, settings.timeout_seconds))
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _has_service_banner(host: str, port: int, proto: str) -> bool:
    if proto == "ssh":
        raw, _ = tcp_transact(host, port, b"", recv_first=True, timeout=1.5)
        return raw.startswith(b"SSH-")
    if proto == "http":
        raw, _ = tcp_transact(host, port, b"GET / HTTP/1.0\r\n\r\n", recv_first=False, timeout=1.5)
        return raw.startswith(b"HTTP/")
    if proto == "ftp":
        raw, _ = tcp_transact(host, port, b"", recv_first=True, timeout=1.5)
        return raw.startswith(b"220")
    if proto == "telnet":
        raw, _ = tcp_transact(host, port, b"", recv_first=True, timeout=1.5)
        return bool(raw)
    if proto == "redis":
        raw, _ = tcp_transact(host, port, b"PING\r\n", recv_first=False, timeout=1.5)
        return b"+PONG" in raw or b"-NOAUTH" in raw or b"-ERR" in raw
    if proto == "smtp":
        raw, _ = tcp_transact(host, port, b"", recv_first=True, timeout=1.5)
        return raw.startswith(b"220")
    return _port_open(host, port)


def probe_cotenancy(host: str, ports: dict[str, int], corroboration: bool = False) -> list[Indicator]:
    """
    Flag implausible multi-service honeypot buffets.

    When corroboration=False (standalone), uses a high threshold (8+ responsive IT lures).
    When corroboration=True (another category already hit), threshold lowers to 5+.
    """
    merged = dict(ports)
    merged.update({k: v for k, v in EXTENDED_PROBE_PORTS.items() if k not in merged})
    responsive: list[str] = []
    for proto in _BUFFET_PROTOCOLS:
        port = merged.get(proto)
        if not port:
            continue
        if _has_service_banner(host, port, proto):
            responsive.append(f"{proto}:{port}")

    threshold = 5 if corroboration else 8
    triggered = len(responsive) >= threshold
    detail = f"{len(responsive)} responsive IT lures: {', '.join(responsive[:12])}"
    if triggered:
        detail += f" (>={threshold} threshold)"
    return [
        Indicator(
            id="deep.cotenancy",
            title="Implausible multi-service honeypot buffet on single IP",
            category="cotenancy",
            triggered=triggered,
            protocol="multi",
            detail=detail,
            evidence=",".join(responsive),
        )
    ]
