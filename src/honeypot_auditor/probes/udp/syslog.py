"""Syslog fingerprint engine (RFC 3164 / RFC 5424 over UDP, RFC 6587 over TCP).

Syslog has no request/response channel by design — RFC 5426 datagrams are
fire-and-forget, and RFC 6587 TCP frames are consumed in silence. Detection is
therefore purely RFC-behavioral (no signatures):
  · static_signature — any bytes back on the ack-less UDP channel
  · static_signature — any bytes back on the TCP framing channel (echo/ACK)
Non-destructive: two single-line synthetic messages per transport, no floods.
UDP/514 (lab 10514); TCP 514 shares the IANA port (RFC 6587). A silent open
port is honest syslog and does not score.
"""

from __future__ import annotations

from contextlib import closing

from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, udp_exchange
from honeypot_auditor.probes.common import is_safe_mode
from honeypot_auditor.probes.udp._engine import UDPEngine
from honeypot_auditor.proxy_transport import create_connection
from honeypot_auditor.settings import settings

_SYSLOG_SKIP = (
    (
        "syslog.unexpected_reply",
        "Syslog replies on an ack-less UDP channel",
        "static_signature",
    ),
    (
        "syslog.tcp_reply",
        "Syslog TCP framing channel answers or echoes",
        "static_signature",
    ),
)

# RFC 3164 line: PRI <13> user-level notice, timestamp, host, tag, content.
_RFC3164_LINE = b"<13>Feb  5 17:32:18 hpaudit hpaudit-tag: decoy probe line"
# RFC 5424 line: PRI 34, VERSION 1, timestamp, host, app, procid, msgid, '-' SD.
_RFC5424_LINE = b"<34>1 2026-01-01T00:00:00.000Z hpaudit hpaudit-app 1234 ID47 - decoy probe line"
# RFC 6587 non-transparent framing: newline-terminated TCP frame.
_TCP_FRAME = b"<13>1 2026-01-01T00:00:00.000Z hpaudit hpaudit-app - - - tcp decoy probe\n"


def probe_syslog(host: str, port: int) -> list[Indicator]:
    udp_replies: list[bytes] = []
    udp_errors: list[str] = []
    for payload in (_RFC3164_LINE, _RFC5424_LINE):
        try:
            exchange = udp_exchange(host, port, payload, timeout=settings.timeout_seconds)
        except Exception as exc:
            udp_errors.append(closed_reason(str(exc)))
            continue
        if exchange.error and not exchange.data:
            udp_errors.append(exchange.error)
        elif exchange.data:
            udp_replies.append(exchange.data)

    tcp_reply = b""
    tcp_error = ""
    tcp_skipped = False
    if is_safe_mode():
        tcp_skipped = True
    else:
        try:
            with closing(create_connection(host, port, settings.timeout_seconds)) as sock:
                sock.settimeout(settings.timeout_seconds)
                sock.sendall(_TCP_FRAME)
                try:
                    tcp_reply = sock.recv(512)
                except TimeoutError:
                    tcp_reply = b""
        except OSError as exc:
            tcp_error = closed_reason(str(exc))
            tcp_skipped = True

    udp_hit = bool(udp_replies)
    tcp_hit = bool(tcp_reply)
    return [
        Indicator(
            id="syslog.unexpected_reply",
            title="Syslog replies on an ack-less UDP channel",
            category="static_signature",
            triggered=udp_hit,
            skipped=bool(udp_errors) and not udp_hit,
            skip_reason="; ".join(udp_errors),
            protocol="syslog",
            detail=(
                f"RFC 3164/5424 datagrams drew {len(udp_replies)} reply datagrams "
                "(RFC 5426 syslog never acknowledges)"
                if udp_hit
                else "UDP channel silent, as real syslog requires"
            ),
            evidence=" | ".join(r[:80].decode("utf-8", "replace") for r in udp_replies),
            remediation="Syslog over UDP (RFC 5426) has no reply channel — never answer datagrams",
        ),
        Indicator(
            id="syslog.tcp_reply",
            title="Syslog TCP framing channel answers or echoes",
            category="static_signature",
            triggered=tcp_hit,
            skipped=tcp_skipped,
            skip_reason=tcp_error if tcp_skipped else "",
            protocol="syslog",
            detail=(
                f"RFC 6587 TCP frame drew a {len(tcp_reply)}-byte reply (real syslog consumes in silence)"
                if tcp_hit
                else "TCP framing channel silent or closed without data"
            ),
            evidence=tcp_reply[:120].decode("utf-8", "replace"),
            remediation="RFC 6587 TCP syslog never replies to well-formed frames",
        ),
    ]


UDP_ENGINE = UDPEngine(name="syslog", probe=probe_syslog)

__all__ = ["UDP_ENGINE", "probe_syslog"]
