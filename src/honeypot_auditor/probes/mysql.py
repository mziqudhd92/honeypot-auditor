"""MySQL fingerprint engine.

Strategies: static signature (EOL 5.5.x ubuntu greeting, stock handshake caps) ·
state non-persistence (session dropped after one 1045, wrong-seq 1156, SSL-request
silent drop). Arbitrary auth is not on the basic path (deny-all is also a real
server with the wrong password).
"""

from __future__ import annotations

import struct

from honeypot_auditor.config import (
    match_mysql_eol_banner,
    match_mysql_pkt_order,
    match_mysql_stock_handshake,
)
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_roundtrips
from honeypot_auditor.probes.common import random_creds, skip_suite

_MYSQL_SKIP = (
    ("mysql.signature", "MySQL greeting is an EOL 5.5.x ubuntu template", "static_signature"),
    (
        "mysql.handshake",
        "MySQL handshake uses stock capability/auth-plugin template",
        "static_signature",
    ),
    ("mysql.persist", "MySQL drops the session after one access-denied", "state_nonpersist"),
    ("mysql.seq_order", "MySQL returns ER 1156 on wrong auth packet sequence", "state_nonpersist"),
    ("mysql.ssl_drop", "MySQL silently drops on CLIENT_SSL handshake request", "state_nonpersist"),
)

# CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH-ish baseline used elsewhere
_MYSQL_BASE_CAPS = 0x0000A285
_CLIENT_SSL = 0x00000800


def parse_mysql_version(raw: bytes) -> str:
    data = raw or b""
    if len(data) < 5:
        return ""
    payload = data[4:] if len(data) > 4 else data
    if not payload.startswith(b"\x0a"):
        idx = data.find(b"\x0a")
        if idx < 0:
            return ""
        payload = data[idx:]
    end = payload.find(b"\x00", 1)
    if end < 0:
        return ""
    return payload[1:end].decode("ascii", "replace")


def _mysql_handshake_response(user: str, *, seq_id: int = 1, caps: int = _MYSQL_BASE_CAPS) -> bytes:
    payload = (
        struct.pack("<I", caps)
        + struct.pack("<I", 16777216)
        + b"\x21"
        + b"\x00" * 23
        + user.encode("ascii", "replace")
        + b"\x00\x00"
    )
    return struct.pack("<I", len(payload))[:3] + bytes([seq_id & 0xFF]) + payload


def _mysql_ssl_request(*, seq_id: int = 1) -> bytes:
    """Capability packet with CLIENT_SSL set — shallow emulators close with no ERR."""
    payload = (
        struct.pack("<I", _MYSQL_BASE_CAPS | _CLIENT_SSL)
        + struct.pack("<I", 16777216)
        + b"\x21"
        + b"\x00" * 23
    )
    return struct.pack("<I", len(payload))[:3] + bytes([seq_id & 0xFF]) + payload


def _mysql_access_denied(raw: bytes) -> bool:
    payload = raw[4:] if len(raw) > 4 else raw
    return payload.startswith(b"\xff") and (b"Access denied" in raw or b"\x29\x04" in payload[:8])


def _mysql_err_packet(raw: bytes) -> bool:
    payload = raw[4:] if len(raw) > 4 else raw
    return payload.startswith(b"\xff")


def _mysql_ssl_drop_probe(host: str, port: int) -> tuple[bool, str, str, bool]:
    """Return (triggered, detail, evidence, skipped). Silent close after CLIENT_SSL is the tell."""
    import socket

    from honeypot_auditor.settings import settings

    timeout = settings.timeout_seconds
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            greeting = b""
            try:
                while len(greeting) < 4096:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    greeting += chunk
                    sock.settimeout(min(0.4, timeout))
            except TimeoutError:
                pass
            if not parse_mysql_version(greeting):
                return False, closed_reason("no greeting"), "", True
            sock.settimeout(timeout)
            sock.sendall(_mysql_ssl_request())
            follow = b""
            try:
                sock.settimeout(min(1.0, timeout))
                follow = sock.recv(4096)
            except TimeoutError:
                follow = b""
            if _mysql_err_packet(follow):
                return (
                    False,
                    "CLIENT_SSL request returned an ERR packet (not a silent drop)",
                    follow[:80].hex(),
                    False,
                )
            still_open = True
            try:
                sock.sendall(b"\x00")
            except OSError:
                still_open = False
            if not still_open and not follow:
                return (
                    True,
                    "CLIENT_SSL handshake request closed the session with no ERR packet",
                    "closed",
                    False,
                )
            return (
                False,
                f"CLIENT_SSL follow-up {len(follow)} bytes (session stayed open)",
                follow[:80].hex() if follow else "open",
                False,
            )
    except OSError as exc:
        return False, closed_reason(str(exc)), str(exc), True


def probe_mysql(host: str, port: int) -> list[Indicator]:
    user, _password = random_creds()
    replies, err = tcp_roundtrips(
        host, port, [_mysql_handshake_response(user), b"\x00"], recv_first=True
    )
    if err and not replies:
        return skip_suite(_MYSQL_SKIP, closed_reason(err), protocol="mysql", error=err)
    greeting = replies[0] if replies else b""
    version = parse_mysql_version(greeting)
    if not version:
        return skip_suite(_MYSQL_SKIP, "not a MySQL handshake speaker", protocol="mysql", error=err)
    deny = replies[1] if len(replies) > 1 else b""
    follow = replies[2] if len(replies) > 2 else b""
    dropped = _mysql_access_denied(deny) and not follow
    eol_hit = match_mysql_eol_banner(version)
    handshake_hit = match_mysql_stock_handshake(greeting)

    seq_replies, seq_err = tcp_roundtrips(
        host,
        port,
        [_mysql_handshake_response(user, seq_id=0), b"\x00"],
        recv_first=True,
    )
    seq_greeting = seq_replies[0] if seq_replies else b""
    seq_reply = seq_replies[1] if len(seq_replies) > 1 else b""
    seq_hit = match_mysql_pkt_order(seq_reply) if seq_greeting else None
    if not seq_hit and seq_err and not seq_reply:
        seq_hit = None

    ssl_dropped, ssl_detail, ssl_evidence, ssl_skipped = _mysql_ssl_drop_probe(host, port)

    return [
        Indicator(
            id="mysql.signature",
            title="MySQL greeting is an EOL 5.5.x ubuntu template",
            category="static_signature",
            triggered=bool(eol_hit),
            protocol="mysql",
            detail=eol_hit or f"version={version}",
            evidence=greeting[:200].decode("utf-8", "replace"),
        ),
        Indicator(
            id="mysql.handshake",
            title="MySQL handshake uses stock capability/auth-plugin template",
            category="static_signature",
            triggered=bool(handshake_hit),
            protocol="mysql",
            detail=handshake_hit or "handshake capability/auth plugin look normal",
            evidence=greeting[:200].decode("utf-8", "replace"),
        ),
        Indicator(
            id="mysql.persist",
            title="MySQL drops the session after one access-denied",
            category="state_nonpersist",
            triggered=dropped,
            protocol="mysql",
            detail=(
                "1045 then connection closed (no retry window)"
                if dropped
                else "session still open after access-denied (or no 1045)"
            ),
            evidence=(deny[:120].hex() if deny else ""),
        ),
        Indicator(
            id="mysql.seq_order",
            title="MySQL returns ER 1156 on wrong auth packet sequence",
            category="state_nonpersist",
            triggered=bool(seq_hit),
            skipped=not seq_greeting,
            skip_reason=""
            if seq_greeting
            else (closed_reason(seq_err) if seq_err else "no greeting"),
            protocol="mysql",
            detail=seq_hit or "wrong auth sequence did not yield ER 1156",
            evidence=seq_reply[:120].hex() if seq_reply else "",
        ),
        Indicator(
            id="mysql.ssl_drop",
            title="MySQL silently drops on CLIENT_SSL handshake request",
            category="state_nonpersist",
            triggered=ssl_dropped,
            skipped=ssl_skipped,
            skip_reason=ssl_detail if ssl_skipped else "",
            protocol="mysql",
            detail=ssl_detail,
            evidence=ssl_evidence,
        ),
    ]
