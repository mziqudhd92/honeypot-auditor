"""MSSQL / TDS fingerprint engine.

Strategies: static signature (canned nmap prelogin, PRELOGIN encrypt NOT SUP) ·
state non-persistence (canned LOGIN7 18456 failure, TLS close after ENCRYPT_NOT_SUP).
Arbitrary auth is not on the basic path.
"""

from __future__ import annotations

import struct

from honeypot_auditor.config import (
    MSSQL_NMAP_PRELOGIN_PAYLOAD,
    match_mssql_canned_prelogin,
    match_mssql_login7_canned,
    match_mssql_prelogin_encrypt,
)
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_roundtrips, tcp_transact
from honeypot_auditor.probes.common import random_creds, skip_suite

_MSSQL_SKIP = (
    ("mssql.signature", "MSSQL prelogin is a canned nmap-shaped template", "static_signature"),
    ("mssql.prelogin", "MSSQL PRELOGIN advertises encryption NOT SUP", "static_signature"),
    ("mssql.login7", "MSSQL LOGIN7 gets a canned 18456 failure", "state_nonpersist"),
    ("mssql.tls_drop", "MSSQL closes on TLS after advertising ENCRYPT_NOT_SUP", "state_nonpersist"),
)

# Minimal TLS ClientHello record — shallow TDS lures only check the leading 0x16 byte.
_TLS_CLIENT_HELLO = bytes.fromhex("16030100200100001c0303" + "00" * 32 + "0000000200130100")


def _tds_packet(pkt_type: int, payload: bytes, *, status: int = 1) -> bytes:
    header = struct.pack(">BBHHBB", pkt_type, status, len(payload) + 8, 0, 0, 0)
    return header + payload


def _tds_prelogin_probe() -> bytes:
    return _tds_packet(0x12, MSSQL_NMAP_PRELOGIN_PAYLOAD)


def _tds_client_prelogin() -> bytes:
    data = (
        b"\x0f\x00\x07\xd0\x00\x00"  # version
        b"\x01"  # encrypt ON (client asks)
        b"\x00"  # instance
        b"\x00\x00\x00\x00"  # thread id
        b"\x00"  # mars
    )
    options = (
        b"\x00\x00\x15\x00\x06"
        b"\x01\x00\x1b\x00\x01"
        b"\x02\x00\x1c\x00\x01"
        b"\x03\x00\x1d\x00\x04"
        b"\x04\x00\x21\x00\x01"
        b"\xff" + data
    )
    return _tds_packet(0x12, options)


def _minimal_login7(username: str) -> bytes:
    host = "WORKSTATION"
    app = "hpaudit"
    server = "MSSQL"
    client = "hpaudit"
    host_b = host.encode("utf-16le")
    user_b = username.encode("utf-16le")
    app_b = app.encode("utf-16le")
    server_b = server.encode("utf-16le")
    client_b = client.encode("utf-16le")
    var = host_b + user_b + app_b + server_b + client_b
    fixed = 94
    off = fixed
    ib_host, cch_host = off, len(host)
    off += len(host_b)
    ib_user, cch_user = off, len(username)
    off += len(user_b)
    ib_pass, cch_pass = off, 0
    off += 0
    ib_app, cch_app = off, len(app)
    off += len(app_b)
    ib_server, cch_server = off, len(server)
    off += len(server_b)
    ib_ext, cb_ext = off, 0
    off += 0
    ib_client, cch_client = off, len(client)
    off += len(client_b)
    ib_lang, cch_lang = off, 0
    ib_db, cch_db = off, 0
    ib_sspi, cb_sspi = off, 0
    ib_attach, cch_attach = off, 0
    ib_change, cch_change = off, 0
    body = struct.pack(
        "<IIIIII4BlI18H6s6HI",
        fixed + len(var),
        0x71000001,
        4096,
        0,
        1234,
        0,
        0xE0,
        0x03,
        0x00,
        0x00,
        0,
        0x00090409,
        ib_host,
        cch_host,
        ib_user,
        cch_user,
        ib_pass,
        cch_pass,
        ib_app,
        cch_app,
        ib_server,
        cch_server,
        ib_ext,
        cb_ext,
        ib_client,
        cch_client,
        ib_lang,
        cch_lang,
        ib_db,
        cch_db,
        b"\x00" * 6,
        ib_sspi,
        cb_sspi,
        ib_attach,
        cch_attach,
        ib_change,
        cch_change,
        0,
    )
    return _tds_packet(0x10, body + var)


def probe_mssql(host: str, port: int) -> list[Indicator]:
    raw, err = tcp_transact(host, port, _tds_prelogin_probe())
    if err and not raw:
        return skip_suite(_MSSQL_SKIP, closed_reason(err), protocol="mssql", error=err)
    if not raw or raw[0] != 0x04:
        return skip_suite(_MSSQL_SKIP, "not a TDS speaker", protocol="mssql")
    nmap_hit = match_mssql_canned_prelogin(raw)

    pre_replies, pre_err = tcp_roundtrips(host, port, [_tds_client_prelogin()], recv_first=False)
    prelogin_reply = pre_replies[0] if pre_replies else b""
    prelogin_hit = match_mssql_prelogin_encrypt(prelogin_reply)

    user, _ = random_creds()
    login_replies, login_err = tcp_roundtrips(
        host,
        port,
        [_tds_client_prelogin(), _minimal_login7(user)],
        recv_first=False,
    )
    login_reply = login_replies[1] if len(login_replies) > 1 else b""
    login_hit = match_mssql_login7_canned(login_reply)

    tls_replies, tls_err = tcp_roundtrips(
        host,
        port,
        [_tds_client_prelogin(), _TLS_CLIENT_HELLO],
        recv_first=False,
    )
    tls_pre = tls_replies[0] if tls_replies else b""
    tls_follow = tls_replies[1] if len(tls_replies) > 1 else b""
    tls_not_sup = bool(match_mssql_prelogin_encrypt(tls_pre))
    tls_dropped = tls_not_sup and not tls_follow
    if tls_dropped:
        tls_detail = "ENCRYPT_NOT_SUP then TLS ClientHello closed the session"
    elif not tls_pre and tls_err:
        tls_detail = closed_reason(tls_err)
    elif not tls_not_sup:
        tls_detail = "PRELOGIN did not advertise ENCRYPT_NOT_SUP before TLS probe"
    else:
        tls_detail = f"TLS follow-up {len(tls_follow)} bytes after ENCRYPT_NOT_SUP"

    return [
        Indicator(
            id="mssql.signature",
            title="MSSQL prelogin is a canned nmap-shaped template",
            category="static_signature",
            triggered=bool(nmap_hit),
            protocol="mssql",
            detail=nmap_hit or f"{len(raw)} byte TDS response",
            evidence=raw[:80].hex(),
        ),
        Indicator(
            id="mssql.prelogin",
            title="MSSQL PRELOGIN advertises encryption NOT SUP",
            category="static_signature",
            triggered=bool(prelogin_hit),
            skipped=not prelogin_reply and bool(pre_err),
            skip_reason=closed_reason(pre_err) if pre_err and not prelogin_reply else "",
            protocol="mssql",
            detail=prelogin_hit or "PRELOGIN encryption negotiation looks normal",
            evidence=prelogin_reply[:80].hex() if prelogin_reply else "",
        ),
        Indicator(
            id="mssql.login7",
            title="MSSQL LOGIN7 gets a canned 18456 failure",
            category="state_nonpersist",
            triggered=bool(login_hit),
            skipped=not login_reply and bool(login_err),
            skip_reason=closed_reason(login_err) if login_err and not login_reply else "",
            protocol="mssql",
            detail=login_hit or "LOGIN7 did not return a canned 18456 failure",
            evidence=login_reply[:120].hex() if login_reply else "",
        ),
        Indicator(
            id="mssql.tls_drop",
            title="MSSQL closes on TLS after advertising ENCRYPT_NOT_SUP",
            category="state_nonpersist",
            triggered=tls_dropped,
            skipped=not tls_pre and bool(tls_err),
            skip_reason=closed_reason(tls_err) if not tls_pre and tls_err else "",
            protocol="mssql",
            detail=tls_detail,
            evidence=(tls_follow[:40].hex() if tls_follow else tls_err or "empty"),
        ),
    ]
