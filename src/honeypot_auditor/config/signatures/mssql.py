from __future__ import annotations

import struct

from honeypot_auditor.config.tells.mssql import MSSQL_CANNED_PRELOGIN


def match_mssql_canned_prelogin(raw: bytes) -> str | None:
    """TDS prelogin reply is one of the frozen nmap-shaped templates."""
    data = raw or b""
    if not data:
        return None
    for canned in MSSQL_CANNED_PRELOGIN:
        if data.startswith(canned) or data == canned:
            return "canned TDS prelogin (nmap-probe-shaped)"
    if (
        b"\xff\x0b\x00\x0c\x38" in data
        or b"\xff\x0c\x00\x07\xd0" in data
        or b"\xff\x0a\x32\x10\xb4" in data
    ):
        return "canned TDS prelogin (nmap-probe-shaped)"
    return None


def match_mssql_prelogin_encrypt(raw: bytes) -> str | None:
    """Client PRELOGIN gets encryption NOT SUP (0x02) and a frozen version blob."""
    data = raw or b""
    if len(data) > 8 and data[0] == 0x04:
        i = 8
        while i + 5 <= len(data):
            if data[i] == 0xFF:
                break
            token = data[i]
            offset = struct.unpack(">H", data[i + 1 : i + 3])[0]
            length = struct.unpack(">H", data[i + 3 : i + 5])[0]
            i += 5
            if token == 0x01 and length >= 1:
                pos = 8 + offset
                if pos < len(data) and data[pos] == 0x02:
                    return "PRELOGIN encryption NOT SUP (0x02)"
    payload = data[8:] if len(data) > 8 and data[0] == 0x04 else data
    if b"\x0c\x00\x10\x04\x00\x00" in payload and b"\xff" in payload:
        if b"\x02" in payload[payload.find(b"\xff") : payload.find(b"\xff") + 32]:
            return "PRELOGIN encryption NOT SUP with frozen version token"
    return None


def match_mssql_login7_canned(raw: bytes) -> str | None:
    """LOGIN7 gets a canned 18456 failure with a fixed trailing token trailer."""
    data = raw or b""
    if len(data) >= 6 and data[0] == 0x04 and struct.unpack(">H", data[4:6])[0] == 54:
        if b"Login failed" in data or "Login failed".encode("utf-16le") in data:
            return "canned LOGIN7 failure (fixed SPID 54)"
    if b"\xfd\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" in data:
        if b"Login failed" in data or "Login failed".encode("utf-16le") in data:
            return "canned LOGIN7 failure with fixed trailer"
    return None


def _mssql_looks_like_login_fail(raw: bytes) -> bool:
    data = raw or b""
    return bool(data) and (
        b"Login failed" in data or "Login failed".encode("utf-16le") in data or b"\xfd\x02" in data
    )


def match_mssql_login7_clone(raw_a: bytes, raw_b: bytes, user_a: str, user_b: str) -> str | None:
    """Two LOGIN7 failures with distinct usernames return identical TDS payloads.

    Real SQL Server embeds the attempted username in the 18456 error (UTF-16LE).
    """
    a, b = raw_a or b"", raw_b or b""
    if not a or not b or a != b:
        return None
    if not (_mssql_looks_like_login_fail(a) and _mssql_looks_like_login_fail(b)):
        return None
    if not user_a or not user_b or user_a == user_b:
        return None
    ua = user_a.encode("utf-16le")
    ub = user_b.encode("utf-16le")
    if ua in a or ub in a:
        # Identical bytes that somehow embed both users is still impossible; treat as clone.
        return "LOGIN7 failures bitwise-identical across distinct usernames"
    return "LOGIN7 failures bitwise-identical (no per-user error embedding)"


def match_mssql_prelogin_blind(
    raw_a: bytes, raw_b: bytes, *, canned_hint: bool = False
) -> str | None:
    """Distinct PRELOGIN option sets get a bitwise-identical canned reply.

    Real SQL Server often returns the same ENCRYPT_NOT_SUP template for encrypt
    ON vs OFF, so identity alone is not scored unless the reply already looks
    like a canned/nmap lure (``canned_hint``) — callers should also set
    ``requires_corroboration``.
    """
    a, b = raw_a or b"", raw_b or b""
    if len(a) < 8 or len(b) < 8:
        return None
    if a[0] != 0x04 or b[0] != 0x04:
        return None
    if a != b:
        return None
    if not canned_hint:
        return None
    return "PRELOGIN replies identical for distinct option sets (canned template)"
