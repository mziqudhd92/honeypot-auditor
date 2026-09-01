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
