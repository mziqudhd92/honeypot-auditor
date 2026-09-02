from __future__ import annotations

import struct

from honeypot_auditor.config.tells.mysql import (
    MYSQL_EOL_RE,
    MYSQL_PKT_ORDER_CODE,
    MYSQL_STOCK_CAP_BLOCK,
)


def match_mysql_eol_banner(version: str) -> str | None:
    """Frozen MySQL 5.5-on-Ubuntu-14.04 greeting (EOL template, not a live distro)."""
    blob = (version or "").strip()
    if not blob:
        return None
    if MYSQL_EOL_RE.search(blob):
        return f"EOL MySQL greeting {blob}"
    return None


def match_mysql_stock_handshake(raw: bytes) -> str | None:
    """Server greeting uses a frozen capability block and mysql_native_password only."""
    data = raw or b""
    if MYSQL_STOCK_CAP_BLOCK not in data:
        return None
    if b"mysql_native_password" not in data:
        return None
    return "stock handshake capability block + mysql_native_password"


def match_mysql_pkt_order(raw: bytes) -> str | None:
    """Wrong auth sequence id — classic ER 1156 or modern emulator 'Expected seq' FSM."""
    payload = raw[4:] if len(raw) > 4 else raw
    if not payload.startswith(b"\xff"):
        return None
    if len(payload) >= 3 and struct.unpack("<H", payload[1:3])[0] == MYSQL_PKT_ORDER_CODE:
        return "ER 1156 packets out of order on wrong auth sequence"
    if b"packets out of order" in raw:
        return "packets out of order on wrong auth sequence"
    # Newer low-interaction MySQL lures (e.g. 8.0.x faces) use a custom seq FSM string
    # instead of stock ER 1156 — still not how real mysqld answers a wrong seq_id.
    low = raw.lower()
    if b"expected seq(" in low and b"got seq(" in low:
        msg = raw.split(b"\xff", 1)[-1][2:].decode("utf-8", "replace").strip()
        return f"emulator seq FSM on wrong auth sequence ({msg[:80]})"
    return None
