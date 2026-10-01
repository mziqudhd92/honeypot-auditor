from __future__ import annotations

from honeypot_auditor.config.tells.mysql import (
    MYSQL_EOL_RE,
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
    """Wrong auth sequence id — emulator 'Expected seq' FSM (not real ER 1156).

    Real mysqld returns ER 1156 / "Got packets out of order" for a bad seq_id.
    Low-interaction faces often invent ``Expected seq(N) got seq(M)`` instead.
    """
    payload = raw[4:] if len(raw) > 4 else raw
    if not payload.startswith(b"\xff"):
        return None
    # Newer low-interaction MySQL lures (e.g. 8.0.x faces) use a custom seq FSM string
    # instead of stock ER 1156 — that string is the tell, not ER 1156 itself.
    low = raw.lower()
    if b"expected seq(" in low and b"got seq(" in low:
        msg = raw.split(b"\xff", 1)[-1][2:].decode("utf-8", "replace").strip()
        return f"emulator seq FSM on wrong auth sequence ({msg[:80]})"
    return None


def extract_mysql_scramble(raw: bytes) -> bytes:
    """Extract auth plugin data (scramble) from a Protocol::HandshakeV10 greeting."""
    data = raw or b""
    if len(data) < 5:
        return b""
    payload = data[4:] if len(data) > 4 else data
    if not payload.startswith(b"\x0a"):
        idx = data.find(b"\x0a")
        if idx < 0:
            return b""
        payload = data[idx:]
    # skip protocol + version\0
    end = payload.find(b"\x00", 1)
    if end < 0 or end + 1 + 4 + 8 > len(payload):
        return b""
    # connection_id (4) + auth_plugin_data_part_1 (8) + filler (1)
    part1 = payload[end + 1 + 4 : end + 1 + 4 + 8]
    rest = payload[end + 1 + 4 + 8 + 1 :]
    if len(rest) < 2 + 1 + 2 + 13:
        return part1
    # capability_low(2) charset(1) status(2) capability_high(2) auth_plugin_data_len(1)
    # reserved(10) then auth_plugin_data_part_2 (len-8 bytes, usually 12 + NUL)
    if len(rest) < 2 + 1 + 2 + 2 + 1 + 10:
        return part1
    plugin_len = rest[7]
    part2_start = 8 + 10
    if plugin_len <= 8 or part2_start >= len(rest):
        return part1
    part2_len = max(0, plugin_len - 8)
    part2 = rest[part2_start : part2_start + part2_len].rstrip(b"\x00")
    return part1 + part2


def match_mysql_scramble_frozen(scramble_a: bytes, scramble_b: bytes) -> str | None:
    """Auth scramble salt identical across independent greetings."""
    a, b = scramble_a or b"", scramble_b or b""
    if len(a) < 8 or len(b) < 8:
        return None
    if a != b:
        return None
    return "handshake scramble frozen across reconnects"


def match_mysql_auth_error_clone(raw_a: bytes, raw_b: bytes, user_a: str, user_b: str) -> str | None:
    """Two access-denied packets for distinct users are bitwise-identical.

    Real mysqld embeds ``user@host`` in the 1045 message. Identical fixed
    "Access denied for user …" templates score; generic identical ERR packets
    with no user-attributed wording are too weak alone.
    """
    a, b = raw_a or b"", raw_b or b""
    if not a or not b or a != b:
        return None
    pa = a[4:] if len(a) > 4 else a
    pb = b[4:] if len(b) > 4 else b
    if not (pa.startswith(b"\xff") and pb.startswith(b"\xff")):
        return None
    if not user_a or not user_b or user_a == user_b:
        return None
    # Real mysqld embeds user@host in the 1045 message.
    ua, ub = user_a.encode("ascii", "replace"), user_b.encode("ascii", "replace")
    if ua in a or ub in a:
        return "access-denied packets bitwise-identical across distinct users"
    low = a.lower()
    if b"access denied for user" in low or b"for user '" in low or b'for user "' in low:
        return "access-denied packets bitwise-identical (fixed user embedding)"
    return None
