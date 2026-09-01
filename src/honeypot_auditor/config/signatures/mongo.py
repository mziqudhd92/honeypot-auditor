from __future__ import annotations

import struct


def match_mongo_stock_hello(raw: bytes) -> str | None:
    """hello/isMaster looks like mongod but connectionId is hardcoded to 1."""
    data = raw or b""
    looks_like_hello = b"ismaster" in data or b"maxWireVersion" in data or b"maxBsonObjectSize" in data
    if looks_like_hello and b"\x10connectionId\x00\x01\x00\x00\x00" in data:
        return "hello connectionId frozen at 1"
    if b"4.4.6" in data:
        return "frozen hello version 4.4.6"
    return None


def match_mongo_ping_unauthorized(text: str) -> str | None:
    """Ping/other commands return unauthorized while hello still works."""
    low = (text or "").lower()
    if "authentication required" in low or "not authorized" in low:
        return "non-hello command unauthorized after hello"
    return None


def match_mongo_op_msg_reply(raw: bytes) -> str | None:
    """OP_MSG hello reply uses opcode 2013 or a synthetic outbound requestId."""
    data = raw or b""
    if len(data) < 16:
        return None
    _length, request_id, _response_to, opcode = struct.unpack("<IIII", data[:16])
    hits: list[str] = []
    if opcode == 2013:
        hits.append("OP_MSG opcode 2013 reply")
    if request_id == 9999:
        hits.append("synthetic reply requestId 9999")
    return "; ".join(hits) if hits else None
