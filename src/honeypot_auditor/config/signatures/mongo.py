from __future__ import annotations

import struct


def match_mongo_stock_hello(raw: bytes) -> str | None:
    """hello/isMaster looks like mongod but connectionId is hardcoded to 1."""
    data = raw or b""
    looks_like_hello = (
        b"ismaster" in data or b"maxWireVersion" in data or b"maxBsonObjectSize" in data
    )
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
    """Synthetic OP_MSG reply header (hardcoded requestId 9999).

    Opcode 2013 is the normal MongoDB wire protocol since 3.6 — never score it.
    """
    data = raw or b""
    if len(data) < 16:
        return None
    _length, request_id, _response_to, _opcode = struct.unpack("<IIII", data[:16])
    if request_id == 9999:
        return "synthetic reply requestId 9999"
    return None


def match_mongo_response_to(raw: bytes, request_id: int) -> str | None:
    """Wire reply responseTo does not echo the client's requestId.

    Only scores OP_REPLY (1) / OP_MSG (2013) frames — garbage ≥16-byte payloads
    are not Mongo speakers and must stay clean.
    """
    data = raw or b""
    if len(data) < 16:
        return None
    _length, _rid, response_to, opcode = struct.unpack("<IIII", data[:16])
    if opcode not in (1, 2013):
        return None
    if response_to == request_id:
        return None
    return f"responseTo={response_to} does not echo requestId={request_id}"


def match_mongo_hello_clone(raw_a: bytes, raw_b: bytes) -> str | None:
    """Two independent hello replies are bitwise-identical (frozen localTime/cid)."""
    a, b = raw_a or b"", raw_b or b""
    if len(a) < 16 or len(b) < 16 or a != b:
        return None
    looks = (
        b"ismaster" in a
        or b"maxWireVersion" in a
        or b"maxBsonObjectSize" in a
        or b"helloOk" in a
    )
    if not looks:
        return None
    return "hello replies bitwise-identical across reconnects"
