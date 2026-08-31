"""MongoDB fingerprint engine.

Strategies: static signature (hello connectionId frozen at 1, OP_MSG synthetic reply) ·
state non-persistence (ping unauthorized after hello). Arbitrary auth is not on the
basic path (deny-all auth is also a real --auth instance).
"""

from __future__ import annotations

import struct

from honeypot_auditor.config import (
    match_mongo_op_msg_reply,
    match_mongo_ping_unauthorized,
    match_mongo_stock_hello,
)
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import skip_suite

_MONGO_SKIP = (
    ("mongodb.signature", "MongoDB hello connectionId is frozen at 1", "static_signature"),
    ("mongodb.op_msg", "MongoDB OP_MSG hello uses a synthetic reply header", "static_signature"),
    ("mongodb.persist", "MongoDB ping is unauthorized after hello", "state_nonpersist"),
)

_OP_QUERY = 2004
_OP_MSG = 2013


def _bson_int32(key: str, value: int) -> bytes:
    return b"\x10" + key.encode("ascii") + b"\x00" + struct.pack("<i", value)


def _bson_doc(*elements: bytes) -> bytes:
    body = b"".join(elements) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _op_query(collection: str, query: bytes) -> bytes:
    payload = (
        struct.pack("<i", 0)
        + collection.encode("ascii")
        + b"\x00"
        + struct.pack("<i", 0)
        + struct.pack("<i", -1)
        + query
    )
    header = struct.pack("<iiii", 16 + len(payload), 1, 0, _OP_QUERY)
    return header + payload


def _op_msg_hello(request_id: int = 2) -> bytes:
    doc = _bson_doc(_bson_int32("isMaster", 1))
    payload = struct.pack("<I", 0) + b"\x00" + doc
    header = struct.pack("<iiii", 16 + len(payload), request_id, 0, _OP_MSG)
    return header + payload


def probe_mongodb(host: str, port: int) -> list[Indicator]:
    hello = _op_query("admin.$cmd", _bson_doc(_bson_int32("isMaster", 1)))
    hello_raw, err = tcp_transact(host, port, hello)
    if err and not hello_raw:
        return skip_suite(_MONGO_SKIP, closed_reason(err), protocol="mongodb", error=err)
    if len(hello_raw) < 16:
        return skip_suite(_MONGO_SKIP, "not a MongoDB wire-protocol speaker", protocol="mongodb")
    hello_ok = b"ismaster" in hello_raw or b"maxWireVersion" in hello_raw or b"maxBsonObjectSize" in hello_raw

    op_msg_raw, op_msg_err = tcp_transact(host, port, _op_msg_hello())
    op_msg_hit = match_mongo_op_msg_reply(op_msg_raw) if op_msg_raw else None

    ping = _op_query("admin.$cmd", _bson_doc(_bson_int32("ping", 1)))
    ping_raw, _ = tcp_transact(host, port, ping)
    ping_text = ping_raw.decode("latin-1", "replace")
    ping_hit = match_mongo_ping_unauthorized(ping_text) if hello_ok else None
    frozen = match_mongo_stock_hello(hello_raw)
    return [
        Indicator(
            id="mongodb.signature",
            title="MongoDB hello connectionId is frozen at 1",
            category="static_signature",
            triggered=bool(frozen),
            protocol="mongodb",
            detail=frozen or "hello connectionId is not frozen at 1",
            evidence=hello_raw[:200].hex(),
        ),
        Indicator(
            id="mongodb.op_msg",
            title="MongoDB OP_MSG hello uses a synthetic reply header",
            category="static_signature",
            triggered=bool(op_msg_hit),
            skipped=not op_msg_raw and bool(op_msg_err),
            skip_reason=closed_reason(op_msg_err) if op_msg_err and not op_msg_raw else "",
            protocol="mongodb",
            detail=op_msg_hit or "OP_MSG hello reply looks normal",
            evidence=op_msg_raw[:120].hex() if op_msg_raw else "",
        ),
        Indicator(
            id="mongodb.persist",
            title="MongoDB ping is unauthorized after hello",
            category="state_nonpersist",
            triggered=bool(ping_hit),
            skipped=not hello_ok,
            skip_reason="" if hello_ok else "hello did not look like mongod",
            protocol="mongodb",
            detail=ping_hit or "ping after hello was not unauthorized",
            evidence=ping_text[:200],
        ),
    ]
