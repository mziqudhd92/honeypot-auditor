"""MongoDB probe tests with mocks."""

from __future__ import annotations

import struct
from unittest.mock import patch

import honeypot_auditor.probes.mongodb as mongodb
from honeypot_auditor.config.signatures.mongo import (
    match_mongo_hello_clone,
    match_mongo_response_to,
)

_HELLO = (
    b"\x00" * 16 + b"ismaster\x00" + b"maxWireVersion\x00" + b"version\x00\x06\x00\x00\x004.4.6\x00"
)
_PING_DENIED = b"\x00" * 16 + b"Authentication required"
_PING_OK = b"\x00" * 16 + b"ok"
_OP_MSG_REPLY = (
    struct.pack("<I", 16 + 4 + 4 + len(b"ismaster\x00maxWireVersion\x00"))
    + struct.pack("<III", 9999, 2, 2013)
    + b"ismaster\x00maxWireVersion\x00"
)
_OP_MSG_BAD_RESPONSE_TO = (
    struct.pack("<I", 32)
    + struct.pack("<III", 7, 99, 2013)  # responseTo=99 ≠ requestId=2
    + b"\x00" * 16
)


@patch.object(mongodb, "tcp_transact")
def test_mongodb_frozen_hello(mock_tcp):
    # hello, hello2, op_msg, ping
    mock_tcp.side_effect = [
        (_HELLO, ""),
        (_HELLO + b"\x01", ""),
        (_OP_MSG_REPLY, ""),
        (_PING_OK, ""),
    ]
    inds = mongodb.probe_mongodb("127.0.0.1", 27017)
    by_id = {i.id: i for i in inds}
    assert by_id["mongodb.signature"].triggered
    assert "4.4.6" in by_id["mongodb.signature"].detail
    assert by_id["mongodb.op_msg"].triggered
    assert not by_id["mongodb.persist"].triggered
    assert not by_id["mongodb.hello_clone"].triggered


_HELLO_CID = (
    b"\x00" * 16
    + b"ismaster\x00"
    + b"maxWireVersion\x00"
    + b"\x10connectionId\x00\x01\x00\x00\x00"
    + b"version\x00\x06\x00\x00\x006.0.8\x00"
)


@patch.object(mongodb, "tcp_transact")
def test_mongodb_connection_id_frozen(mock_tcp):
    mock_tcp.side_effect = [
        (_HELLO_CID, ""),
        (_HELLO_CID, ""),
        (_OP_MSG_REPLY, ""),
        (_PING_DENIED, ""),
    ]
    inds = mongodb.probe_mongodb("127.0.0.1", 27017)
    by_id = {i.id: i for i in inds}
    assert by_id["mongodb.signature"].triggered
    assert "connectionId" in by_id["mongodb.signature"].detail
    assert by_id["mongodb.persist"].triggered
    assert by_id["mongodb.hello_clone"].triggered


@patch.object(mongodb, "tcp_transact")
def test_mongodb_ping_unauthorized_after_hello(mock_tcp):
    hello = b"\x00" * 16 + b"ismaster\x00maxWireVersion\x00version\x007.0.14\x00"
    mock_tcp.side_effect = [
        (hello, ""),
        (hello + b"x", ""),
        (b"", ""),
        (_PING_DENIED, ""),
    ]
    inds = mongodb.probe_mongodb("127.0.0.1", 27017)
    by_id = {i.id: i for i in inds}
    assert not by_id["mongodb.signature"].triggered
    assert by_id["mongodb.persist"].triggered
    assert "unauthorized" in by_id["mongodb.persist"].detail.lower()


@patch.object(mongodb, "tcp_transact")
def test_mongodb_response_to_mismatch(mock_tcp):
    hello = b"\x00" * 16 + b"ismaster\x00maxWireVersion\x00"
    mock_tcp.side_effect = [
        (hello, ""),
        (hello + b"y", ""),
        (_OP_MSG_BAD_RESPONSE_TO, ""),
        (_PING_OK, ""),
    ]
    inds = mongodb.probe_mongodb("127.0.0.1", 27017)
    by_id = {i.id: i for i in inds}
    assert by_id["mongodb.response_to"].triggered


@patch.object(mongodb, "tcp_transact")
def test_mongodb_closed_port(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = mongodb.probe_mongodb("127.0.0.1", 27017)
    assert len(inds) == 5
    assert all(i.skipped for i in inds)


def test_mongo_matchers():
    assert match_mongo_response_to(_OP_MSG_BAD_RESPONSE_TO, 2)
    good = struct.pack("<IIII", 16, 1, 2, 2013)
    assert match_mongo_response_to(good, 2) is None
    assert match_mongo_hello_clone(_HELLO_CID, _HELLO_CID)
    assert match_mongo_hello_clone(_HELLO_CID, _HELLO_CID + b"x") is None


def test_mongo_response_to_ignores_non_mongo_opcode():
    garbage = struct.pack("<IIII", 32, 1, 99, 0) + b"\x00" * 16  # opcode 0
    assert match_mongo_response_to(garbage, 1) is None
