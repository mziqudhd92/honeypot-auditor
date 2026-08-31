"""MongoDB probe tests with mocks."""

from __future__ import annotations

import struct
from unittest.mock import patch

import honeypot_auditor.probes.mongodb as mongodb

_HELLO = (
    b"\x00" * 16
    + b"ismaster\x00"
    + b"maxWireVersion\x00"
    + b"version\x00\x06\x00\x00\x004.4.6\x00"
)
_PING_DENIED = b"\x00" * 16 + b"Authentication required"
_PING_OK = b"\x00" * 16 + b"ok"
_OP_MSG_REPLY = (
    struct.pack("<I", 16 + 4 + 4 + len(b"ismaster\x00maxWireVersion\x00"))
    + struct.pack("<III", 9999, 2, 2013)
    + b"ismaster\x00maxWireVersion\x00"
)


@patch.object(mongodb, "tcp_transact")
def test_mongodb_frozen_hello(mock_tcp):
    mock_tcp.side_effect = [(_HELLO, ""), (_OP_MSG_REPLY, ""), (_PING_OK, "")]
    inds = mongodb.probe_mongodb("127.0.0.1", 27017)
    by_id = {i.id: i for i in inds}
    assert by_id["mongodb.signature"].triggered
    assert "4.4.6" in by_id["mongodb.signature"].detail
    assert by_id["mongodb.op_msg"].triggered
    assert not by_id["mongodb.persist"].triggered


_HELLO_CID = (
    b"\x00" * 16
    + b"ismaster\x00"
    + b"maxWireVersion\x00"
    + b"\x10connectionId\x00\x01\x00\x00\x00"
    + b"version\x00\x06\x00\x00\x006.0.8\x00"
)


@patch.object(mongodb, "tcp_transact")
def test_mongodb_connection_id_frozen(mock_tcp):
    mock_tcp.side_effect = [(_HELLO_CID, ""), (_OP_MSG_REPLY, ""), (_PING_DENIED, "")]
    inds = mongodb.probe_mongodb("127.0.0.1", 27017)
    by_id = {i.id: i for i in inds}
    assert by_id["mongodb.signature"].triggered
    assert "connectionId" in by_id["mongodb.signature"].detail
    assert by_id["mongodb.persist"].triggered


@patch.object(mongodb, "tcp_transact")
def test_mongodb_ping_unauthorized_after_hello(mock_tcp):
    hello = b"\x00" * 16 + b"ismaster\x00maxWireVersion\x00version\x007.0.14\x00"
    mock_tcp.side_effect = [(hello, ""), (b"", ""), (_PING_DENIED, "")]
    inds = mongodb.probe_mongodb("127.0.0.1", 27017)
    by_id = {i.id: i for i in inds}
    assert not by_id["mongodb.signature"].triggered
    assert by_id["mongodb.persist"].triggered
    assert "unauthorized" in by_id["mongodb.persist"].detail.lower()


@patch.object(mongodb, "tcp_transact")
def test_mongodb_closed_port(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = mongodb.probe_mongodb("127.0.0.1", 27017)
    assert len(inds) == 3
    assert all(i.skipped for i in inds)
