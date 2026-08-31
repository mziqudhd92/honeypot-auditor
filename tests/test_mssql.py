"""MSSQL probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.mssql as mssql
from honeypot_auditor.config import MSSQL_CANNED_PRELOGIN

_PRELOGIN_ENCRYPT = (
    b"\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01"
    b"\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0c\x00\x10\x04\x00\x00\x02"
)
_LOGIN7_FAIL = (
    b"\x04\x01\x00\x40\x00\x36\x01\x00"
    + "Login failed for user test.".encode("utf-16le")
    + b"\xfd\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)


@patch.object(mssql, "tcp_roundtrips")
@patch.object(mssql, "tcp_transact")
def test_mssql_canned_prelogin_and_login7(mock_tcp, mock_rt):
    mock_tcp.return_value = (MSSQL_CANNED_PRELOGIN[1], "")
    mock_rt.side_effect = [
        ([_PRELOGIN_ENCRYPT], ""),
        ([_PRELOGIN_ENCRYPT, _LOGIN7_FAIL], ""),
        ([_PRELOGIN_ENCRYPT, b""], ""),
    ]
    inds = mssql.probe_mssql("127.0.0.1", 1433)
    by_id = {i.id: i for i in inds}
    assert by_id["mssql.signature"].triggered
    assert by_id["mssql.prelogin"].triggered
    assert by_id["mssql.login7"].triggered
    assert by_id["mssql.tls_drop"].triggered


@patch.object(mssql, "tcp_roundtrips")
@patch.object(mssql, "tcp_transact")
def test_mssql_other_tds_clean(mock_tcp, mock_rt):
    mock_tcp.return_value = (b"\x04\x01\x00\x20\x00\x00\x01\x00" + b"\x00" * 24, "")
    mock_rt.side_effect = [
        ([b"\x04\x01\x00\x20\x00\x00\x01\x00" + b"\x00" * 24], ""),
        ([b"\x04\x01\x00\x20\x00\x00\x01\x00" + b"\x00" * 24, b"\x04\x01\x00\x10"], ""),
        ([b"\x04\x01\x00\x20\x00\x00\x01\x00" + b"\x00" * 24, b"\x16\x03"], ""),
    ]
    inds = mssql.probe_mssql("127.0.0.1", 1433)
    by_id = {i.id: i for i in inds}
    assert not by_id["mssql.signature"].triggered
    assert not by_id["mssql.prelogin"].triggered
    assert not by_id["mssql.login7"].triggered
    assert not by_id["mssql.tls_drop"].triggered


@patch.object(mssql, "tcp_transact")
def test_mssql_closed_port(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = mssql.probe_mssql("127.0.0.1", 1433)
    assert len(inds) == 4
    assert all(i.skipped for i in inds)


@patch.object(mssql, "tcp_roundtrips")
@patch.object(mssql, "tcp_transact")
def test_mssql_trapster_shaped_prelogin_encrypt(mock_tcp, mock_rt):
    trapster_pre = bytes.fromhex(
        "0401002500000100000015000601001b000102001c000103001d0000ff0f00000000000200"
    )
    mock_tcp.return_value = (trapster_pre, "")
    mock_rt.side_effect = [
        ([trapster_pre], ""),
        ([trapster_pre, _LOGIN7_FAIL], ""),
        ([trapster_pre, b""], ""),
    ]
    inds = mssql.probe_mssql("127.0.0.1", 1433)
    by_id = {i.id: i for i in inds}
    assert by_id["mssql.prelogin"].triggered
    assert by_id["mssql.tls_drop"].triggered
