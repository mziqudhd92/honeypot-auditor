"""MSSQL probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.mssql as mssql
from honeypot_auditor.config import MSSQL_CANNED_PRELOGIN
from honeypot_auditor.config.signatures.mssql import (
    match_mssql_login7_clone,
    match_mssql_prelogin_blind,
)

_PRELOGIN_ENCRYPT = (
    b"\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01"
    b"\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff\x0c\x00\x10\x04\x00\x00\x02"
)
_LOGIN7_FAIL = (
    b"\x04\x01\x00\x40\x00\x36\x01\x00"
    + "Login failed for user test.".encode("utf-16le")
    + b"\xfd\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)


def _rt_side_effect_honeypot():
    # prelogin ON, prelogin OFF, login1, login2, tls
    return [
        ([_PRELOGIN_ENCRYPT], ""),
        ([_PRELOGIN_ENCRYPT], ""),
        ([_PRELOGIN_ENCRYPT, _LOGIN7_FAIL], ""),
        ([_PRELOGIN_ENCRYPT, _LOGIN7_FAIL], ""),
        ([_PRELOGIN_ENCRYPT, b""], ""),
    ]


@patch.object(mssql, "tcp_roundtrips")
@patch.object(mssql, "tcp_transact")
def test_mssql_canned_prelogin_and_login7(mock_tcp, mock_rt):
    mock_tcp.return_value = (MSSQL_CANNED_PRELOGIN[1], "")
    mock_rt.side_effect = _rt_side_effect_honeypot()
    inds = mssql.probe_mssql("127.0.0.1", 1433)
    by_id = {i.id: i for i in inds}
    assert by_id["mssql.signature"].triggered
    assert by_id["mssql.prelogin"].triggered
    assert by_id["mssql.prelogin_blind"].triggered
    assert by_id["mssql.login7"].triggered
    assert by_id["mssql.login7_clone"].triggered
    assert by_id["mssql.tls_drop"].triggered


@patch.object(mssql, "tcp_roundtrips")
@patch.object(mssql, "tcp_transact")
def test_mssql_other_tds_clean(mock_tcp, mock_rt):
    clean = b"\x04\x01\x00\x20\x00\x00\x01\x00" + b"\x00" * 24
    clean_b = b"\x04\x01\x00\x21\x00\x00\x01\x00" + b"\x01" * 24
    mock_tcp.return_value = (clean, "")
    mock_rt.side_effect = [
        ([clean], ""),
        ([clean_b], ""),
        ([clean, b"\x04\x01\x00\x10"], ""),
        ([clean, b"\x04\x01\x00\x11"], ""),
        ([clean, b"\x16\x03"], ""),
    ]
    inds = mssql.probe_mssql("127.0.0.1", 1433)
    by_id = {i.id: i for i in inds}
    assert not by_id["mssql.signature"].triggered
    assert not by_id["mssql.prelogin"].triggered
    assert not by_id["mssql.prelogin_blind"].triggered
    assert not by_id["mssql.login7"].triggered
    assert not by_id["mssql.login7_clone"].triggered
    assert not by_id["mssql.tls_drop"].triggered


@patch.object(mssql, "tcp_transact")
def test_mssql_closed_port(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = mssql.probe_mssql("127.0.0.1", 1433)
    assert len(inds) == 6
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
        ([trapster_pre], ""),
        ([trapster_pre, _LOGIN7_FAIL], ""),
        ([trapster_pre, _LOGIN7_FAIL], ""),
        ([trapster_pre, b""], ""),
    ]
    inds = mssql.probe_mssql("127.0.0.1", 1433)
    by_id = {i.id: i for i in inds}
    assert by_id["mssql.prelogin"].triggered
    assert by_id["mssql.tls_drop"].triggered
    # ENCRYPT_NOT_SUP + identical PRELOGIN without nmap/canned shape must not
    # enable prelogin_blind (honest SQL often mirrors that pattern).
    assert not by_id["mssql.signature"].triggered
    assert not by_id["mssql.prelogin_blind"].triggered


@patch.object(mssql, "tcp_roundtrips")
@patch.object(mssql, "tcp_transact")
def test_mssql_encrypt_not_sup_identical_prelogin_not_blind_without_canned(mock_tcp, mock_rt):
    """Honest NOT_SUP + identical option replies must not fire prelogin_blind."""
    mock_tcp.return_value = (_PRELOGIN_ENCRYPT, "")  # NOT_SUP but not nmap canned list
    mock_rt.side_effect = [
        ([_PRELOGIN_ENCRYPT], ""),
        ([_PRELOGIN_ENCRYPT], ""),
        ([_PRELOGIN_ENCRYPT, b"\x04\x01\x00\x10"], ""),
        ([_PRELOGIN_ENCRYPT, b"\x04\x01\x00\x11"], ""),
        ([_PRELOGIN_ENCRYPT, b"\x16\x03"], ""),
    ]
    # Ensure canned matcher does not treat this as nmap lure.
    from honeypot_auditor.config.signatures.mssql import match_mssql_canned_prelogin

    assert match_mssql_canned_prelogin(_PRELOGIN_ENCRYPT) is None
    inds = mssql.probe_mssql("127.0.0.1", 1433)
    by_id = {i.id: i for i in inds}
    assert by_id["mssql.prelogin"].triggered
    assert not by_id["mssql.prelogin_blind"].triggered


def test_mssql_login7_clone_matcher():
    assert match_mssql_login7_clone(_LOGIN7_FAIL, _LOGIN7_FAIL, "alice", "bob")
    distinct = _LOGIN7_FAIL + b"\x00"
    assert match_mssql_login7_clone(_LOGIN7_FAIL, distinct, "alice", "bob") is None
    # Generic identical failure without user-attributed wording is too weak.
    generic = (
        b"\x04\x01\x00\x20\x00\x36\x01\x00"
        + "Login failed.".encode("utf-16le")
        + b"\xfd\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    assert match_mssql_login7_clone(generic, generic, "alice", "bob") is None


def test_mssql_prelogin_blind_matcher():
    assert match_mssql_prelogin_blind(_PRELOGIN_ENCRYPT, _PRELOGIN_ENCRYPT, canned_hint=True)
    assert match_mssql_prelogin_blind(_PRELOGIN_ENCRYPT, _PRELOGIN_ENCRYPT, canned_hint=False) is None
    other = _PRELOGIN_ENCRYPT[:-1] + b"\x01"
    assert match_mssql_prelogin_blind(_PRELOGIN_ENCRYPT, other) is None
