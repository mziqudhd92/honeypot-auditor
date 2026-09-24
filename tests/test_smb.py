"""SMB probe tests with mocks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import honeypot_auditor.probes.smb as smb
from honeypot_auditor.analyzer import build_report
from honeypot_auditor.config import STATUS_ACCESS_DENIED, STATUS_BAD_NETWORK_NAME, STATUS_OBJECT_NAME_NOT_FOUND
from honeypot_auditor.models import Indicator


def test_smb_skipped_without_impacket():
    with patch.object(smb, "optional_impacket", return_value=(None, None)):
        inds = smb.probe_smb("127.0.0.1", 445)
    assert len(inds) == 7
    assert all(i.skipped for i in inds)
    assert {i.id for i in inds} == {
        "smb.arbitrary_auth",
        "smb.dialect",
        "smb.ntlm_challenge",
        "smb.stock_shares",
        "smb.bogus_pipe",
        "smb.ghost_share",
        "smb.silent_accept",
    }


@patch.object(smb, "probe_arbitrary_logins", return_value=(0, ["low-entropy: rejected"]))
@patch.object(
    smb,
    "probe_pipe_and_ghost_share",
    return_value=(
        (STATUS_OBJECT_NAME_NOT_FOUND, "ok", False),
        (STATUS_BAD_NETWORK_NAME, "ok", False),
    ),
)
@patch.object(smb, "collect_ntlm_challenges", return_value=[b"\x11" * 8, b"\x22" * 8])
@patch.object(
    smb,
    "smb_connection_summary",
    return_value={
        "dialect": "SMB 1",
        "native_os": "Windows 5.1",
        "shares": ["honey", "IPC$"],
    },
)
@patch.object(smb, "optional_impacket", return_value=(MagicMock(), MagicMock()))
def test_smb_emulator_native_os(_imp, _summary, _challenges, _pipe_ghost, _auth):
    inds = smb.probe_smb("127.0.0.1", 445)
    by_id = {i.id: i for i in inds}
    assert by_id["smb.dialect"].triggered
    assert not by_id["smb.ntlm_challenge"].triggered
    assert not by_id["smb.bogus_pipe"].triggered
    assert not by_id["smb.ghost_share"].triggered
    assert by_id["smb.stock_shares"].triggered
    assert not by_id["smb.stock_shares"].requires_corroboration
    assert not by_id["smb.arbitrary_auth"].triggered


@patch.object(
    smb,
    "probe_arbitrary_logins",
    return_value=(2, ["low-entropy: login accepted", "high-entropy: login accepted"]),
)
@patch.object(
    smb,
    "probe_pipe_and_ghost_share",
    return_value=(
        (0xC0000001, "NTSTATUS 0xC0000001", False),
        (None, "ghost share x TREE_CONNECT accepted", True),
    ),
)
@patch.object(smb, "collect_ntlm_challenges", return_value=[b"\xaa" * 8, b"\xaa" * 8])
@patch.object(
    smb,
    "smb_connection_summary",
    return_value={"dialect": "0x0311", "native_os": "Windows 10", "shares": []},
)
@patch.object(smb, "optional_impacket", return_value=(MagicMock(), MagicMock()))
def test_smb_static_challenge_and_bad_pipe(_imp, _summary, _challenges, _pipe_ghost, _auth):
    inds = smb.probe_smb("127.0.0.1", 445)
    by_id = {i.id: i for i in inds}
    assert not by_id["smb.dialect"].triggered
    assert by_id["smb.ntlm_challenge"].triggered
    assert by_id["smb.bogus_pipe"].triggered
    assert by_id["smb.ghost_share"].triggered
    assert by_id["smb.arbitrary_auth"].triggered
    assert by_id["smb.arbitrary_auth"].fidelity == "decisive"


@patch.object(smb, "probe_arbitrary_logins", return_value=(0, ["rejected"]))
@patch.object(
    smb,
    "probe_pipe_and_ghost_share",
    return_value=(
        (STATUS_OBJECT_NAME_NOT_FOUND, "ok", False),
        (STATUS_ACCESS_DENIED, "NTSTATUS 0xC0000022", False),
    ),
)
@patch.object(smb, "collect_ntlm_challenges", return_value=[b"\x11" * 8, b"\x22" * 8])
@patch.object(
    smb,
    "smb_connection_summary",
    return_value={"dialect": "0x0311", "native_os": "Windows 10", "shares": ["C$"]},
)
@patch.object(smb, "optional_impacket", return_value=(MagicMock(), MagicMock()))
def test_smb_ghost_access_denied_is_clean(_imp, _summary, _challenges, _pipe_ghost, _auth):
    inds = smb.probe_smb("127.0.0.1", 445)
    by_id = {i.id: i for i in inds}
    assert not by_id["smb.ghost_share"].triggered
    assert not by_id["smb.stock_shares"].triggered


@patch.object(smb, "tcp_transact", return_value=(b"\x00SMB", ""))
@patch.object(
    smb,
    "smb_connection_summary",
    return_value={"login_error": "unpack requires a buffer of 2 bytes"},
)
@patch.object(smb, "optional_impacket", return_value=(MagicMock(), MagicMock()))
def test_smb_framing_anomaly_on_open_port(_imp, _summary, mock_tcp):
    inds = smb.probe_smb("127.0.0.1", 445)
    by_id = {i.id: i for i in inds}
    assert by_id["smb.dialect"].triggered
    assert "session setup failed" in by_id["smb.dialect"].detail
    assert by_id["smb.ntlm_challenge"].skipped
    assert by_id["smb.bogus_pipe"].skipped
    assert by_id["smb.ghost_share"].skipped
    assert by_id["smb.arbitrary_auth"].skipped
    assert not by_id["smb.silent_accept"].triggered


@patch.object(smb, "_tcp_accepts", return_value=True)
@patch.object(
    smb,
    "smb_connection_summary",
    return_value={"login_error": "The NETBIOS connection with the remote host timed out."},
)
@patch.object(smb, "optional_impacket", return_value=(MagicMock(), MagicMock()))
def test_smb_silent_accept_on_netbios_timeout(_imp, _summary, _tcp):
    inds = smb.probe_smb("127.0.0.1", 445)
    by_id = {i.id: i for i in inds}
    assert by_id["smb.silent_accept"].triggered
    assert len(inds) == 7


def test_smb_generic_stock_shares_alone_suppressed_in_report():
    inds = [
        Indicator(
            id="smb.stock_shares",
            title="SMB share list matches stock honeypot lure names",
            category="static_signature",
            triggered=True,
            protocol="smb",
            detail="stock lure share names: public, tmp",
            requires_corroboration=True,
        )
    ]
    report = build_report(
        target="203.0.113.10",
        resolved_ip="203.0.113.10",
        ports={"smb": [445]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    stock = {ind.id: ind for ind in report.indicators}["smb.stock_shares"]
    assert not stock.triggered
    assert report.score == 0.0
    assert "suppressed: no corroborating tell" in stock.detail
