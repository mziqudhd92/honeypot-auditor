"""SMB probe tests with mocks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import honeypot_auditor.probes.smb as smb
from honeypot_auditor.config import STATUS_OBJECT_NAME_NOT_FOUND


def test_smb_skipped_without_impacket():
    with patch.object(smb, "optional_impacket", return_value=(None, None)):
        inds = smb.probe_smb("127.0.0.1", 445)
    assert len(inds) == 3
    assert all(i.skipped for i in inds)


@patch.object(smb, "probe_bogus_pipe", return_value=(STATUS_OBJECT_NAME_NOT_FOUND, "ok", False))
@patch.object(smb, "collect_ntlm_challenges", return_value=[b"\x11" * 8, b"\x22" * 8])
@patch.object(
    smb,
    "smb_connection_summary",
    return_value={"dialect": "SMB 1", "native_os": "Windows 5.1", "shares": ["PUBLIC"]},
)
@patch.object(smb, "optional_impacket", return_value=(MagicMock(), MagicMock()))
def test_smb_emulator_native_os(_imp, _summary, _challenges, _pipe):
    inds = smb.probe_smb("127.0.0.1", 445)
    by_id = {i.id: i for i in inds}
    assert by_id["smb.dialect"].triggered
    assert not by_id["smb.ntlm_challenge"].triggered
    assert not by_id["smb.bogus_pipe"].triggered


@patch.object(smb, "probe_bogus_pipe", return_value=(0xC0000001, "NTSTATUS 0xC0000001", False))
@patch.object(smb, "collect_ntlm_challenges", return_value=[b"\xaa" * 8, b"\xaa" * 8])
@patch.object(
    smb,
    "smb_connection_summary",
    return_value={"dialect": "0x0311", "native_os": "Windows 10", "shares": []},
)
@patch.object(smb, "optional_impacket", return_value=(MagicMock(), MagicMock()))
def test_smb_static_challenge_and_bad_pipe(_imp, _summary, _challenges, _pipe):
    inds = smb.probe_smb("127.0.0.1", 445)
    by_id = {i.id: i for i in inds}
    assert not by_id["smb.dialect"].triggered
    assert by_id["smb.ntlm_challenge"].triggered
    assert by_id["smb.bogus_pipe"].triggered


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
