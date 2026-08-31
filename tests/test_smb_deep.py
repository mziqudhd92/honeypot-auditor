"""Deep SMB probe tests."""

from __future__ import annotations

from unittest.mock import patch

from honeypot_auditor.probes.deep.smb import probe_smb_negotiate, probe_smb_target_mismatch


@patch("honeypot_auditor.probes.deep.smb.optional_impacket", return_value=(None, None))
def test_deep_smb_skipped_without_impacket(_imp):
    assert probe_smb_negotiate("127.0.0.1", 445)[0].skipped
    assert probe_smb_target_mismatch("127.0.0.1", 445)[0].skipped


@patch(
    "honeypot_auditor.probes.deep.smb.smb_negotiate_facts",
    return_value={"dialect": 0x0202, "supports_encryption": False},
)
@patch("honeypot_auditor.probes.deep.smb.optional_impacket", return_value=(object(), object()))
def test_deep_smb_negotiate_legacy_dialect(_imp, _facts):
    ind = probe_smb_negotiate("127.0.0.1", 445)[0]
    assert ind.triggered
    assert "legacy dialect" in ind.detail


@patch(
    "honeypot_auditor.probes.deep.smb.capture_ntlm_challenge",
    return_value={"native_os": "Windows 10 Build 19041", "av_pairs": object()},
)
@patch(
    "honeypot_auditor.probes.deep.smb.match_smb_target_info_mismatch",
    return_value="native_os 'Windows 10' vs NTLM name 'SAMBA'",
)
@patch("honeypot_auditor.probes.deep.smb.optional_impacket", return_value=(object(), object()))
def test_deep_smb_target_mismatch(_imp, _match, _capture):
    ind = probe_smb_target_mismatch("127.0.0.1", 445)[0]
    assert ind.triggered
    assert "SAMBA" in ind.detail
