"""Config matcher tests for SMB tells."""

from __future__ import annotations

from honeypot_auditor.config import (
    STATUS_OBJECT_NAME_NOT_FOUND,
    match_smb_bogus_pipe,
    match_smb_negotiate_deficit,
    match_smb_static_ntlm_challenge,
)


def test_match_smb_static_ntlm_challenge():
    assert match_smb_static_ntlm_challenge([b"\xaa" * 8, b"\xaa" * 8])
    assert match_smb_static_ntlm_challenge([b"\xaa" * 8, b"\xbb" * 8]) is None


def test_match_smb_bogus_pipe():
    assert match_smb_bogus_pipe(STATUS_OBJECT_NAME_NOT_FOUND, "ok", accepted=False) is None
    assert match_smb_bogus_pipe(None, "bogus pipe hpaudit_x opened", accepted=True)
    assert match_smb_bogus_pipe(0xC0000001, "x", accepted=False)


def test_match_smb_negotiate_deficit():
    assert match_smb_negotiate_deficit({"dialect": 0x0202})
    assert match_smb_negotiate_deficit({"dialect": 0x0311, "supports_encryption": False})
