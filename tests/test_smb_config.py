"""Config matcher tests for SMB tells."""

from __future__ import annotations

from honeypot_auditor.config import (
    STATUS_ACCESS_DENIED,
    STATUS_BAD_NETWORK_NAME,
    STATUS_OBJECT_NAME_NOT_FOUND,
    match_smb_bogus_pipe,
    match_smb_ghost_share,
    match_smb_negotiate_deficit,
    match_smb_static_ntlm_challenge,
    match_smb_stock_shares,
)


def test_match_smb_static_ntlm_challenge():
    assert match_smb_static_ntlm_challenge([b"\xaa" * 8, b"\xaa" * 8])
    assert match_smb_static_ntlm_challenge([b"\xaa" * 8, b"\xbb" * 8]) is None


def test_match_smb_bogus_pipe():
    assert match_smb_bogus_pipe(STATUS_OBJECT_NAME_NOT_FOUND, "ok", accepted=False) is None
    assert match_smb_bogus_pipe(None, "bogus pipe hpaudit_x opened", accepted=True)
    assert match_smb_bogus_pipe(0xC0000001, "x", accepted=False)


def test_match_smb_ghost_share():
    assert match_smb_ghost_share(STATUS_BAD_NETWORK_NAME, "ok", accepted=False) is None
    assert match_smb_ghost_share(STATUS_OBJECT_NAME_NOT_FOUND, "ok", accepted=False) is None
    assert match_smb_ghost_share(STATUS_ACCESS_DENIED, "ok", accepted=False) is None
    assert match_smb_ghost_share(None, "ghost share x TREE_CONNECT accepted", accepted=True)
    assert match_smb_ghost_share(0xC0000001, "x", accepted=False)


def test_match_smb_stock_shares():
    detail, requires = match_smb_stock_shares(["honey", "IPC$"])
    assert detail and "honey" in detail
    assert requires is False
    detail, requires = match_smb_stock_shares(["PUBLIC", "tmp"])
    assert detail and requires is True
    detail, requires = match_smb_stock_shares(["PUBLIC"])
    assert detail is None
    detail, requires = match_smb_stock_shares(["C$", "ADMIN$", "IPC$"])
    assert detail is None


def test_match_smb_negotiate_deficit():
    assert match_smb_negotiate_deficit({"dialect": 0x0202})
    assert match_smb_negotiate_deficit({"dialect": 0x0311, "supports_encryption": False})
