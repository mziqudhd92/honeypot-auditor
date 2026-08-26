"""Tests for HASSH parsing and mismatch detection."""

from __future__ import annotations

from honeypot_auditor.hassh import (
    SSHKexInit,
    capture_server_kexinit,
    hassh_algo_mismatch,
    parse_kexinit_payload,
)


def test_hassh_server_digest():
    kex = SSHKexInit(
        kex="curve25519-sha256",
        host_key="ssh-rsa",
        enc_c2s="aes128-ctr",
        enc_s2c="aes128-ctr",
        mac_c2s="hmac-sha2-256",
        mac_s2c="hmac-sha2-256",
        comp_c2s="none",
        comp_s2c="none",
    )
    assert len(kex.hassh_server) == 32


def test_twisted_kex_mismatch():
    kex = SSHKexInit(
        kex="diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
        host_key="ssh-rsa",
        enc_c2s="aes128-ctr",
        enc_s2c="aes128-ctr",
        mac_c2s="hmac-sha1",
        mac_s2c="hmac-sha1",
        comp_c2s="none",
        comp_s2c="none",
    )
    triggered, detail = hassh_algo_mismatch("SSH-2.0-OpenSSH_9.2p1 Debian", kex)
    assert triggered
    assert "Twisted" in detail or "legacy" in detail


def test_parse_kexinit_rejects_short_payload():
    assert parse_kexinit_payload(b"\x14") is None


def test_capture_banner_only():
    banner, kex = capture_server_kexinit(b"SSH-2.0-test\r\n")
    assert banner.startswith("SSH-2.0-test")
    assert kex is None
