"""Tests for HASSH parsing and mismatch detection."""

from __future__ import annotations

from honeypot_auditor.hassh import (
    SSHKexInit,
    capture_server_kexinit,
    find_kexinit_payload,
    hassh_algo_mismatch,
    openssh_version_from_banner,
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


def test_openssh_version_from_banner():
    assert openssh_version_from_banner("SSH-2.0-OpenSSH_9.2p1 Debian") == "9.2p1"
    assert openssh_version_from_banner("SSH-2.0-Cowrie") is None


def test_hassh_client_digest():
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
    assert len(kex.hassh_client) == 32


def test_find_kexinit_none_on_garbage():
    assert find_kexinit_payload(b"not ssh binary") is None


def test_hassh_non_openssh_banner_no_trigger():
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
    triggered, detail = hassh_algo_mismatch("SSH-2.0-Cowrie", kex)
    assert not triggered
    assert "non-OpenSSH" in detail


def test_capture_kexinit_raw_hex():
    # Minimal SSH banner + fake KEXINIT payload marker
    banner = b"SSH-2.0-OpenSSH_8.9\r\n"
    payload = bytes([20]) + b"\x00" * 16
    raw = banner + payload
    kex_payload = find_kexinit_payload(raw)
    assert kex_payload is None or isinstance(kex_payload, bytes)
    banner_out, kex = capture_server_kexinit(raw)
    assert banner_out.startswith("SSH-2.0-OpenSSH")


def test_kexinit_is_rigid_twisted_prefix():
    from honeypot_auditor.hassh import kexinit_is_rigid

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
    triggered, detail = kexinit_is_rigid(kex)
    assert triggered
    assert "rigid" in detail.lower()


def test_kexinit_is_rigid_modern_openssh_negative():
    from honeypot_auditor.hassh import kexinit_is_rigid

    kex = SSHKexInit(
        kex="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256",
        host_key="rsa-sha2-512,ssh-ed25519",
        enc_c2s="chacha20-poly1305@openssh.com,aes128-ctr",
        enc_s2c="chacha20-poly1305@openssh.com,aes128-ctr",
        mac_c2s="hmac-sha2-256-etm@openssh.com",
        mac_s2c="hmac-sha2-256-etm@openssh.com",
        comp_c2s="none",
        comp_s2c="none",
    )
    triggered, _ = kexinit_is_rigid(kex)
    assert not triggered


def test_kexinit_rigid_fires_without_openssh_banner():
    """Non-OpenSSH banner: hassh mismatch stays quiet; rigid template still scores."""
    from unittest.mock import patch

    from honeypot_auditor.probes.deep import stack

    banner = b"SSH-2.0-Twisted\r\n"
    # Minimal rigid-prefix payload reused from hassh unit shape via capture path
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
    with patch.object(stack, "tcp_transact", return_value=(banner + b"\x00", "")):
        with patch.object(stack, "capture_server_kexinit", return_value=("SSH-2.0-Twisted", kex)):
            with patch.object(stack, "find_kexinit_payload", return_value=b"\x14" + b"\x00" * 16):
                inds = stack.probe_hassh("127.0.0.1", 22)
    by_id = {i.id: i for i in inds}
    assert not by_id["deep.hassh"].triggered
    assert by_id["deep.kexinit_rigid"].triggered
