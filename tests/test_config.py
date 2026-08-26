"""Tests for config helpers and port presets."""

from __future__ import annotations

import pytest

from honeypot_auditor.config import (
    FTP_WELCOME_TELLS,
    NMAP_HONEYPOT_TELLS,
    is_private_or_loopback,
    match_ssh_banner,
    match_uname_signature,
    merge_ports,
    parse_port_overrides,
)


def test_is_private_loopback():
    assert is_private_or_loopback("127.0.0.1")
    assert is_private_or_loopback("10.0.0.5")
    assert is_private_or_loopback("192.168.1.1")
    assert not is_private_or_loopback("8.8.8.8")


def test_merge_ports_override():
    ports = merge_ports("docker-research", parse_port_overrides("ssh=8022"))
    assert ports["ssh"] == 8022
    assert ports["http"] == 8081


def test_nmap_honeypot_tells_include_cowrie():
    assert "cowrie" in NMAP_HONEYPOT_TELLS
    assert any("DiskStation" in t for t in FTP_WELCOME_TELLS)


def test_invalid_port():
    with pytest.raises(ValueError):
        parse_port_overrides("ssh=0")


def test_ssh_banner_legacy():
    assert match_ssh_banner("SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2")
    assert match_ssh_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3") is None


def test_uname_normalize():
    raw = "Linux decoy 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux"
    assert match_uname_signature(raw)
