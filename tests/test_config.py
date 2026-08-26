"""Tests for config helpers and port presets."""

from __future__ import annotations

from unittest.mock import patch

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


def test_invalid_ports_format():
    with pytest.raises(ValueError):
        parse_port_overrides("ssh8022")


def test_unknown_preset():
    with pytest.raises(ValueError):
        merge_ports("not-a-preset")


def test_resolve_target_ip():
    from honeypot_auditor.config import resolve_target

    assert resolve_target("127.0.0.1") == "127.0.0.1"


@patch("honeypot_auditor.config.socket.gethostbyname", return_value="93.184.216.34")
def test_resolve_target_hostname(mock_dns):
    from honeypot_auditor.config import resolve_target

    assert resolve_target("example.com") == "93.184.216.34"


def test_match_cpuinfo_signature():
    from honeypot_auditor.config import match_cpuinfo_signature

    assert match_cpuinfo_signature("model name : Intel(R) Core(TM)2 Duo CPU     T7300  @ 2.00GHz")


def test_ssh_banner_legacy():
    assert match_ssh_banner("SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2")
    assert match_ssh_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3") is None


def test_uname_normalize():
    raw = "Linux decoy 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux"
    assert match_uname_signature(raw)


def test_uname_whitespace_only():
    from honeypot_auditor.config import normalize_uname

    assert normalize_uname("\n") == ""
    assert match_uname_signature("\n") is None
