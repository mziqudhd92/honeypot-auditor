"""Tests for netutil helpers."""

from honeypot_auditor.netutil import is_non_routable_ip, parse_ftp_pasv_host


def test_parse_ftp_pasv_host():
    assert parse_ftp_pasv_host("227 Entering Passive Mode (172,18,0,2,182,77).") == "172.18.0.2"
    assert parse_ftp_pasv_host("garbage") is None


def test_is_non_routable_ip():
    assert is_non_routable_ip("172.18.0.2")
    assert is_non_routable_ip("127.0.0.1")
    assert not is_non_routable_ip("8.8.8.8")
