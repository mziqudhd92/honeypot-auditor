"""Proxy transport tests."""

from __future__ import annotations

import pytest

from honeypot_auditor.proxy_transport import normalize_proxy_url


def test_socks5_hostname_rejected():
    with pytest.raises(ValueError, match="socks5h"):
        normalize_proxy_url("socks5://proxy.example:1080", "target.example.com")


def test_socks5h_hostname_ok():
    url = normalize_proxy_url("socks5h://127.0.0.1:9050", "target.example.com")
    assert url.startswith("socks5h://")


def test_ip_target_allows_socks5():
    url = normalize_proxy_url("socks5://127.0.0.1:1080", "203.0.113.1")
    assert "127.0.0.1:1080" in url
