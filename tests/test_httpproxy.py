"""HTTP proxy probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.httpproxy as httpproxy

_SQUID_407 = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b"Server: squid/3.3.8\r\n"
    b"Via: 1.1 localhost (squid/3.3.8)\r\n"
    b"X-Squid-Error: ERR_CACHE_ACCESS_DENIED 0\r\n"
    b"\r\n"
)


@patch.object(httpproxy, "tcp_transact")
def test_httpproxy_squid_lure(mock_tcp):
    mock_tcp.return_value = (_SQUID_407, "")
    inds = httpproxy.probe_httpproxy("127.0.0.1", 3128)
    assert inds[0].triggered
    assert "squid" in inds[0].detail.lower() or "via" in inds[0].detail.lower()


@patch.object(httpproxy, "tcp_transact")
def test_httpproxy_plain_407_clean(mock_tcp):
    mock_tcp.return_value = (b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", "")
    inds = httpproxy.probe_httpproxy("127.0.0.1", 3128)
    assert not inds[0].triggered


@patch.object(httpproxy, "tcp_transact")
def test_httpproxy_closed_port(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = httpproxy.probe_httpproxy("127.0.0.1", 3128)
    assert all(i.skipped for i in inds)
    assert {i.id for i in inds} == {"httpproxy.signature", "httpproxy.silent_accept"}


@patch.object(httpproxy, "tcp_transact")
def test_httpproxy_silent_accept(mock_tcp):
    mock_tcp.return_value = (b"", "")
    inds = httpproxy.probe_httpproxy("127.0.0.1", 8080)
    by_id = {i.id: i for i in inds}
    assert by_id["httpproxy.silent_accept"].triggered
    assert not by_id["httpproxy.signature"].triggered
