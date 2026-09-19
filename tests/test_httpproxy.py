"""HTTP proxy probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.httpproxy as httpproxy

_CREDS = (("user_low", "pass_low"), ("user_HIGH_entropy_xx", "pass_HIGH_entropy_yy"))

_SQUID_407 = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b"Server: squid/3.3.8\r\n"
    b"Via: 1.1 localhost (squid/3.3.8)\r\n"
    b"X-Squid-Error: ERR_CACHE_ACCESS_DENIED 0\r\n"
    b"\r\n"
)

_OK_200 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
_PLAIN_407 = b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"


@patch.object(httpproxy, "tcp_transact")
def test_httpproxy_squid_lure(mock_tcp):
    mock_tcp.return_value = (_SQUID_407, "")
    with (
        patch.object(httpproxy, "entropy_varied_creds", return_value=_CREDS),
        patch.object(httpproxy, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = httpproxy.probe_httpproxy("127.0.0.1", 3128)
    by_id = {i.id: i for i in inds}
    assert by_id["httpproxy.signature"].triggered
    assert "squid" in by_id["httpproxy.signature"].detail.lower() or "via" in by_id[
        "httpproxy.signature"
    ].detail.lower()


@patch.object(httpproxy, "tcp_transact")
def test_httpproxy_plain_407_clean(mock_tcp):
    # Distinct 407 bodies on reconnect so state does not fire on identical canned 407.
    mock_tcp.side_effect = [
        (_PLAIN_407, ""),
        (_PLAIN_407 + b" ", ""),  # auth1 reject (still 407)
        (_PLAIN_407 + b"  ", ""),  # auth2
        (b"HTTP/1.1 407 Proxy Authentication Required\r\nX-Nonce: 1\r\n\r\n", ""),
    ]
    with (
        patch.object(httpproxy, "entropy_varied_creds", return_value=_CREDS),
        patch.object(httpproxy, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = httpproxy.probe_httpproxy("127.0.0.1", 3128)
    by_id = {i.id: i for i in inds}
    assert not by_id["httpproxy.signature"].triggered
    assert not by_id["httpproxy.arbitrary_auth"].triggered


@patch.object(httpproxy, "tcp_transact")
def test_httpproxy_closed_port(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = httpproxy.probe_httpproxy("127.0.0.1", 3128)
    assert all(i.skipped for i in inds)
    assert {i.id for i in inds} == {
        "httpproxy.arbitrary_auth",
        "httpproxy.state_nonpersist",
        "httpproxy.signature",
        "httpproxy.silent_accept",
    }


@patch.object(httpproxy, "tcp_transact")
def test_httpproxy_silent_accept(mock_tcp):
    mock_tcp.return_value = (b"", "")
    inds = httpproxy.probe_httpproxy("127.0.0.1", 8080)
    by_id = {i.id: i for i in inds}
    assert by_id["httpproxy.silent_accept"].triggered
    assert not by_id["httpproxy.signature"].triggered


@patch.object(httpproxy, "tcp_transact")
def test_httpproxy_arbitrary_auth_and_state(mock_tcp):
    mock_tcp.side_effect = [
        (_PLAIN_407, ""),  # baseline
        (_OK_200, ""),  # auth low
        (_OK_200, ""),  # auth high
        (_PLAIN_407, ""),  # reconnect → 407 after success
    ]
    with (
        patch.object(httpproxy, "entropy_varied_creds", return_value=_CREDS),
        patch.object(httpproxy, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = httpproxy.probe_httpproxy("127.0.0.1", 3128)
    by_id = {i.id: i for i in inds}
    assert by_id["httpproxy.arbitrary_auth"].triggered
    assert by_id["httpproxy.state_nonpersist"].triggered
