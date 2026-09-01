"""HTTP probe tests with mocks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import honeypot_auditor.probes.http as http


@patch.object(http, "optional_import", return_value=None)
@patch.object(http, "tcp_transact")
def test_http_malformed_200(mock_tcp, _no_requests):
    mock_tcp.return_value = (
        b"HTTP/1.1 200 OK\r\nDate: Wed, 26 Aug 2026 00:00:00 GMT\r\n\r\n",
        "",
    )
    inds = http.probe_http("127.0.0.1", 80)
    by_id = {i.id: i for i in inds}
    assert by_id["http.malformed_200"].triggered
    assert not by_id["http.dynamic_headers"].triggered
    assert not by_id["http.method_stub"].triggered
    assert not by_id["http.login_skin"].triggered
    assert not by_id["http.proxy_lure"].triggered


@patch.object(http, "tcp_transact")
def test_http_skipped_on_closed_port(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = http.probe_http("127.0.0.1", 80)
    assert {i.id for i in inds} == {
        "http.malformed_200",
        "http.dynamic_headers",
        "http.method_stub",
        "http.login_skin",
        "http.proxy_lure",
        "http.header_order",
        "http.wildcard_host",
    }
    assert all(i.skipped for i in inds)


@patch.object(http, "optional_import", return_value=None)
@patch.object(http, "tcp_transact")
def test_http_put_empty_405(mock_tcp, _no_requests):
    mock_tcp.side_effect = [
        (b"HTTP/1.1 400 Bad Request\r\nDate: Wed, 26 Aug 2026 00:00:00 GMT\r\n\r\n", ""),
        (b"HTTP/1.1 400 Bad Request\r\nDate: Wed, 26 Aug 2026 00:00:00 GMT\r\n\r\n", ""),
        (b"HTTP/1.1 405 Method Not Allowed\r\n\r\n", ""),
        (b"HTTP/1.1 400 Bad Request\r\nDate: Wed, 26 Aug 2026 00:00:00 GMT\r\n\r\n", ""),
    ]
    inds = http.probe_http("127.0.0.1", 80)
    by_id = {i.id: i for i in inds}
    assert by_id["http.method_stub"].triggered
    assert not by_id["http.malformed_200"].triggered


@patch.object(http, "tcp_transact")
def test_http_login_skin_redirect(mock_tcp):
    mock_tcp.return_value = (
        b"HTTP/1.1 200 OK\r\nDate: Wed, 26 Aug 2026 00:00:00 GMT\r\nServer: Apache/2.4.52 (Ubuntu)\r\n\r\n",
        "",
    )
    requests_mod = MagicMock()
    resp = MagicMock()
    resp.status_code = 302
    resp.headers = {
        "Location": "/index.html",
        "Server": "Apache/2.4.52 (Ubuntu)",
        "Date": "Wed, 26 Aug 2026 00:00:00 GMT",
    }
    resp.content = b"<html></html>"
    put = MagicMock()
    put.status_code = 405
    put.content = b""
    requests_mod.get.return_value = resp
    requests_mod.put.return_value = put
    with patch.object(http, "optional_import", return_value=requests_mod):
        inds = http.probe_http("127.0.0.1", 80)
    by_id = {i.id: i for i in inds}
    assert by_id["http.login_skin"].triggered
    assert by_id["http.method_stub"].triggered
    assert not by_id["http.dynamic_headers"].triggered


@patch.object(http, "tcp_transact")
def test_http_https_login_skin(mock_tcp):
    requests_mod = MagicMock()
    resp = MagicMock()
    resp.status_code = 302
    resp.headers = {"Location": "/index.html", "Date": "Wed, 26 Aug 2026 00:00:00 GMT"}
    resp.content = b""
    put = MagicMock()
    put.status_code = 405
    put.content = b""
    requests_mod.get.return_value = resp
    requests_mod.put.return_value = put
    with patch.object(http, "optional_import", return_value=requests_mod):
        inds = http.probe_http("127.0.0.1", 443)
    mock_tcp.assert_not_called()
    assert requests_mod.get.call_args[0][0].startswith("https://")
    by_id = {i.id: i for i in inds}
    assert by_id["http.login_skin"].triggered
    assert by_id["http.method_stub"].triggered
