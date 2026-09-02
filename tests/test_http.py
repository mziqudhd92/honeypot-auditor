"""HTTP probe tests with mocks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import honeypot_auditor.probes.http as http
from honeypot_auditor.settings import settings


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
        "http.framework_404_session",
        "http.silent_accept",
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


def test_framework_404_session_helpers():
    assert http._framework_404_session(
        404, "Werkzeug/3.0.3 Python/3.12", {"set-cookie": "session=abc"}
    )
    assert not http._framework_404_session(200, "Werkzeug/3.0.3", {"set-cookie": "session=abc"})
    assert not http._framework_404_session(404, "nginx", {"set-cookie": "session=abc"})
    assert not http._framework_404_session(404, "gunicorn", {})
    detail = http._framework_404_detail(404, "gunicorn", {"set-cookie": "s=1"})
    assert "Set-Cookie" in detail
    assert "without framework" in http._framework_404_detail(200, "gunicorn", {})


@patch.object(http, "tcp_transact")
def test_http_framework_404_session_triggered(mock_tcp):
    mock_tcp.return_value = (b"HTTP/1.1 400 Bad Request\r\n\r\n", "")
    requests_mod = MagicMock()
    resp = MagicMock()
    resp.status_code = 404
    resp.headers = {
        "Server": "Werkzeug/3.0.3 Python/3.12.0",
        "Set-Cookie": "session=deadbeef; Path=/",
        "Content-Type": "text/html",
    }
    resp.content = b"Not Found"
    put = MagicMock()
    put.status_code = 405
    put.content = b"nope"
    # First GET / → 404; admin paths empty; no index.html form; PUT not empty 405
    requests_mod.get.side_effect = [
        resp,
        MagicMock(status_code=404, content=b""),
        MagicMock(status_code=404, content=b""),
        MagicMock(status_code=404, content=b""),
        MagicMock(status_code=404, content=b""),
        MagicMock(status_code=404, content=b""),
        MagicMock(status_code=404, content=b""),
    ]
    requests_mod.put.return_value = put
    with patch.object(http, "optional_import", return_value=requests_mod):
        inds = http.probe_http("127.0.0.1", 80)
    by_id = {i.id: i for i in inds}
    assert by_id["http.framework_404_session"].triggered
    assert "Set-Cookie" in by_id["http.framework_404_session"].detail
    assert "missing Date" in by_id["http.dynamic_headers"].detail


@patch.object(http, "tcp_transact")
def test_http_admin_path_login_skin_after_404(mock_tcp):
    mock_tcp.return_value = (
        b"HTTP/1.1 400 Bad Request\r\nDate: Wed, 26 Aug 2026 00:00:00 GMT\r\n\r\n",
        "",
    )
    requests_mod = MagicMock()
    root = MagicMock()
    root.status_code = 404
    root.headers = {"Date": "Wed, 26 Aug 2026 00:00:00 GMT", "Server": "nginx"}
    root.content = b""
    admin = MagicMock()
    admin.status_code = 200
    admin.content = b'<html><form><input name="pma_username"><input name="pma_password"></form>'
    put = MagicMock()
    put.status_code = 200
    put.content = b"ok"
    requests_mod.get.side_effect = [root, admin]
    requests_mod.put.return_value = put
    with patch.object(http, "optional_import", return_value=requests_mod):
        inds = http.probe_http("127.0.0.1", 80)
    by_id = {i.id: i for i in inds}
    assert by_id["http.login_skin"].triggered
    assert requests_mod.get.call_args_list[1][0][0].endswith("/phpmyadmin/")
    assert "Date present" in by_id["http.dynamic_headers"].detail
    assert not by_id["http.framework_404_session"].triggered


def test_probe_admin_login_skin_continues_on_request_error():
    requests_mod = MagicMock()
    requests_mod.get.side_effect = [
        ConnectionError("boom"),
        MagicMock(status_code=200, content=b'name="username" name="password"'),
    ]
    assert http._probe_admin_login_skin(requests_mod, "http://127.0.0.1:80") is True
    assert requests_mod.get.call_count == 2


@patch.object(settings, "safe_mode", True)
@patch.object(http, "tcp_transact")
def test_http_safe_mode_handshake_only(mock_tcp):
    mock_tcp.return_value = (
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: Wed, 26 Aug 2026 00:00:00 GMT\r\n\r\n",
        "",
    )
    inds = http.probe_http("127.0.0.1", 80)
    by_id = {i.id: i for i in inds}
    assert "http.dynamic_headers" in by_id
    assert not by_id["http.dynamic_headers"].triggered
    assert "Date present" in by_id["http.dynamic_headers"].detail
    assert by_id["http.framework_404_session"].skipped
    assert by_id["http.login_skin"].skipped


@patch.object(http, "optional_import", return_value=None)
@patch.object(http, "tcp_transact")
def test_http_silent_accept(mock_tcp, _no_requests):
    mock_tcp.return_value = (b"", "")
    inds = http.probe_http("127.0.0.1", 80)
    by_id = {i.id: i for i in inds}
    assert by_id["http.silent_accept"].triggered
    assert "no HTTP bytes" in by_id["http.silent_accept"].detail
    assert not by_id["http.malformed_200"].skipped
    assert not by_id["http.malformed_200"].triggered


@patch.object(settings, "safe_mode", True)
@patch.object(http, "optional_import")
def test_http_safe_mode_https(mock_import):
    requests_mod = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {"Server": "nginx", "Date": "Wed, 26 Aug 2026 00:00:00 GMT"}
    requests_mod.get.return_value = resp
    mock_import.return_value = requests_mod
    inds = http.probe_http("127.0.0.1", 443)
    by_id = {i.id: i for i in inds}
    assert not by_id["http.dynamic_headers"].triggered
    assert by_id["http.wildcard_host"].skipped
