"""Network helper tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from honeypot_auditor import netutil


def test_closed_reason_variants():
    assert "refused" in netutil.closed_reason("Connection refused")
    assert netutil.closed_reason("timed out") == "timeout"
    assert netutil.closed_reason("Connection reset by peer") == "connection reset"
    assert netutil.closed_reason("") == "no response"
    assert netutil.closed_reason("weird") == "weird"


@patch("honeypot_auditor.netutil.socket.create_connection")
def test_tcp_transact_send_recv(mock_connect):
    sock = MagicMock()
    sock.recv.side_effect = [b"hello", b""]
    mock_connect.return_value.__enter__.return_value = sock

    data, err = netutil.tcp_transact("127.0.0.1", 80, b"GET /\r\n\r\n", timeout=1.0)
    assert data == b"hello"
    assert err == ""
    sock.sendall.assert_called_once_with(b"GET /\r\n\r\n")


@patch("honeypot_auditor.netutil.socket.create_connection", side_effect=OSError("refused"))
def test_tcp_transact_error(mock_connect):
    data, err = netutil.tcp_transact("127.0.0.1", 80, timeout=1.0)
    assert data == b""
    assert "refused" in err


@patch("honeypot_auditor.netutil.socket.socket")
def test_udp_transact(mock_socket_ctor):
    sock = MagicMock()
    sock.recvfrom.return_value = (b"pong", ("127.0.0.1", 53))
    mock_socket_ctor.return_value = sock

    data, err = netutil.udp_transact("127.0.0.1", 53, b"ping", timeout=1.0)
    assert data == b"pong"
    assert err == ""
    sock.close.assert_called_once()
