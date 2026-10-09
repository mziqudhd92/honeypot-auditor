"""Tests for netutil helpers — fake sockets for TCP, loopback peers for UDP."""

from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from unittest.mock import patch

from honeypot_auditor import netutil
from honeypot_auditor.netutil import (
    UdpExchange,
    closed_reason,
    is_non_routable_ip,
    parse_ftp_pasv_host,
    tcp_roundtrips,
    tcp_transact,
    udp_exchange,
    udp_exchange_to,
    udp_exchange_with_retransmit_watch,
    udp_transact,
)


def test_parse_ftp_pasv_host():
    assert parse_ftp_pasv_host("227 Entering Passive Mode (172,18,0,2,182,77).") == "172.18.0.2"
    assert parse_ftp_pasv_host("garbage") is None


def test_is_non_routable_ip():
    assert is_non_routable_ip("172.18.0.2")
    assert is_non_routable_ip("127.0.0.1")
    assert not is_non_routable_ip("8.8.8.8")
    assert not is_non_routable_ip("not-an-ip")  # ValueError → False
    assert is_non_routable_ip("169.254.1.1")  # link-local
    assert is_non_routable_ip("192.0.2.1")  # reserved (TEST-NET)


def test_closed_reason_classification():
    assert closed_reason("") == "no response"
    assert "refused" in closed_reason("Connection refused")
    assert closed_reason("timed out") == "timeout"
    assert closed_reason("Connection reset by peer") == "connection reset"
    assert closed_reason("winsock 10054 forcibly closed") == "connection reset"
    assert closed_reason("weird transport failure") == "weird transport failure"


# --------------------------------------------------------------------------
# TCP helpers with a scripted fake socket
# --------------------------------------------------------------------------
class _FakeSocket:
    """Context-manager socket modeling a request/response server.

    recv() yields at most one scripted reply per sendall() (server stays
    silent afterwards, so _recv's reduced-timeout loop ends in TimeoutError).
    """

    def __init__(self, script=()):
        self._script = list(script)
        self._responded = False
        self.sent: list[bytes] = []
        self.timeouts: list[float] = []

    def sendall(self, data):
        self.sent.append(data)
        self._responded = False

    def recv(self, _n):
        if self._responded or not self._script:
            raise TimeoutError("timed out")
        self._responded = True
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def settimeout(self, value):
        self.timeouts.append(value)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _patch_transport(fake_or_factory):
    return patch.object(netutil, "create_connection", fake_or_factory)


def test_tcp_transact_greeting_then_command():
    fake = _FakeSocket(script=[b"220 hello", b"250 OK"])
    with _patch_transport(lambda host, port, timeout: fake):
        data, err = tcp_transact("h", 1, b"HELLO\r\n", recv_first=True, timeout=2.0)
    assert err == "" and data == b"220 hello250 OK"
    assert fake.sent == [b"HELLO\r\n"]


def test_tcp_transact_recv_first_without_payload():
    fake = _FakeSocket(script=[b"greeting only"])
    with _patch_transport(lambda host, port, timeout: fake):
        data, err = tcp_transact("h", 1, recv_first=True, timeout=1.0)
    assert err == "" and data == b"greeting only"
    assert fake.sent == []


def test_tcp_transact_recv_timeout_is_swallowed():
    fake = _FakeSocket(script=[TimeoutError("timed out")])
    with _patch_transport(lambda host, port, timeout: fake):
        data, err = tcp_transact("h", 1, b"Q", timeout=0.5)
    assert err == "" and data == b""


def test_tcp_transact_reports_transport_errors():
    def _refused(host, port, timeout):
        raise ConnectionRefusedError("connection refused")

    with _patch_transport(_refused):
        data, err = tcp_transact("h", 1, b"Q", timeout=0.5)
    assert data == b"" and "refused" in err


def test_tcp_roundtrips_same_session():
    fake = _FakeSocket(script=[b"hi", b"one", b"two"])
    with _patch_transport(lambda host, port, timeout: fake):
        replies, err = tcp_roundtrips("h", 1, [b"A", b"B"], recv_first=True, timeout=1.0)
    assert err == ""
    assert replies == [b"hi", b"one", b"two"]
    assert fake.sent == [b"A", b"B"]


def test_tcp_roundtrips_empty_payloads_still_recv():
    fake = _FakeSocket(script=[b"r1", b"r2"])
    with _patch_transport(lambda host, port, timeout: fake):
        replies, err = tcp_roundtrips("h", 1, [b"", b"X"], timeout=1.0)
    assert err == "" and replies == [b"r1", b"r2"]
    assert fake.sent == [b"X"]  # empty payload is not sent


def test_tcp_roundtrips_error_keeps_prior_replies():
    def _boom(host, port, timeout):
        raise OSError("reset by peer")

    with _patch_transport(_boom):
        replies, err = tcp_roundtrips("h", 1, [b"A"], timeout=1.0)
    assert replies == [] and "reset" in err


# --------------------------------------------------------------------------
# UDP helpers against real loopback peers
# --------------------------------------------------------------------------
@contextmanager
def _udp_peer(replies_per_request: list[bytes] | None = None):
    """Loopback UDP peer echoing `replies_per_request` datagrams per request."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    host, port = sock.getsockname()
    stop = threading.Event()

    def serve():
        sock.settimeout(0.5)
        while not stop.is_set():
            try:
                _data, addr = sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                break
            for reply in replies_per_request or []:
                sock.sendto(reply, addr)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield host, port, sock
    finally:
        stop.set()
        sock.close()
        thread.join(timeout=1)


def test_udp_exchange_learns_peer_port():
    with _udp_peer([b"PONG"]) as (host, port, _sock):
        ex = udp_exchange(host, port, b"PING", timeout=2.0)
    assert isinstance(ex, UdpExchange)
    assert ex.error == "" and ex.data == b"PONG"
    assert ex.peer_host == "127.0.0.1" and ex.peer_port == port


def test_udp_exchange_connected_mode():
    with _udp_peer([b"ACK"]) as (host, port, _sock):
        ex = udp_exchange(host, port, b"Q", connected=True, timeout=2.0)
    assert ex.error == "" and ex.data == b"ACK"
    assert (ex.peer_host, ex.peer_port) == (host, port)


def test_udp_exchange_timeout_returns_error():
    # port with no listener: unconnected recvfrom just times out
    ex = udp_exchange("127.0.0.1", 1, b"X", timeout=0.3)
    assert ex.data == b"" and ex.error != ""


def test_udp_exchange_to_and_udp_transact_wrappers():
    with _udp_peer([b"ECHO"]) as (host, port, _sock):
        ex = udp_exchange_to(host, port, b"REQ", timeout=2.0)
        assert ex.data == b"ECHO" and ex.peer_port == port

        data, err = udp_transact(host, port, b"REQ", timeout=2.0)
        assert (data, err) == (b"ECHO", "")


def test_retransmit_watch_detects_silent_stub():
    with _udp_peer([b"OACK"]) as (host, port, _sock):
        first, idle = udp_exchange_with_retransmit_watch(
            host, port, b"RRQ", timeout=2.0, retransmit_wait=0.4
        )
    assert first.error == "" and first.data == b"OACK"
    assert idle.data == b"" and idle.error == "timed out"


def test_retransmit_watch_sees_second_datagram():
    with _udp_peer([b"FIRST", b"SECOND"]) as (host, port, _sock):
        first, second = udp_exchange_with_retransmit_watch(
            host, port, b"RRQ", timeout=2.0, retransmit_wait=1.5
        )
    assert first.data == b"FIRST" and second.error == ""
    assert second.data == b"SECOND" and second.peer_port == port


def test_retransmit_watch_first_exchange_failure():
    first, idle = udp_exchange_with_retransmit_watch(
        "127.0.0.1", 1, b"X", timeout=0.3, retransmit_wait=0.2
    )
    assert first.data == b"" and first.error != ""
    assert idle.data == b"" and idle.error == "timed out"


def test_retransmit_watch_connected_mode():
    with _udp_peer([b"ONE", b"TWO"]) as (host, port, _sock):
        first, second = udp_exchange_with_retransmit_watch(
            host, port, b"Q", connected=True, timeout=2.0, retransmit_wait=1.5
        )
    assert first.data == b"ONE" and second.data == b"TWO"
    assert (second.peer_host, second.peer_port) == (host, port)
