"""Syslog RFC-behavioral probe tests (no request/response channel by design)."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.udp.syslog as syslog
from honeypot_auditor.netutil import UdpExchange


class _FakeTcpSock:
    def __init__(self, recv_behavior) -> None:
        self._recv_behavior = recv_behavior
        self.sent: list[bytes] = []

    def settimeout(self, value) -> None:
        return None

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        return self._recv_behavior(size)

    def close(self) -> None:
        return None


def _exchange(data: bytes = b"", error: str = "") -> UdpExchange:
    return UdpExchange(data=data, peer_host="127.0.0.1", peer_port=514, rtt_ms=0.5, error=error)


def test_syslog_silent_channel_is_clean():
    with patch.object(syslog, "udp_exchange", return_value=_exchange()):
        inds = syslog.probe_syslog("127.0.0.1", 514)
    by_id = {i.id: i for i in inds}
    assert not any(i.triggered for i in inds)
    assert "silent" in by_id["syslog.unexpected_reply"].detail
    assert not by_id["syslog.tcp_reply"].triggered


def test_syslog_udp_reply_is_a_tell():
    with patch.object(syslog, "udp_exchange", return_value=_exchange(data=b"ack?")):
        inds = syslog.probe_syslog("127.0.0.1", 514)
    by_id = {i.id: i for i in inds}
    assert by_id["syslog.unexpected_reply"].triggered
    assert "never acknowledges" in by_id["syslog.unexpected_reply"].detail


def test_syslog_udp_errors_skip_udp_tell():
    with patch.object(syslog, "udp_exchange", return_value=_exchange(error="port unreachable")):
        inds = syslog.probe_syslog("127.0.0.1", 514)
    by_id = {i.id: i for i in inds}
    assert by_id["syslog.unexpected_reply"].skipped
    assert not by_id["syslog.unexpected_reply"].triggered


def test_syslog_tcp_echo_is_a_tell():
    sock = _FakeTcpSock(lambda size: b"<13> echo of your frame")
    with patch.object(syslog, "create_connection", return_value=sock):
        inds = syslog.probe_syslog("127.0.0.1", 514)
    by_id = {i.id: i for i in inds}
    assert by_id["syslog.tcp_reply"].triggered
    assert "consumes in silence" in by_id["syslog.tcp_reply"].detail
    assert sock.sent, "TCP frame was not sent"


def test_syslog_tcp_silent_is_clean():
    def silent(size: int) -> bytes:
        raise TimeoutError()

    sock = _FakeTcpSock(silent)
    with patch.object(syslog, "create_connection", return_value=sock):
        inds = syslog.probe_syslog("127.0.0.1", 514)
    by_id = {i.id: i for i in inds}
    assert not by_id["syslog.tcp_reply"].triggered
    assert not by_id["syslog.tcp_reply"].skipped
