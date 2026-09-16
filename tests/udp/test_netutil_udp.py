"""Scaffold RED/GREEN: UdpExchange peer port, RTT, refused mapping, udp_transact compat."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from honeypot_auditor.netutil import (
    UdpExchange,
    closed_reason,
    udp_exchange,
    udp_exchange_to,
    udp_transact,
)


@contextmanager
def _udp_echo_server(*, reply_from_ephemeral: bool = False) -> Iterator[tuple[str, int]]:
    """Local UDP server that echoes payload; optionally replies from a second socket."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    host, port = srv.getsockname()
    stop = threading.Event()

    def _loop() -> None:
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = srv.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if reply_from_ephemeral:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
                    out.sendto(data, addr)
            else:
                srv.sendto(data, addr)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    try:
        yield host, port
    finally:
        stop.set()
        t.join(timeout=1.0)
        srv.close()


def test_udp_exchange_returns_frozen_dataclass_fields():
    with _udp_echo_server() as (host, port):
        result = udp_exchange(host, port, b"ping", timeout=1.0)
    assert isinstance(result, UdpExchange)
    assert result.data == b"ping"
    assert result.error == ""
    assert result.peer_host == "127.0.0.1"
    assert result.peer_port == port
    assert result.rtt_ms >= 0.0


def test_udp_exchange_captures_ephemeral_peer_port():
    """Unconnected recvfrom must surface the peer source port (TFTP TID learning)."""
    with _udp_echo_server(reply_from_ephemeral=True) as (host, port):
        result = udp_exchange(host, port, b"tid-learn", connected=False, timeout=1.0)
    assert result.error == ""
    assert result.data == b"tid-learn"
    assert result.peer_port != 0
    assert result.peer_port != port


def test_udp_exchange_measures_rtt_ms():
    with _udp_echo_server() as (host, port):
        t0 = time.perf_counter()
        result = udp_exchange(host, port, b"rtt", timeout=1.0)
        wall_ms = (time.perf_counter() - t0) * 1000.0
    assert result.error == ""
    assert 0.0 <= result.rtt_ms <= wall_ms + 50.0


def test_udp_exchange_connected_maps_refused():
    """Connected mode surfaces ICMP port-unreachable as refused where the OS provides it."""
    # Bind then close so the port is unused; connected UDP often gets ECONNREFUSED on localhost.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    host, port = probe.getsockname()
    probe.close()

    result = udp_exchange(host, port, b"x", connected=True, timeout=0.5)
    assert result.data == b""
    assert result.error
    reason = closed_reason(result.error)
    assert reason in (
        "connection refused (closed port or filtered)",
        "timeout",
    ) or "refused" in result.error.lower() or "timed out" in result.error.lower()


def test_udp_exchange_timeout_sets_error():
    # High unused port; unconnected UDP typically times out (no ICMP).
    result = udp_exchange("127.0.0.1", 1, b"silent", connected=False, timeout=0.2)
    assert result.data == b""
    assert result.error
    assert "timed out" in result.error.lower() or "timeout" in closed_reason(result.error)


def test_udp_exchange_to_sends_to_peer_port():
    with _udp_echo_server() as (host, port):
        result = udp_exchange_to(host, port, b"follow-up", timeout=1.0)
    assert result.error == ""
    assert result.data == b"follow-up"
    assert result.peer_port == port


def test_udp_transact_back_compat_wrapper():
    with _udp_echo_server() as (host, port):
        data, err = udp_transact(host, port, b"legacy", timeout=1.0)
    assert err == ""
    assert data == b"legacy"
    assert isinstance(data, bytes)


def test_udp_transact_back_compat_error_tuple():
    data, err = udp_transact("127.0.0.1", 1, b"x", timeout=0.2)
    assert data == b""
    assert err
