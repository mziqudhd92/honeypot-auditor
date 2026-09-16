"""Shared UDP test harness: scripted datagram replies without live network."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

import pytest

from honeypot_auditor.netutil import UdpExchange


@dataclass(frozen=True)
class ScriptedReply:
    """One scripted UDP reply: payload, peer port, RTT, and optional error."""

    data: bytes = b""
    peer_port: int = 0
    rtt_ms: float = 0.0
    error: str = ""


class MockUDPTransceiver:
    """Scripted ``udp_exchange`` / ``udp_exchange_to`` for unit tests.

    Feed ``(data, peer_port, rtt_ms, error)`` tuples (or ``ScriptedReply``).
    Each call consumes the next scripted reply. Exhaustion yields a timeout-like
    empty exchange so probes skip rather than raise.
    """

    def __init__(
        self,
        replies: Sequence[ScriptedReply | tuple[bytes, int, float, str]] | None = None,
        *,
        peer_host: str = "127.0.0.1",
    ) -> None:
        self.peer_host = peer_host
        self.calls: list[dict[str, Any]] = []
        self._replies: list[ScriptedReply] = [
            r if isinstance(r, ScriptedReply) else ScriptedReply(*r) for r in (replies or ())
        ]

    def queue(self, *replies: ScriptedReply | tuple[bytes, int, float, str]) -> None:
        for r in replies:
            self._replies.append(r if isinstance(r, ScriptedReply) else ScriptedReply(*r))

    def _next(self, host: str, port: int, payload: bytes, *, connected: bool) -> UdpExchange:
        self.calls.append(
            {
                "host": host,
                "port": port,
                "payload": payload,
                "connected": connected,
            }
        )
        if not self._replies:
            return UdpExchange(
                data=b"",
                peer_host="",
                peer_port=0,
                rtt_ms=0.0,
                error="timed out",
            )
        reply = self._replies.pop(0)
        return UdpExchange(
            data=reply.data,
            peer_host="" if reply.error else self.peer_host,
            peer_port=0 if reply.error else reply.peer_port,
            rtt_ms=reply.rtt_ms,
            error=reply.error,
        )

    def udp_exchange(
        self,
        host: str,
        port: int,
        payload: bytes,
        *,
        connected: bool = False,
        timeout: float | None = None,
        max_bytes: int = 4096,
    ) -> UdpExchange:
        del timeout, max_bytes
        return self._next(host, port, payload, connected=connected)

    def udp_exchange_to(
        self,
        host: str,
        peer_port: int,
        payload: bytes,
        *,
        timeout: float | None = None,
        max_bytes: int = 4096,
    ) -> UdpExchange:
        del timeout, max_bytes
        return self._next(host, peer_port, payload, connected=False)

    @contextmanager
    def patch(self, target: str = "honeypot_auditor.netutil") -> Iterator[MockUDPTransceiver]:
        """Patch ``udp_exchange`` / ``udp_exchange_to`` on ``target`` (module path).

        Uses ``create=True`` so protocol modules that only import ``udp_exchange``
        still patch cleanly.
        """
        with (
            patch(f"{target}.udp_exchange", side_effect=self.udp_exchange, create=True),
            patch(f"{target}.udp_exchange_to", side_effect=self.udp_exchange_to, create=True),
        ):
            yield self


@pytest.fixture
def mock_udp_cls() -> type[MockUDPTransceiver]:
    """Expose ``MockUDPTransceiver`` to tests without package imports."""
    return MockUDPTransceiver


@pytest.fixture
def scripted_reply_cls() -> type[ScriptedReply]:
    """Expose ``ScriptedReply`` to tests without package imports."""
    return ScriptedReply
