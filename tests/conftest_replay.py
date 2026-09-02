"""Offline socket replay fixtures."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "replays"


@pytest.fixture
def replay_socket(monkeypatch):
    """Patch socket.create_connection to replay recorded streams."""

    class ReplaySocket:
        def __init__(self, response: bytes, recv_first: bool = False):
            self._response = response
            self._sent = b""
            self._recv_first = recv_first
            self._closed = False

        def sendall(self, data: bytes) -> None:
            self._sent += data

        def recv(self, n: int) -> bytes:
            if self._closed:
                return b""
            if self._recv_first and not self._sent:
                chunk, self._response = self._response[:n], self._response[n:]
                return chunk
            chunk, self._response = self._response[:n], self._response[n:]
            return chunk

        def settimeout(self, _t: float) -> None:
            pass

        def setsockopt(self, *args) -> None:
            pass

        def getsockname(self):
            return ("127.0.0.1", 50000)

        def close(self) -> None:
            self._closed = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def _load(name: str) -> dict:
        return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

    def _install(name: str):
        spec = _load(name)
        session_specs = iter(spec.get("sessions", [spec]))

        def fake_connect(addr, timeout=None):
            _ = (addr, timeout)
            session = next(session_specs)
            if "response_text" in session:
                response = session["response_text"].encode("latin-1")
            else:
                response = bytes.fromhex(session["response_hex"])
            return ReplaySocket(response, recv_first=session.get("recv_first", False))

        monkeypatch.setattr(socket, "create_connection", fake_connect)

    return _install
