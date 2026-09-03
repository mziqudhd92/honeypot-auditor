"""Offline socket replay fixtures."""

from __future__ import annotations

import io
import json
import socket
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "replays"


@pytest.fixture
def replay_socket(monkeypatch):
    """Patch socket.create_connection to replay recorded streams."""

    class ReplaySocket:
        def __init__(self, response: bytes, recv_first: bool = False, peer_port: int = 0):
            self._response = bytearray(response)
            self._sent = b""
            self._recv_first = recv_first
            self._closed = False
            self._peer_port = int(peer_port) if peer_port else 0
            self.family = socket.AF_INET
            self.type = socket.SOCK_STREAM
            self.proto = 0

        def sendall(self, data: bytes) -> None:
            self._sent += data

        def send(self, data: bytes) -> int:
            self.sendall(data)
            return len(data)

        def recv(self, n: int) -> bytes:
            if self._closed:
                return b""
            # Client-first protocols (HTTP/TLS): wait until something was sent.
            if not self._recv_first and not self._sent:
                return b""
            chunk = bytes(self._response[:n])
            del self._response[:n]
            return chunk

        def makefile(self, mode="r", buffering=None, *, encoding=None, errors=None, newline=None):
            """ftplib/readline path — expose remaining response as a file object.

            Consumes the remaining buffer into an independent stream (FTP safe-mode).
            Do not mix makefile() with later recv() on the same session.
            """
            _ = buffering
            data = bytes(self._response)
            self._response.clear()
            raw = io.BytesIO(data)
            if "b" in mode:
                return raw
            return io.TextIOWrapper(
                raw,
                encoding=encoding or "utf-8",
                errors=errors or "replace",
                newline=newline,
            )

        def settimeout(self, _t: float) -> None:
            pass

        def setsockopt(self, *args) -> None:
            pass

        def getsockname(self):
            return ("127.0.0.1", 50000)

        def getpeername(self):
            return ("127.0.0.1", self._peer_port or 0)

        def fileno(self) -> int:
            return -1

        def shutdown(self, _how: int) -> None:
            pass

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
        default_recv_first = bool(spec.get("recv_first", False))
        session_specs = iter(spec.get("sessions", [spec]))

        def fake_connect(addr, timeout=None, source_address=None):
            _ = (timeout, source_address)
            peer_port = 0
            if isinstance(addr, tuple) and len(addr) >= 2 and isinstance(addr[1], int):
                peer_port = addr[1]
            session = next(session_specs)
            if "response_text" in session:
                response = session["response_text"].encode("latin-1")
            else:
                response = bytes.fromhex(session["response_hex"])
            recv_first = bool(session.get("recv_first", default_recv_first))
            return ReplaySocket(response, recv_first=recv_first, peer_port=peer_port)

        monkeypatch.setattr(socket, "create_connection", fake_connect)

    return _install
