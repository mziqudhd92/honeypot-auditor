"""Socket helpers with configurable timeouts."""

from __future__ import annotations

import socket

from honeypot_auditor.settings import settings


def tcp_transact(
    host: str,
    port: int,
    payload: bytes = b"",
    *,
    recv_first: bool = False,
    timeout: float | None = None,
    max_bytes: int = 65535,
) -> tuple[bytes, str]:
    if timeout is None:
        timeout = settings.timeout_seconds
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = _recv(sock, timeout, max_bytes) if recv_first else b""
            if payload:
                sock.sendall(payload)
                data += _recv(sock, timeout, max_bytes)
            return data, ""
    except OSError as exc:
        return b"", str(exc)


def udp_transact(
    host: str,
    port: int,
    payload: bytes,
    *,
    timeout: float | None = None,
    max_bytes: int = 4096,
) -> tuple[bytes, str]:
    if timeout is None:
        timeout = settings.timeout_seconds
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        data, _addr = sock.recvfrom(max_bytes)
        return data, ""
    except OSError as exc:
        return b"", str(exc)
    finally:
        sock.close()


def _recv(sock: socket.socket, timeout: float, max_bytes: int) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    try:
        while sum(len(c) for c in chunks) < max_bytes:
            buf = sock.recv(4096)
            if not buf:
                break
            chunks.append(buf)
            sock.settimeout(min(0.4, timeout))
    except TimeoutError:
        pass
    return b"".join(chunks)


def closed_reason(err: str) -> str:
    if not err:
        return "no response"
    low = err.lower()
    if "refused" in low:
        return "connection refused (closed port or filtered)"
    if "timed out" in low or "timeout" in low:
        return "timeout"
    if "reset" in low:
        return "connection reset"
    return err
