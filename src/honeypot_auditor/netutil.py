"""Socket helpers with configurable timeouts."""

from __future__ import annotations

import ipaddress
import re
import socket

from honeypot_auditor.proxy_transport import create_connection
from honeypot_auditor.settings import settings

_PASV_RE = re.compile(r"(\d+,\d+,\d+,\d+,\d+,\d+)")


def parse_ftp_pasv_host(response: str) -> str | None:
    m = _PASV_RE.search(response or "")
    if not m:
        return None
    octets = [int(x) for x in m.group(1).split(",")]
    if len(octets) < 4:
        return None
    return ".".join(str(x) for x in octets[:4])


def is_non_routable_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


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
        with create_connection(host, port, timeout) as sock:
            data = _recv(sock, timeout, max_bytes) if recv_first else b""
            if payload:
                sock.sendall(payload)
                data += _recv(sock, timeout, max_bytes)
            return data, ""
    except (OSError, ImportError) as exc:
        return b"", str(exc)


def tcp_roundtrips(
    host: str,
    port: int,
    payloads: list[bytes],
    *,
    recv_first: bool = False,
    timeout: float | None = None,
    max_bytes: int = 65535,
) -> tuple[list[bytes], str]:
    """Same TCP session: optional greeting, then each payload followed by a recv."""
    if timeout is None:
        timeout = settings.timeout_seconds
    replies: list[bytes] = []
    try:
        with create_connection(host, port, timeout) as sock:
            if recv_first:
                replies.append(_recv(sock, timeout, max_bytes))
            for payload in payloads:
                if payload:
                    sock.sendall(payload)
                replies.append(_recv(sock, timeout, max_bytes))
            return replies, ""
    except (OSError, ImportError) as exc:
        return replies, str(exc)


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
