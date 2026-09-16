"""Socket helpers with configurable timeouts."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass

from honeypot_auditor.proxy_transport import create_connection
from honeypot_auditor.settings import settings

_PASV_RE = re.compile(r"(\d+,\d+,\d+,\d+,\d+,\d+)")


@dataclass(frozen=True)
class UdpExchange:
    """One UDP request/response with peer addressing and timing evidence."""

    data: bytes
    peer_host: str
    peer_port: int
    rtt_ms: float
    error: str


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


def udp_exchange(
    host: str,
    port: int,
    payload: bytes,
    *,
    connected: bool = False,
    timeout: float | None = None,
    max_bytes: int = 4096,
) -> UdpExchange:
    """Send one datagram and capture the reply, peer port, and RTT.

    Default is unconnected ``sendto``/``recvfrom`` so the peer source port is
    learned (required for TFTP TID follow-ups). Set ``connected=True`` when an
    ICMP port-unreachable mapping is more useful than peer-port learning.
    """
    if timeout is None:
        timeout = settings.timeout_seconds
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        started = time.perf_counter()
        if connected:
            sock.connect((host, port))
            sock.send(payload)
            data = sock.recv(max_bytes)
            peer_host, peer_port = host, port
        else:
            sock.sendto(payload, (host, port))
            data, addr = sock.recvfrom(max_bytes)
            peer_host, peer_port = addr[0], int(addr[1])
        rtt_ms = (time.perf_counter() - started) * 1000.0
        return UdpExchange(
            data=data,
            peer_host=peer_host,
            peer_port=peer_port,
            rtt_ms=rtt_ms,
            error="",
        )
    except OSError as exc:
        return UdpExchange(
            data=b"",
            peer_host="",
            peer_port=0,
            rtt_ms=0.0,
            error=str(exc),
        )
    finally:
        sock.close()


def udp_exchange_to(
    host: str,
    peer_port: int,
    payload: bytes,
    *,
    timeout: float | None = None,
    max_bytes: int = 4096,
) -> UdpExchange:
    """Follow-up exchange to a learned peer port (e.g. TFTP TID)."""
    return udp_exchange(
        host,
        peer_port,
        payload,
        connected=False,
        timeout=timeout,
        max_bytes=max_bytes,
    )


def udp_transact(
    host: str,
    port: int,
    payload: bytes,
    *,
    timeout: float | None = None,
    max_bytes: int = 4096,
) -> tuple[bytes, str]:
    """Back-compat wrapper: ``(data, error)`` from :func:`udp_exchange`."""
    exchange = udp_exchange(
        host,
        port,
        payload,
        connected=False,
        timeout=timeout,
        max_bytes=max_bytes,
    )
    return exchange.data, exchange.error


def _recv(sock: socket.socket, timeout: float, max_bytes: int) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
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
    # Winsock WSAECONNRESET (10054) / "forcibly closed" — common for connected UDP
    # against a closed port on Windows (no ICMP port-unreachable).
    if "reset" in low or "10054" in low or "forcibly closed" in low:
        return "connection reset"
    return err
