"""SOCKS5 proxy transport with remote DNS enforcement."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

from honeypot_auditor.settings import settings

_PROXY_SCHEME = re.compile(r"^socks5h?://", re.I)


def normalize_proxy_url(url: str, target_host: str, *, allow_local_dns: bool = False) -> str:
    """Normalize proxy URL; enforce socks5h for hostname targets."""
    if not url:
        return ""
    parsed = urlparse(url if _PROXY_SCHEME.match(url) else f"socks5h://{url}")
    scheme = (parsed.scheme or "socks5h").lower()
    host = parsed.hostname or ""
    port = parsed.port or 1080
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    if scheme == "socks5" and not is_ip and not allow_local_dns:
        raise ValueError(
            "socks5:// with hostname target leaks DNS — use socks5h:// or pass --proxy-allow-local-dns"
        )
    if scheme == "socks5" and not is_ip:
        scheme = "socks5h"
    return f"{scheme}://{userinfo}{host}:{port}"


def resolve_proxy_url(target_host: str) -> str:
    """Return normalized proxy URL from settings, or empty."""
    raw = settings.proxy_url
    if not raw:
        return ""
    return normalize_proxy_url(
        raw,
        target_host,
        allow_local_dns=settings.proxy_allow_local_dns,
    )


def configure_requests_proxy() -> dict[str, str]:
    """Return requests-compatible proxy dict from settings."""
    if not settings.proxy_url:
        return {}
    url = normalize_proxy_url(
        settings.proxy_url,
        "127.0.0.1",
        allow_local_dns=settings.proxy_allow_local_dns,
    )
    return {"http": url, "https": url}


def create_connection(
    host: str,
    port: int,
    timeout: float,
) -> socket.socket:
    """TCP connect, optionally via configured SOCKS5 proxy."""
    proxy_url = resolve_proxy_url(host)
    if not proxy_url:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock
    require_pysocks()
    import socks  # type: ignore[import-untyped]

    parsed = urlparse(proxy_url)
    scheme = parsed.scheme.lower()
    remote_dns = scheme == "socks5h"
    proxy_host = parsed.hostname or "127.0.0.1"
    proxy_port = parsed.port or 1080
    sock = socks.socksocket()
    sock.set_proxy(
        socks.SOCKS5,
        proxy_host,
        proxy_port,
        rdns=remote_dns,
        username=parsed.username,
        password=parsed.password,
    )
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def wrap_tls(sock: socket.socket, host: str) -> socket.socket:
    """Wrap an already-connected socket in TLS (cert verify disabled for probes)."""
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(sock, server_hostname=host or None)
    tls.settimeout(sock.gettimeout())
    return tls


def create_tls_connection(host: str, port: int, timeout: float) -> socket.socket:
    """TCP connect then TLS handshake (for IMAPS/MQTTS-style implicit TLS ports)."""
    sock = create_connection(host, port, timeout)
    try:
        return wrap_tls(sock, host)
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


def paramiko_proxy_sock(host: str, port: int, timeout: float) -> socket.socket | None:
    """Socket for Paramiko when proxy configured."""
    if not settings.proxy_url:
        return None
    return create_connection(host, port, timeout)


def require_pysocks() -> None:
    try:
        import socks  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "PySocks required for --proxy (pip install 'honeypot-auditor[full]')"
        ) from exc
