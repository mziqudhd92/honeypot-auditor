"""Port presets, target expansion, and scan-address helpers."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Mapping

PORT_PRESET_IANA: dict[str, int] = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "http": 80,
    "pop3": 110,
    "imap": 143,
    "smb": 445,
    "sip": 5060,
    "vnc": 5900,
    "redis": 6379,
    "mysql": 3306,
    "postgres": 5432,
    "git": 9418,
    "rdp": 3389,
    "httpproxy": 3128,
    "mssql": 1433,
    "mongodb": 27017,
}

PORT_PRESET_DOCKER_RESEARCH: dict[str, int] = {
    "ftp": 2121,
    "ssh": 2222,
    "telnet": 2323,
    "smtp": 2525,
    "http": 8081,
    "pop3": 1110,
    "imap": 1143,
    "smb": 1445,
    "sip": 5060,
    "vnc": 5000,
    "redis": 6379,
    "mysql": 3306,
    "postgres": 5432,
    "git": 9418,
    "rdp": 3389,
    "httpproxy": 8080,
    "mssql": 1433,
    "mongodb": 27017,
}

PORT_PRESETS: dict[str, dict[str, int]] = {
    "iana": PORT_PRESET_IANA,
    "docker-research": PORT_PRESET_DOCKER_RESEARCH,
}

DEFAULT_PORT_PRESET = "both"
PORT_PRESET_CHOICES = ("both", "iana", "docker-research")

_EXTRA_PORT_PROTOCOLS: dict[int, str] = {
    139: "smb",
    443: "http",
    993: "imap",
    8080: "httpproxy",
    8443: "http",
    5061: "sip",
    5000: "vnc",
    5901: "vnc",
}


def _well_known_port_protocols() -> dict[int, str]:
    mapping: dict[int, str] = dict(_EXTRA_PORT_PROTOCOLS)
    for proto, port in PORT_PRESET_IANA.items():
        mapping[port] = proto
    for proto, port in PORT_PRESET_DOCKER_RESEARCH.items():
        mapping[port] = proto
    return mapping


WELL_KNOWN_PORT_PROTOCOLS = _well_known_port_protocols()

MAX_SUBNET_PREFIX_IPV4 = 24
MAX_SUBNET_HOSTS = 256
DEFAULT_SCAN_CONCURRENCY = 8


def _require_tcp_port(port: int, *, label: str = "port") -> int:
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid {label} {port}")
    return port


def parse_port_overrides(spec: str) -> dict[str, int]:
    out: dict[str, int] = {}
    if not spec:
        return out
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"invalid --ports item {part!r}; expected proto=port")
        name, raw = part.split("=", 1)
        name = name.strip().lower()
        port = _require_tcp_port(int(raw.strip()), label=f"port for {name}")
        out[name] = port
    return out


def parse_port_numbers(spec: str) -> list[int]:
    """Parse ``22`` or ``22,2222`` into TCP port numbers."""
    out: list[int] = []
    if not spec:
        return out
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part, 10)
        except ValueError as exc:
            raise ValueError(f"invalid --port value {part!r}") from exc
        out.append(_require_tcp_port(port))
    if not out:
        raise ValueError("empty --port value")
    return out


def protocol_for_port(port: int) -> str:
    """Map a TCP port to a probe protocol. Unknown numbers are treated as SSH."""
    return WELL_KNOWN_PORT_PROTOCOLS.get(int(port), "ssh")


def as_port_list(
    value: int | list[int] | tuple[int, ...] | None, default: int | list[int] | None = None
) -> list[int]:
    if value is None:
        value = default
    if value is None:
        return []
    if isinstance(value, int):
        return [value]
    return [int(p) for p in value]


def all_tcp_ports(ports: Mapping[str, int | list[int]]) -> list[int]:
    seen: list[int] = []
    for value in ports.values():
        for port in as_port_list(value):
            if port not in seen:
                seen.append(port)
    return seen


def protocol_by_port(ports: Mapping[str, int | list[int]]) -> dict[int, str]:
    mapping: dict[int, str] = {}
    for name, value in ports.items():
        for port in as_port_list(value):
            mapping[int(port)] = name
    return mapping


def _unique_ports(*ports: int) -> list[int]:
    seen: list[int] = []
    for port in ports:
        if port not in seen:
            seen.append(port)
    return seen


def probe_port_map(
    preset: str = DEFAULT_PORT_PRESET,
    overrides: Mapping[str, int] | None = None,
    extra_ports: list[int] | None = None,
) -> dict[str, list[int]]:
    """
    Ports to probe per protocol.

    ``both`` (default) unions IANA well-known ports with docker/lab aliases
    (SSH 22 and 2222, HTTP 80 and 8081, …). ``--ports proto=N`` replaces that
    protocol's list. ``-p/--port`` is nmap-style: **only** those numbers are
    scanned (preset is ignored). Well-known numbers map to a protocol;
    unknown ports are probed as SSH.
    """
    if extra_ports:
        ports: dict[str, list[int]] = {}
        for port in extra_ports:
            port = _require_tcp_port(int(port))
            proto = protocol_for_port(port)
            current = ports.setdefault(proto, [])
            if port not in current:
                current.append(port)
    elif preset == "both":
        ports = {
            proto: _unique_ports(PORT_PRESET_IANA[proto], PORT_PRESET_DOCKER_RESEARCH[proto])
            for proto in PORT_PRESET_IANA
        }
    elif preset in PORT_PRESETS:
        ports = {proto: [port] for proto, port in PORT_PRESETS[preset].items()}
    else:
        raise ValueError(f"unknown preset {preset!r}; choose from {PORT_PRESET_CHOICES}")
    if not extra_ports and preset in ("both", "iana"):
        http_ports = ports.get("http")
        if http_ports is not None and 443 not in http_ports:
            http_ports.append(443)
    if overrides:
        for name, port in overrides.items():
            ports[name] = [_require_tcp_port(int(port), label=f"port for {name}")]
    return ports


def merge_ports(preset: str, overrides: Mapping[str, int] | None = None) -> dict[str, int]:
    if preset == "both":
        raise ValueError("merge_ports() is single-port only; use probe_port_map('both')")
    if preset not in PORT_PRESETS:
        raise ValueError(f"unknown preset {preset!r}; choose from {sorted(PORT_PRESETS)}")
    ports = dict(PORT_PRESETS[preset])
    if overrides:
        ports.update(overrides)
    return ports


def resolve_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("target is empty")
    if "/" in target:
        raise ValueError(
            "target looks like a CIDR subnet; use expand_scan_targets() or pass a single IP/hostname"
        )
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)


def expand_scan_targets(target: str) -> tuple[str, list[str]]:
    """
    Expand --target to one or more probe addresses.

    Returns (scan_kind, addresses) where scan_kind is ``host`` or ``subnet``.
    Single IPs and hostnames resolve to one address. IPv4 CIDR up to /24 expands
    to host addresses (network/broadcast omitted when applicable).
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("target is empty")

    if "/" not in target:
        return "host", [resolve_target(target)]

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR target {target!r}: {exc}") from exc

    if network.version != 4:
        raise ValueError("subnet scans support IPv4 CIDR only")

    if network.prefixlen < MAX_SUBNET_PREFIX_IPV4:
        raise ValueError(
            f"subnet {target} is too large; maximum allowed prefix is /{MAX_SUBNET_PREFIX_IPV4}"
        )

    if network.num_addresses > MAX_SUBNET_HOSTS:
        raise ValueError(
            f"subnet {target} has {network.num_addresses} addresses; "
            f"maximum is {MAX_SUBNET_HOSTS} (/{MAX_SUBNET_PREFIX_IPV4})"
        )

    hosts = [str(addr) for addr in network.hosts()]
    if not hosts and network.num_addresses <= 2:
        hosts = [str(addr) for addr in network]
    if not hosts:
        raise ValueError(f"subnet {target} has no scannable host addresses")

    return "subnet", hosts


def is_private_or_loopback(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
