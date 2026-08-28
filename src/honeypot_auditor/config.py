"""Scoring weights, timeouts, port presets, and signature corpus."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Mapping

from honeypot_auditor import __version__

USER_AGENT = f"honeypot-auditor/{__version__}"
DEFAULT_TIMEOUT_SECONDS = 3.0
NMAP_HOST_TIMEOUT = "45s"
SHODAN_HONEYSCORE_URL = "https://api.shodan.io/labs/honeyscore/{ip}"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_SCORE_THRESHOLD = 0.6

WEIGHTS: dict[str, float] = {
    "shodan": 0.25,
    "arbitrary_auth": 0.30,
    "state_nonpersist": 0.25,
    "static_signature": 0.20,
}

# Deep-mode categories (--deep). Sum adds to 0.75 atop basic weights when all fire.
DEEP_WEIGHTS: dict[str, float] = {
    "behavior": 0.18,
    "coherence": 0.15,
    "stack_fingerprint": 0.12,
    "proto_conformance": 0.12,
    "cotenancy": 0.08,
    "temporal": 0.10,
}

# Extra ports scanned for co-tenancy on deception / lab stacks.
EXTENDED_PROBE_PORTS: dict[str, int] = {
    "modbus": 1502,
    "snmp": 161,
    "dns": 15353,
    "ipp": 631,
    "pop": 1110,
}

# Categories that corroborate co-tenancy (avoid false positives on multi-decoy platforms).
COTENANCY_CORROBORATION_CATEGORIES = frozenset(
    {"arbitrary_auth", "behavior", "static_signature", "coherence", "stack_fingerprint"}
)

THREAT_CONFIRMED = 60.0
THREAT_SUSPECTED = 30.0

THREAT_LEVELS = {
    "confirmed": "Confirmed Honeypot",
    "suspected": "Suspected Honeypot",
    "likely_real": "Likely Real Host",
    "inconclusive": "Inconclusive",
}

PORT_PRESET_IANA: dict[str, int] = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "http": 80,
    "smb": 445,
    "sip": 5060,
    "vnc": 5900,
    "redis": 6379,
}

# Non-privileged ports common in Docker / lab compose stacks.
PORT_PRESET_DOCKER_RESEARCH: dict[str, int] = {
    "ftp": 2121,
    "ssh": 2222,
    "telnet": 2323,
    "smtp": 2525,
    "http": 8081,
    "smb": 1445,
    "sip": 5060,
    "vnc": 5900,
    "redis": 6379,
}

PORT_PRESETS: dict[str, dict[str, int]] = {
    "iana": PORT_PRESET_IANA,
    "docker-research": PORT_PRESET_DOCKER_RESEARCH,
}

NMAP_SCRIPTS = "banner,ssh2-enum-algos,ssh-auth-methods,ssh-publickey-acceptance"

# Prefer these when capping nmap -sV work (version scan is slow on many ports).
NMAP_PORT_PRIORITY = ("telnet", "ssh", "ftp", "http", "smb", "smtp", "vnc", "redis", "sip")
NMAP_MAX_OPEN_PORTS = 2

# Substrings in nmap service/product/version/script output that indicate emulators.
NMAP_HONEYPOT_TELLS = (
    "honeypot",
    "cowrie",
    "kippo",
    "dionaea",
    "conpot",
    "opencanary",
    "honeyd",
    "amun",
    "glastopf",
)

PROBE_USERNAME_TEMPLATE = "user_a{n}"
PROBE_PASSWORD_TEMPLATE = "pass_z{n}"
FTP_PROBE_PREFIX = "hpaudit_"
FTP_PROBE_BODY = b"hpaudit-state-probe\n"
FTP_WELCOME_TELLS = (
    "DiskStation FTP server",
    "dionaea",
    "honeypot ftp",
)
FTP_SYST_TELLS = (
    "215 UNIX Type: L8",
    "215 UNIX Type: L8 version",
)
HTTP_SERVER_TELLS = (
    "nginx",
)
HTTP_STATIC_BODY_MARKERS = (
    b"<html>",
    b"Welcome",
)
REDIS_PROBE_KEY_PREFIX = "hpaudit_"
REDIS_PROBE_VALUE = "probe_val"

SMTP_HELO = "auditor.invalid"
SMTP_MAIL_FROM = "probe@auditor.invalid"
SMTP_RCPT_TO = "fake_user@external-domain.com"

SSH_BANNER_SIGNATURES = (
    "SSH-2.0-OpenSSH_5.1p1 Debian-5",
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4",
)

UNAME_SIGNATURES = (
    "Linux <host> 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:08 UTC 2009 i686 GNU/Linux",
    "Linux <host> 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux",
    "Linux <host> 3.2.0-4-amd64 #1 SMP Debian 3.2.51-1 x86_64 GNU/Linux",
)

CPUINFO_TELLS = (
    "Intel(R) Core(TM)2 Duo CPU     T7300  @ 2.00GHz",
    "Intel(R) Core(TM)2 Duo CPU T7300 @ 2.00GHz",
)

SMB_SMB1_DIALECTS = frozenset({"NT LM 0.12", "SMB1", "1.0"})
SMB_NATIVE_OS_TELLS = ("Windows 5.0", "Windows 5.1", "Unix")
HTTP_DYNAMIC_HEADERS = ("date",)
SIP_UA_TELLS = ("honeypot", "sipuas", "friendly-scanner")

_UNAME_HOST_RE = re.compile(r"^Linux\s+\S+\s+")


def match_ssh_banner(banner: str) -> str | None:
    text = (banner or "").strip()
    for sig in SSH_BANNER_SIGNATURES:
        if sig in text:
            return sig
    return None


def normalize_uname(text: str) -> str:
    if not text:
        return ""
    lines = (text or "").strip().splitlines()
    if not lines:
        return ""
    line = lines[0]
    return _UNAME_HOST_RE.sub("Linux <host> ", line).strip()


def match_uname_signature(text: str) -> str | None:
    norm = normalize_uname(text)
    for sig in UNAME_SIGNATURES:
        if norm == sig:
            return sig
    return None


def match_cpuinfo_signature(text: str) -> str | None:
    blob = text or ""
    for tell in CPUINFO_TELLS:
        if tell in blob:
            return tell
    return None


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
        port = int(raw.strip())
        if not 1 <= port <= 65535:
            raise ValueError(f"invalid port {port} for {name}")
        out[name] = port
    return out


def merge_ports(preset: str, overrides: Mapping[str, int] | None = None) -> dict[str, int]:
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


# Largest allowed IPv4 scan: /24 (256 addresses). Smaller prefixes are rejected.
MAX_SUBNET_PREFIX_IPV4 = 24
MAX_SUBNET_HOSTS = 256
DEFAULT_SCAN_CONCURRENCY = 8


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
