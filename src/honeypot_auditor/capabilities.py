"""Runtime capability probing and graceful degradation."""

from __future__ import annotations

import importlib.util
import os
import socket
from dataclasses import dataclass, field


@dataclass
class Capabilities:
    raw_sockets: bool = False
    scapy_tls: bool = False
    pysocks: bool = False
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, bool]:
        return {
            "raw_sockets": self.raw_sockets,
            "scapy_tls": self.scapy_tls,
            "pysocks": self.pysocks,
        }


def _probe_raw_socket() -> bool:
    if os.geteuid() == 0:
        return True
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.close()
        return True
    except OSError:
        return False


def probe_capabilities() -> Capabilities:
    """Probe optional dependencies and privileges at engine boot."""
    raw_ok = _probe_raw_socket()
    scapy_ok = importlib.util.find_spec("scapy") is not None
    pysocks_ok = importlib.util.find_spec("socks") is not None
    warnings: list[str] = []
    if not raw_ok:
        warnings.append("raw_sockets_disabled")
    if not scapy_ok:
        warnings.append("scapy_unavailable")
    elif not raw_ok:
        warnings.append("scapy_tls_limited")
    return Capabilities(
        raw_sockets=raw_ok,
        scapy_tls=scapy_ok and raw_ok,
        pysocks=pysocks_ok,
        warnings=warnings,
    )
