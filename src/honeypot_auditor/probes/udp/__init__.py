"""UDP protocol engines (TFTP shipped; DNS / NTP land in follow-up PRs).

Discovery loads non-``_``-prefixed submodules that export ``UDP_ENGINE`` (or
``probe_<name>``) and merges them into top-level ``PROBE_BY_PROTOCOL``.
"""

from __future__ import annotations

from honeypot_auditor.probes.udp._engine import UDPEngine, discover_udp_engines

__all__ = [
    "UDPEngine",
    "discover_udp_engines",
]
