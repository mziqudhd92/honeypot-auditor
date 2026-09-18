"""UDP probe engine contract and package discovery."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass

from honeypot_auditor.models import Indicator

ProbeFn = Callable[[str, int], list[Indicator]]


@dataclass(frozen=True)
class UDPEngine:
    """Metadata + probe callable for a UDP protocol module under ``probes.udp``."""

    name: str
    probe: ProbeFn


def discover_udp_engines() -> list[UDPEngine]:
    """Load ``probes.udp.*`` modules that export ``UDP_ENGINE``.

    Skips ``_``-prefixed modules (helpers such as ``_engine``). Protocol modules
    declare ``UDP_ENGINE = UDPEngine(name=..., probe=...)``. Ports and scoring
    strategies stay in ``config`` (no reverse import).
    """
    import honeypot_auditor.probes.udp as udp_pkg

    engines: list[UDPEngine] = []
    prefix = udp_pkg.__name__ + "."
    for info in pkgutil.iter_modules(udp_pkg.__path__):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(prefix + info.name)
        engine = getattr(module, "UDP_ENGINE", None)
        if isinstance(engine, UDPEngine):
            engines.append(engine)
            continue
        # Fallback: probe_<name> matching the module stem.
        probe = getattr(module, f"probe_{info.name}", None)
        if callable(probe):
            engines.append(UDPEngine(name=info.name, probe=probe))
    return engines
