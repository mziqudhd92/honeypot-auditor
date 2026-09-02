"""Plugin registration API for entry-point extensions."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

ProbeRegistry = dict[str, Callable[..., Any]]
_registry: ProbeRegistry = {}
_log = logging.getLogger(__name__)


def register_probe(name: str, fn: Callable[..., Any]) -> None:
    """Register a protocol probe callable."""
    _registry[name] = fn


def register_probes(registry: ProbeRegistry) -> None:
    """Bulk-register probes from a plugin module."""
    for name, fn in registry.items():
        register_probe(name, fn)


def load_plugins() -> ProbeRegistry:
    """Load honeypot_auditor.plugins entry points."""
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return dict(_registry)

    loaded = dict(_registry)
    eps = entry_points(group="honeypot_auditor.plugins")
    for ep in eps:
        try:
            register = ep.load()
            if callable(register):
                register(loaded)
        except Exception as exc:
            _log.warning("plugin %s failed to load: %s", ep.name, exc)
            continue
    return loaded


def get_registered_probes() -> ProbeRegistry:
    return load_plugins()
