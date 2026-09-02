"""Explicit opt-in entry points for passive intelligence providers."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.redact import redact

IntelProvider = Callable[[str, str | None], list[Indicator]]
_ENTRY_POINT_GROUP = "honeypot_auditor.intel"
_PROVIDER_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_registry: dict[str, IntelProvider] = {}
_log = logging.getLogger(__name__)


def validate_intel_provider_name(name: str) -> str:
    normalized = (name or "").strip().lower()
    if not _PROVIDER_NAME.fullmatch(normalized):
        raise ValueError(
            "intel provider names must use 1-64 lowercase letters, digits, hyphens, or underscores"
        )
    return normalized


def register_intel_provider(name: str, provider: IntelProvider) -> None:
    """Register an in-process provider (primarily for embedded SDK use)."""
    normalized = validate_intel_provider_name(name)
    if not callable(provider):
        raise TypeError("intel provider must be callable")
    _registry[normalized] = provider


def _entry_points() -> list[Any]:
    from importlib.metadata import entry_points

    return list(entry_points(group=_ENTRY_POINT_GROUP))


def get_intel_provider(name: str) -> IntelProvider:
    """Load exactly one named provider; unrelated plugins are never imported."""
    normalized = validate_intel_provider_name(name)
    if normalized in _registry:
        return _registry[normalized]
    for entry_point in _entry_points():
        if entry_point.name.lower() != normalized:
            continue
        provider = entry_point.load()
        if not callable(provider):
            raise TypeError(f"intel provider {normalized!r} is not callable")
        return provider
    raise LookupError(f"intel provider {normalized!r} is not installed")


def _safe_error(exc: Exception, api_key: str | None) -> str:
    detail = str(exc).strip() or type(exc).__name__
    if api_key:
        detail = detail.replace(api_key, "[REDACTED]")
    return redact(detail)[0]


def run_intel_provider(name: str, ip: str, api_key: str | None = None) -> list[Indicator]:
    """Run one selected provider and validate its scoring contract."""
    normalized = validate_intel_provider_name(name)
    protocol = f"intel:{normalized}"
    try:
        provider = get_intel_provider(normalized)
        result = provider(ip, api_key)
        if not isinstance(result, list) or not all(isinstance(ind, Indicator) for ind in result):
            raise TypeError("provider must return list[Indicator]")
        for ind in result:
            if ind.category not in {"shodan", "info"}:
                raise ValueError("provider indicators must use the 'shodan' or 'info' category")
            if not ind.id.startswith(f"intel.{normalized}."):
                ind.id = f"intel.{normalized}.{ind.id}"
            ind.protocol = protocol
        return result
    except Exception as exc:
        detail = _safe_error(exc, api_key)
        _log.warning("intel provider %s unavailable: %s", normalized, detail)
        return [
            skipped_indicator(
                f"intel.{normalized}.unavailable",
                f"Passive intelligence provider {normalized}",
                "shodan",
                detail,
                protocol=protocol,
                error=detail,
            )
        ]


__all__ = [
    "IntelProvider",
    "get_intel_provider",
    "register_intel_provider",
    "run_intel_provider",
    "validate_intel_provider_name",
]
