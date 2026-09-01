"""Runtime settings (set once per CLI invocation)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from honeypot_auditor.capabilities import Capabilities, probe_capabilities


class ProbeProfile(str, Enum):
    AUDIT = "audit"
    BLEND = "blend"
    SAFE = "safe"


@dataclass
class Settings:
    timeout_seconds: float = 3.0
    deep: bool = False
    profile: ProbeProfile = ProbeProfile.AUDIT
    safe_mode: bool = False
    proxy_url: str = ""
    proxy_allow_local_dns: bool = False
    passive_first: bool = False
    osint_only: bool = False
    dual_stack: bool = False
    jitter_fraction: float = 0.0
    jitter_ms_range: tuple[int, int] | None = None
    max_concurrent: int = 32
    seed: int | None = None
    output_nmap_exclude: str = ""
    signature_pack: str = "core"
    output_format: str = "json"
    capabilities: Capabilities = field(default_factory=probe_capabilities)


settings = Settings()
