"""Programmatic audit engine (Python SDK)."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field

from honeypot_auditor.capabilities import probe_capabilities
from honeypot_auditor.cli import _audit_host, _flatten_extra_ports
from honeypot_auditor.config import (
    DEFAULT_PORT_PRESET,
    DEFAULT_TIMEOUT_SECONDS,
    expand_scan_targets,
    is_private_or_loopback,
    parse_port_overrides,
    probe_port_map,
)
from honeypot_auditor.models import AuditReport
from honeypot_auditor.reporters.json_export import export, export_nmap_exclude
from honeypot_auditor.settings import ProbeProfile, settings


@dataclass
class Auditor:
    target: str
    preset: str = DEFAULT_PORT_PRESET
    port_overrides: str = ""
    extra_ports: list[str] = field(default_factory=list)
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    deep: bool = False
    profile: ProbeProfile = ProbeProfile.AUDIT
    safe_mode: bool = False
    proxy: str = ""
    confirm_authorized: bool = False
    output: str = ""
    output_nmap_exclude: str = ""
    intel_providers: list[str] = field(default_factory=list)
    intel_keys: dict[str, str] = field(default_factory=dict, repr=False)

    def _apply_settings(self) -> None:
        settings.timeout_seconds = float(self.timeout)
        settings.deep = bool(self.deep) and not self.safe_mode
        settings.profile = ProbeProfile.SAFE if self.safe_mode else self.profile
        settings.safe_mode = self.safe_mode
        settings.proxy_url = self.proxy
        settings.capabilities = probe_capabilities()

    def _args_namespace(self) -> argparse.Namespace:
        return argparse.Namespace(
            target=self.target,
            preset=self.preset,
            ports=self.port_overrides,
            extra_ports=self.extra_ports,
            timeout=self.timeout,
            deep=settings.deep,
            with_nmap=False,
            shodan_key="",
            intel_provider=list(self.intel_providers),
            intel_key=[f"{name}={key}" for name, key in self.intel_keys.items()],
            confirm_authorized=self.confirm_authorized,
            output=self.output,
            scan_concurrency=8,
            safe_mode=self.safe_mode,
            profile=self.profile.value,
        )

    async def run_async(self) -> AuditReport:
        self._apply_settings()
        caps = settings.capabilities
        _, hosts = expand_scan_targets(self.target)
        ip = hosts[0]
        if not is_private_or_loopback(ip) and not self.confirm_authorized:
            raise PermissionError("Public target requires confirm_authorized=True")
        extra = _flatten_extra_ports(self.extra_ports)
        ports = probe_port_map(self.preset, parse_port_overrides(self.port_overrides), extra)
        args = self._args_namespace()
        report = await _audit_host(
            ip,
            args,
            ports,
            include_shodan=True,
            capabilities=caps.as_dict(),
            capability_warnings=caps.warnings,
        )
        if self.output:
            export(report, self.output)
        if self.output_nmap_exclude and report.score >= 60:
            export_nmap_exclude(report.resolved_ip, self.output_nmap_exclude)
        return report

    def run(self) -> AuditReport:
        return asyncio.run(self.run_async())
