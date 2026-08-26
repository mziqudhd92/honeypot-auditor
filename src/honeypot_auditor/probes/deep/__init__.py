"""Orchestrate all six deep detection axes."""

from __future__ import annotations

from honeypot_auditor.models import Indicator
from honeypot_auditor.probes.deep.behavior import (
    probe_auth_curve,
    probe_shell_semantics,
    probe_telnet_shell_semantics,
)
from honeypot_auditor.probes.deep.coherence import probe_os_coherence
from honeypot_auditor.probes.deep.cotenancy import probe_cotenancy
from honeypot_auditor.probes.deep.fsm import probe_ftp_fsm, probe_http_fsm, probe_smtp_fsm
from honeypot_auditor.probes.deep.stack import probe_hassh, probe_tcp_stack, probe_tls_ja4s
from honeypot_auditor.probes.deep.temporal import probe_egress_silence, probe_latency_distribution


def run_deep_probes(host: str, ports: dict[str, int], *, corroboration: bool = False) -> list[Indicator]:
    ssh_port = ports.get("ssh", 22)
    telnet_port = ports.get("telnet", 23)
    http_port = ports.get("http", 80)
    ftp_port = ports.get("ftp", 21)
    smtp_port = ports.get("smtp", 25)

    out: list[Indicator] = []
    # 1 — execution semantics + auth curve (behavior/temporal)
    out.extend(probe_shell_semantics(host, ssh_port))
    out.extend(probe_telnet_shell_semantics(host, telnet_port))
    out.extend(probe_auth_curve(host, ssh_port))
    # 2 — OS coherence
    out.extend(probe_os_coherence(host, ssh_port))
    # 3 — stack fingerprinting
    out.extend(probe_hassh(host, ssh_port))
    out.extend(probe_tcp_stack(host, ssh_port))
    if http_port in (443, 8443):
        out.extend(probe_tls_ja4s(host, http_port))
    # 4 — protocol FSM
    out.extend(probe_http_fsm(host, http_port))
    out.extend(probe_ftp_fsm(host, ftp_port))
    out.extend(probe_smtp_fsm(host, smtp_port))
    # 5 — co-tenancy (corroboration applied in analyzer pass)
    out.extend(probe_cotenancy(host, ports, corroboration=corroboration))
    # 6 — temporal
    out.extend(probe_latency_distribution(host, ssh_port))
    out.extend(probe_egress_silence(host, ssh_port))
    return out
