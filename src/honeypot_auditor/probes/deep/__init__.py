"""Orchestrate all six deep detection axes."""

from __future__ import annotations

from honeypot_auditor.config import as_port_list
from honeypot_auditor.models import Indicator
from honeypot_auditor.probes.deep.behavior import (
    probe_auth_curve,
    probe_shell_semantics,
    probe_telnet_shell_semantics,
)
from honeypot_auditor.probes.deep.coherence import probe_os_coherence
from honeypot_auditor.probes.deep.cotenancy import probe_cotenancy
from honeypot_auditor.probes.deep.fsm import (
    probe_ftp_fsm,
    probe_http_fsm,
    probe_smtp_fsm,
    probe_telnet_fsm,
)
from honeypot_auditor.probes.deep.stack import (
    probe_banner_vs_stack,
    probe_hassh,
    probe_tcp_stack,
    probe_tls_ja4s,
)
from honeypot_auditor.probes.deep.smb import probe_smb_negotiate, probe_smb_target_mismatch
from honeypot_auditor.probes.deep.temporal import (
    probe_egress_silence,
    probe_idle_accept,
    probe_latency_distribution,
)


def _stamp(indicators: list[Indicator], proto: str, port: int) -> list[Indicator]:
    for ind in indicators:
        current = ind.protocol or proto
        if ":" not in current:
            ind.protocol = f"{current}:{port}"
    return indicators


def run_deep_probes(host: str, ports: dict[str, int | list[int]], *, corroboration: bool = False) -> list[Indicator]:
    ssh_ports = as_port_list(ports.get("ssh"))
    telnet_ports = as_port_list(ports.get("telnet"))
    http_ports = as_port_list(ports.get("http"))
    ftp_ports = as_port_list(ports.get("ftp"))
    smtp_ports = as_port_list(ports.get("smtp"))
    smb_ports = as_port_list(ports.get("smb"))

    out: list[Indicator] = []
    for ssh_port in ssh_ports:
        out.extend(_stamp(probe_shell_semantics(host, ssh_port), "ssh", ssh_port))
        out.extend(_stamp(probe_auth_curve(host, ssh_port), "ssh", ssh_port))
        out.extend(_stamp(probe_os_coherence(host, ssh_port), "ssh", ssh_port))
        out.extend(_stamp(probe_hassh(host, ssh_port), "ssh", ssh_port))
        out.extend(_stamp(probe_tcp_stack(host, ssh_port), "tcp", ssh_port))
        out.extend(_stamp(probe_latency_distribution(host, ssh_port), "tcp", ssh_port))
        out.extend(_stamp(probe_idle_accept(host, ssh_port), "tcp", ssh_port))
        out.extend(_stamp(probe_egress_silence(host, ssh_port), "ssh", ssh_port))
    for telnet_port in telnet_ports:
        out.extend(_stamp(probe_telnet_shell_semantics(host, telnet_port), "telnet", telnet_port))
        out.extend(_stamp(probe_telnet_fsm(host, telnet_port), "telnet", telnet_port))
        out.extend(_stamp(probe_banner_vs_stack(host, telnet_port), "tcp", telnet_port))
    for http_port in http_ports:
        if http_port in (443, 8443):
            out.extend(_stamp(probe_tls_ja4s(host, http_port), "tls", http_port))
        out.extend(_stamp(probe_http_fsm(host, http_port), "http", http_port))
    for ftp_port in ftp_ports:
        out.extend(_stamp(probe_ftp_fsm(host, ftp_port), "ftp", ftp_port))
    for smtp_port in smtp_ports:
        out.extend(_stamp(probe_smtp_fsm(host, smtp_port), "smtp", smtp_port))
        out.extend(_stamp(probe_banner_vs_stack(host, smtp_port), "tcp", smtp_port))
    for smb_port in smb_ports:
        out.extend(_stamp(probe_smb_negotiate(host, smb_port), "smb", smb_port))
        out.extend(_stamp(probe_smb_target_mismatch(host, smb_port), "smb", smb_port))
    out.extend(probe_cotenancy(host, ports, corroboration=corroboration))
    return out
