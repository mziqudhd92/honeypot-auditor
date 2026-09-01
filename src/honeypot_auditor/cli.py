"""CLI entry point and async probe orchestration."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import socket
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from honeypot_auditor import __version__
from honeypot_auditor.analyzer import build_report
from honeypot_auditor.banner import TAGLINE, print_cli_header
from honeypot_auditor.capabilities import probe_capabilities
from honeypot_auditor.config import (
    DEFAULT_PORT_PRESET,
    DEFAULT_SCAN_CONCURRENCY,
    DEFAULT_TIMEOUT_SECONDS,
    PORT_PRESET_CHOICES,
    PROTOCOL_STRATEGIES,
    expand_scan_targets,
    is_private_or_loopback,
    parse_port_numbers,
    parse_port_overrides,
    probe_port_map,
)
from honeypot_auditor.models import AuditReport, Indicator
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.probes.deep import run_deep_probes
from honeypot_auditor.probes.recon import nmap_scan, shodan_lookup
from honeypot_auditor.reporters.console import render, render_subnet_summary
from honeypot_auditor.reporters.json_export import export, export_nmap_exclude, export_subnet
from honeypot_auditor.reporters.sarif import export_sarif
from honeypot_auditor.settings import ProbeProfile, settings
from honeypot_auditor.signatures.evaluate import evaluate_signatures
from honeypot_auditor.transport import _apply_jitter, get_transport_manager

try:
    from rich_argparse import RichHelpFormatter
except ImportError:  # pragma: no cover - dependency should always be installed
    RichHelpFormatter = argparse.HelpFormatter

BANNER = (
    "Multi-protocol decoy fingerprinter for authorized lab and CTI use. "
    "Probes are banner/state checks (no exploits, no SMTP DATA, cleanup of probe artifacts)."
)

CLI_EPILOG = """
examples:
  honeypot-auditor --target 127.0.0.1
  honeypot-auditor --target 203.0.113.10 --confirm-authorized --deep
  honeypot-auditor --target 35.171.9.193 -p 22 --confirm-authorized -n
  honeypot-auditor --target 192.168.1.0/24 --scan-concurrency 16

help:
  -h, --help, /help    show this message and exit (H-AUDITOR figlet header)
"""


def _normalize_argv(argv: list[str] | None) -> list[str]:
    raw = list(argv) if argv is not None else sys.argv[1:]
    out: list[str] = []
    for arg in raw:
        if arg in ("/help", "/?"):
            out.append("--help")
        else:
            out.append(arg)
    return out


def _flatten_extra_ports(raw: list[str]) -> list[int]:
    extra: list[int] = []
    for spec in raw:
        extra.extend(parse_port_numbers(spec))
    return extra


def _stamp_port(indicators: list[Indicator], proto: str, port: int) -> list[Indicator]:
    label = f"{proto}:{port}"
    for ind in indicators:
        current = ind.protocol or proto
        if ":" not in current:
            ind.protocol = f"{current}:{port}" if current else label
        elif current == proto:
            ind.protocol = label
    return indicators


def _port_note(ports: dict[str, list[int]]) -> str:
    bits = []
    for proto in PROTOCOL_STRATEGIES:
        nums = ports.get(proto) or []
        if nums:
            bits.append(f"{proto}:{','.join(str(n) for n in nums)}")
    return " ".join(bits)


def _wants_help(argv: list[str]) -> bool:
    return any(arg in ("-h", "--help") for arg in argv)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="honeypot-auditor",
        description=BANNER,
        formatter_class=RichHelpFormatter,
        epilog=CLI_EPILOG,
        add_help=True,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "--target",
        required=True,
        help="IP, hostname, or IPv4 CIDR (max /24, e.g. 192.168.1.0/24)",
    )
    p.add_argument(
        "--shodan-key",
        default=os.environ.get("SHODAN_API_KEY", ""),
        help="Shodan API key (or set SHODAN_API_KEY)",
    )
    p.add_argument("--output", default="", help="JSON report path (default: honeypot-audit-<ip>.json)")
    p.add_argument(
        "--preset",
        default=DEFAULT_PORT_PRESET,
        choices=[*PORT_PRESET_CHOICES, "deception-audit"],
        help="Port map: both=IANA+lab (default), deception-audit=both+deep QA",
    )
    p.add_argument(
        "-p",
        "--port",
        action="append",
        default=[],
        metavar="PORT",
        dest="extra_ports",
        help="Only these TCP ports (nmap-style; repeatable or 22,2222). 22→ssh, 80→http; unknown numbers probed as SSH. Omit to use --preset",
    )
    p.add_argument("--ports", default="", help="Override ports, e.g. ssh=2222,http=8081")
    p.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Required when any scanned IP is public (single host or subnet)",
    )
    p.add_argument(
        "-n",
        "--with-nmap",
        action="store_true",
        help="Run Nmap -sV / NSE phase (slow; off by default)",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print strategy breakdown, per-protocol matrix, indicator table, why-this-score, and run notes",
    )
    p.add_argument(
        "--deep",
        action="store_true",
        help="Run advanced probes: shell semantics, OS coherence, HASSH/TCP stack, FSM fuzz, co-tenancy, latency under load",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Socket timeout in seconds (default {DEFAULT_TIMEOUT_SECONDS})",
    )
    p.add_argument(
        "--scan-concurrency",
        type=int,
        default=DEFAULT_SCAN_CONCURRENCY,
        help=f"Parallel hosts when scanning a CIDR subnet (default {DEFAULT_SCAN_CONCURRENCY})",
    )
    p.add_argument(
        "--safe-mode",
        action="store_true",
        help="Handshake-only probes; disables --deep shell/path/auth attempts",
    )
    p.add_argument(
        "--profile",
        choices=[p.value for p in ProbeProfile],
        default=ProbeProfile.AUDIT.value,
        help="Probe profile: audit (default), blend (browser mimesis), safe",
    )
    p.add_argument(
        "--proxy",
        default=os.environ.get("HONEYPOT_AUDITOR_PROXY", ""),
        help="SOCKS5 proxy URL (prefer socks5h:// for remote DNS)",
    )
    p.add_argument(
        "--proxy-allow-local-dns",
        action="store_true",
        help="Allow socks5:// with hostname targets (may leak DNS)",
    )
    p.add_argument(
        "--output-nmap-exclude",
        default="",
        help="Append IP to this file when Honeyscore >= 60",
    )
    p.add_argument(
        "--passive-first",
        action="store_true",
        help="Run Shodan OSINT before active probes; skip active when passive score high",
    )
    p.add_argument(
        "--osint-only",
        action="store_true",
        help="Shodan OSINT only — no TCP probes (alias strict passive mode)",
    )
    p.add_argument(
        "--dual-stack",
        action="store_true",
        help="Resolve A+AAAA and compare IPv4 vs IPv6 probe results",
    )
    p.add_argument(
        "--jitter",
        type=float,
        default=0.0,
        metavar="FRACTION",
        help="Random delay up to FRACTION * timeout before each probe (e.g. 0.3)",
    )
    p.add_argument(
        "--jitter-ms",
        default="",
        metavar="MIN-MAX",
        help="Random delay range in ms before each probe (e.g. 50-500)",
    )
    p.add_argument(
        "--max-concurrent",
        type=int,
        default=32,
        help="Max concurrent socket probes (default 32)",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="RNG seed for blend profile TLS/UA rotation",
    )
    p.add_argument(
        "--format",
        choices=("json", "sarif"),
        default="json",
        help="Primary report format (default json)",
    )
    p.add_argument(
        "--signature-pack",
        default="core",
        choices=("core", "community"),
        help="Declarative signature pack (community requires pyyaml)",
    )
    return p


def run_check_sig(argv: list[str]) -> int:
    """Validate a signature pack file offline."""
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: honeypot-auditor check-sig PATH [PATH ...]")
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    import json

    from honeypot_auditor.signatures.loader import load_signature_file, validate_signature_doc

    ok = True
    for path_str in argv:
        path = Path(path_str)
        if not path.is_file():
            print(f"error: {path}: not found", file=sys.stderr)
            ok = False
            continue
        try:
            if path.suffix == ".json":
                doc = json.loads(path.read_text(encoding="utf-8"))
                errors = validate_signature_doc(doc)
                if errors:
                    print(f"FAIL {path}:")
                    for err in errors:
                        print(f"  - {err}")
                    ok = False
                else:
                    print(f"OK {path}")
            else:
                pack = load_signature_file(path)
                print(f"OK {path} ({len(pack.rules)} rules)")
        except Exception as exc:
            print(f"FAIL {path}: {exc}", file=sys.stderr)
            ok = False
    return 0 if ok else 1


async def _run_named(name: str, fn: Callable[[], list[Indicator]], progress, task_id) -> list[Indicator]:
    _apply_jitter()
    mgr = get_transport_manager()
    try:
        result = await mgr.run_sync(fn, timeout=max(5.0, settings.timeout_seconds), jitter=False)
        return result if isinstance(result, list) else []
    except Exception as exc:
        return [
            Indicator(
                id=f"{name}.error",
                title=f"{name} probe error",
                category="static_signature",
                skipped=True,
                skip_reason=str(exc),
                error=str(exc),
                protocol=name,
                detail=str(exc),
            )
        ]
    finally:
        if progress is not None:
            progress.update(task_id, advance=1, description=f"Finished {name}")


def _build_notes(
    args: argparse.Namespace,
    *,
    subnet: bool,
    public_target: bool,
    ports: dict[str, list[int]] | None = None,
) -> list[str]:
    notes = [
        f"preset={args.preset} timeout={args.timeout}s deep={args.deep}",
        "Closed ports are skipped and do not raise the score.",
    ]
    if args.extra_ports:
        notes.append("-p/--port selects only the listed ports (preset not applied)")
    if ports:
        notes.append(f"ports {_port_note(ports)}")
    if public_target and args.confirm_authorized:
        notes.append(
            "Public target: operator asserted authorization via --confirm-authorized."
        )
    if not args.with_nmap:
        notes.append("Nmap omitted by default; pass --with-nmap / -n for -sV/NSE tells.")
    if args.deep:
        notes.append("Deep mode: co-tenancy requires corroboration from another emulator tell.")
    if subnet:
        notes.append(
            f"Subnet scan: {args.scan_concurrency} concurrent host(s); Shodan skipped per-host."
        )
    return notes


def _resolve_dual_stack(target: str) -> tuple[list[str], list[str]]:
    ipv4: list[str] = []
    ipv6: list[str] = []
    try:
        for info in socket.getaddrinfo(target, None, socket.AF_INET):
            ipv4.append(info[4][0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(target, None, socket.AF_INET6):
            ipv6.append(info[4][0])
    except OSError:
        pass
    return list(dict.fromkeys(ipv4)), list(dict.fromkeys(ipv6))


def _passive_score_high(indicators: list[Indicator]) -> bool:
    open_protocols = 0
    for ind in indicators:
        if ind.id == "shodan.honeyscore" and ind.triggered:
            return True
        if ind.id == "shodan.tags" and ind.triggered:
            return True
        if ind.id == "shodan.open_ports" and ind.triggered:
            return True
        if ind.id == "shodan.buffet" and ind.triggered:
            return True
    for ind in indicators:
        if ind.protocol and ind.triggered and not ind.skipped:
            open_protocols += 1
    return open_protocols >= 8


def _probe_jobs(
    ip: str,
    ports: dict[str, list[int]],
    args: argparse.Namespace,
    *,
    include_shodan: bool,
) -> list[tuple[str, Callable[[], list[Indicator]]]]:
    jobs: list[tuple[str, Callable[[], list[Indicator]]]] = []
    shodan_inds: list[Indicator] | None = None
    if include_shodan:
        shodan_inds = shodan_lookup(ip, args.shodan_key or None)
        jobs.append(("shodan", lambda s=shodan_inds: s))
    if settings.osint_only:
        return jobs
    if settings.passive_first and include_shodan and shodan_inds is not None:
        if _passive_score_high(shodan_inds):
            return jobs
    if args.with_nmap and not settings.osint_only:
        jobs.append(("nmap", lambda: nmap_scan(ip, ports)))
    for proto, fn in PROBE_BY_PROTOCOL.items():
        for port in ports.get(proto, []):
            jobs.append(
                (
                    f"{proto}:{port}",
                    lambda f=fn, p=port, pr=proto: _stamp_port(f(ip, p), pr, p),
                )
            )
    if args.deep and not getattr(args, "safe_mode", False):
        jobs.append(("deep", lambda: run_deep_probes(ip, ports)))
    return jobs


def _parse_jitter_ms(raw: str) -> tuple[int, int] | None:
    if not raw:
        return None
    parts = raw.split("-")
    if len(parts) != 2:
        raise ValueError("--jitter-ms expects MIN-MAX (e.g. 50-500)")
    return int(parts[0]), int(parts[1])


def _apply_cli_settings(args: argparse.Namespace) -> None:
    settings.timeout_seconds = float(args.timeout)
    safe = bool(getattr(args, "safe_mode", False))
    if getattr(args, "preset", "") == "deception-audit":
        args.preset = DEFAULT_PORT_PRESET
        if not safe:
            args.deep = True
    settings.deep = bool(args.deep) and not safe
    settings.safe_mode = safe
    settings.profile = ProbeProfile.SAFE if safe else ProbeProfile(getattr(args, "profile", "audit"))
    settings.proxy_url = getattr(args, "proxy", "") or ""
    settings.proxy_allow_local_dns = bool(getattr(args, "proxy_allow_local_dns", False))
    settings.passive_first = bool(getattr(args, "passive_first", False))
    settings.osint_only = bool(getattr(args, "osint_only", False))
    settings.dual_stack = bool(getattr(args, "dual_stack", False))
    settings.max_concurrent = max(1, int(getattr(args, "max_concurrent", 32)))
    settings.seed = getattr(args, "seed", None)
    settings.signature_pack = getattr(args, "signature_pack", "core")
    settings.output_format = getattr(args, "format", "json")
    jitter = float(getattr(args, "jitter", 0.0) or 0.0)
    if jitter < 0:
        raise ValueError("--jitter must be >= 0")
    settings.jitter_fraction = jitter
    jitter_ms = getattr(args, "jitter_ms", "") or ""
    if jitter_ms:
        settings.jitter_ms_range = _parse_jitter_ms(jitter_ms)
    caps = probe_capabilities()
    settings.capabilities = caps


def _write_report(report: AuditReport, args: argparse.Namespace, ip: str, console) -> Path:
    out = args.output or f"honeypot-audit-{ip.replace(':', '_')}.json"
    if args.format == "sarif":
        sarif_path = out if out.endswith(".sarif") else out.replace(".json", ".sarif")
        dest = export_sarif(report, sarif_path)
    else:
        dest = export(report, out)
    nmap_exclude = getattr(args, "output_nmap_exclude", "")
    if nmap_exclude and report.score >= 60:
        export_nmap_exclude(report.resolved_ip, nmap_exclude)
    if args.verbose:
        console.print(f"[dim]Report written to {dest}[/dim]")
    return dest


async def _audit_dual_stack(
    target: str,
    args: argparse.Namespace,
    ports: dict[str, list[int]],
    *,
    capabilities: dict | None = None,
    capability_warnings: list | None = None,
) -> AuditReport:
    ipv4_addrs, ipv6_addrs = _resolve_dual_stack(target)
    v4 = ipv4_addrs[0] if ipv4_addrs else ""
    v6 = ipv6_addrs[0] if ipv6_addrs else ""
    if not v4 and not v6:
        raise ValueError(f"could not resolve A/AAAA for {target!r}")
    reports: dict[str, AuditReport] = {}
    if v4:
        reports["ipv4"] = await _audit_host(
            v4, args, ports, include_shodan=True,
            capabilities=capabilities, capability_warnings=capability_warnings,
        )
    if v6:
        reports["ipv6"] = await _audit_host(
            v6, args, ports, include_shodan=False,
            capabilities=capabilities, capability_warnings=capability_warnings,
        )
    primary = reports.get("ipv4") or reports.get("ipv6")
    assert primary is not None
    dual: dict = {}
    for key, rep in reports.items():
        dual[key] = {
            "resolved_ip": rep.resolved_ip,
            "score": rep.score,
            "threat_level": rep.threat_level,
            "triggered_count": len(rep.triggered()),
        }
    if len(reports) == 2:
        r4, r6 = reports["ipv4"], reports["ipv6"]
        score_delta = abs(r4.score - r6.score)
        if score_delta >= 30:
            primary = build_report(
                target=target,
                resolved_ip=primary.resolved_ip,
                ports=ports,
                indicators=[
                    *primary.indicators,
                    Indicator(
                        id="info.ip_version_mismatch",
                        title="IPv4 vs IPv6 probe divergence",
                        category="coherence",
                        triggered=True,
                        protocol="info",
                        detail=f"ipv4_score={r4.score} ipv6_score={r6.score} delta={score_delta:.1f}",
                        tell_tier="origin",
                    ),
                ],
                notes=primary.notes,
                started_at=primary.started_at,
                finished_at=primary.finished_at,
                deep=args.deep,
                capabilities=capabilities,
                capability_warnings=capability_warnings,
            )
    primary.dual_stack = dual
    primary.target = target
    return primary


async def _audit_host(
    ip: str,
    args: argparse.Namespace,
    ports: dict[str, list[int]],
    *,
    include_shodan: bool,
    progress=None,
    task_id=None,
    capabilities: dict | None = None,
    capability_warnings: list | None = None,
    target: str | None = None,
) -> AuditReport:
    started = datetime.now(timezone.utc).isoformat()
    notes = _build_notes(args, subnet=False, public_target=not is_private_or_loopback(ip), ports=ports)
    jobs = _probe_jobs(ip, ports, args, include_shodan=include_shodan)

    indicators: list[Indicator] = []
    if progress is not None and task_id is not None:
        batches = await asyncio.gather(
            *[_run_named(name, fn, progress, task_id) for name, fn in jobs]
        )
        for batch in batches:
            indicators.extend(batch)
    else:
        for name, fn in jobs:
            indicators.extend(await _run_named(name, fn, None, None))

    indicators.extend(evaluate_signatures(indicators))
    finished = datetime.now(timezone.utc).isoformat()
    return build_report(
        target=target or ip,
        resolved_ip=ip,
        ports=ports,
        indicators=indicators,
        notes=notes,
        started_at=started,
        finished_at=finished,
        deep=args.deep,
        capabilities=capabilities,
        capability_warnings=capability_warnings,
    )


def _subnet_output_path(target: str, output: str) -> str:
    if output:
        return output
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", target)
    return f"honeypot-audit-subnet-{slug}.json"


async def _audit_subnet(
    target: str,
    hosts: list[str],
    args: argparse.Namespace,
    ports: dict[str, list[int]],
    console,
) -> list[AuditReport]:
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    sem = asyncio.Semaphore(max(1, args.scan_concurrency))
    reports: list[AuditReport] = []

    async def _one(ip: str) -> AuditReport:
        async with sem:
            return await _audit_host(ip, args, ports, include_shodan=False)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(f"Scanning {len(hosts)} host(s)…", total=len(hosts))

        async def _tracked(ip: str) -> AuditReport:
            report = await _one(ip)
            progress.update(task_id, advance=1, description=f"Finished {ip}")
            return report

        reports = await asyncio.gather(*[_tracked(ip) for ip in hosts])
    return list(reports)


async def run_audit(args: argparse.Namespace) -> int:
    from rich.console import Console
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    console = Console()
    print_cli_header(console)
    console.print(f"[dim]{TAGLINE}[/dim]\n")

    try:
        scan_kind, hosts = expand_scan_targets(args.target)
        extra = _flatten_extra_ports(args.extra_ports)
        ports = probe_port_map(args.preset, parse_port_overrides(args.ports), extra)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    if args.timeout <= 0:
        console.print("[red]--timeout must be positive[/red]")
        return 2

    if args.scan_concurrency <= 0:
        console.print("[red]--scan-concurrency must be positive[/red]")
        return 2

    public_hosts = [ip for ip in hosts if not is_private_or_loopback(ip)]
    if public_hosts and not args.confirm_authorized:
        if scan_kind == "subnet":
            console.print(
                "[red]Refusing subnet with public addresses without --confirm-authorized. "
                "Probe only networks you own or have explicit permission to test.[/red]"
            )
        else:
            console.print(
                "[red]Refusing public IP without --confirm-authorized. "
                "Probe only systems you own or have explicit permission to test.[/red]"
            )
        return 2

    try:
        _apply_cli_settings(args)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    safe = settings.safe_mode
    if safe and args.deep:
        console.print("[yellow]--safe-mode disables --deep shell/path probes[/yellow]")
    caps = settings.capabilities
    cap_dict = caps.as_dict()
    cap_warnings = caps.warnings
    started = datetime.now(timezone.utc).isoformat()
    console.print(f"[dim]ports {_port_note(ports) or '(none)'}[/dim]\n")

    if scan_kind == "host":
        if settings.dual_stack and not re.match(r"^\d+\.\d+\.\d+\.\d+$", args.target):
            report = await _audit_dual_stack(
                args.target,
                args,
                ports,
                capabilities=cap_dict,
                capability_warnings=cap_warnings,
            )
            render(report, console=console, verbose=args.verbose)
            _write_report(report, args, report.resolved_ip, console)
            return 0

        ip = hosts[0]
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            jobs = _probe_jobs(ip, ports, args, include_shodan=True)
            task_id = progress.add_task("Auditing target…", total=len(jobs))
            report = await _audit_host(
                ip,
                args,
                ports,
                include_shodan=True,
                progress=progress,
                task_id=task_id,
                capabilities=cap_dict,
                capability_warnings=cap_warnings,
                target=args.target,
            )
        render(report, console=console, verbose=args.verbose)
        _write_report(report, args, ip, console)
        return 0

    reports = await _audit_subnet(args.target, hosts, args, ports, console)
    finished = datetime.now(timezone.utc).isoformat()
    notes = _build_notes(args, subnet=True, public_target=bool(public_hosts), ports=ports)
    render_subnet_summary(args.target, reports, console=console)
    if args.verbose:
        for note in notes:
            console.print(f"[dim]{note}[/dim]")
    out = _subnet_output_path(args.target, args.output)
    dest = export_subnet(
        target=args.target,
        reports=reports,
        path=out,
        notes=notes,
        started_at=started,
        finished_at=finished,
    )
    if args.verbose:
        console.print(f"[dim]JSON written to {dest}[/dim]")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = _normalize_argv(argv)
    if argv and argv[0] == "check-sig":
        return run_check_sig(argv[1:])
    parser = build_parser()
    if _wants_help(argv):
        print_cli_header()
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    try:
        return asyncio.run(run_audit(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
