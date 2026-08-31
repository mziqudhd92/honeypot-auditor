"""CLI entry point and async probe orchestration."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from collections.abc import Callable
from datetime import datetime, timezone

from honeypot_auditor import __version__
from honeypot_auditor.analyzer import build_report
from honeypot_auditor.banner import TAGLINE, print_cli_header
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
from honeypot_auditor.reporters.json_export import export, export_subnet
from honeypot_auditor.settings import settings

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
        choices=PORT_PRESET_CHOICES,
        help="Port map: both=IANA+lab (default), iana=22/80/445/…, docker-research=2222/8081/…",
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
        help="Run advanced probes: shell semantics, OS coherence, HASSH/TCP stack, FSM fuzz, co-tenancy, latency",
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
    return p


async def _run_named(name: str, fn: Callable[[], list[Indicator]], progress, task_id) -> list[Indicator]:
    try:
        result = await asyncio.to_thread(fn)
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


def _probe_jobs(
    ip: str,
    ports: dict[str, list[int]],
    args: argparse.Namespace,
    *,
    include_shodan: bool,
) -> list[tuple[str, Callable[[], list[Indicator]]]]:
    jobs: list[tuple[str, Callable[[], list[Indicator]]]] = []
    if include_shodan:
        jobs.append(("shodan", lambda: shodan_lookup(ip, args.shodan_key or None)))
    if args.with_nmap:
        jobs.append(("nmap", lambda: nmap_scan(ip, ports)))
    for proto, fn in PROBE_BY_PROTOCOL.items():
        for port in ports.get(proto, []):
            jobs.append(
                (
                    f"{proto}:{port}",
                    lambda f=fn, p=port, pr=proto: _stamp_port(f(ip, p), pr, p),
                )
            )
    if args.deep:
        jobs.append(("deep", lambda: run_deep_probes(ip, ports)))
    return jobs


async def _audit_host(
    ip: str,
    args: argparse.Namespace,
    ports: dict[str, list[int]],
    *,
    include_shodan: bool,
    progress=None,
    task_id=None,
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

    finished = datetime.now(timezone.utc).isoformat()
    return build_report(
        target=ip,
        resolved_ip=ip,
        ports=ports,
        indicators=indicators,
        notes=notes,
        started_at=started,
        finished_at=finished,
        deep=args.deep,
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

    settings.timeout_seconds = float(args.timeout)
    settings.deep = bool(args.deep)
    started = datetime.now(timezone.utc).isoformat()
    console.print(f"[dim]ports {_port_note(ports) or '(none)'}[/dim]\n")

    if scan_kind == "host":
        ip = hosts[0]
        jobs = _probe_jobs(ip, ports, args, include_shodan=True)
        indicators: list[Indicator] = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("Auditing target…", total=len(jobs))
            batches = await asyncio.gather(
                *[_run_named(name, fn, progress, task_id) for name, fn in jobs]
            )
            for batch in batches:
                indicators.extend(batch)

        finished = datetime.now(timezone.utc).isoformat()
        notes = _build_notes(
            args,
            subnet=False,
            public_target=bool(public_hosts),
            ports=ports,
        )
        report = build_report(
            target=args.target,
            resolved_ip=ip,
            ports=ports,
            indicators=indicators,
            notes=notes,
            started_at=started,
            finished_at=finished,
            deep=args.deep,
        )
        render(report, console=console, verbose=args.verbose)
        out = args.output or f"honeypot-audit-{ip.replace(':', '_')}.json"
        dest = export(report, out)
        if args.verbose:
            console.print(f"[dim]JSON written to {dest}[/dim]")
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
