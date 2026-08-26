"""CLI entry point and async probe orchestration."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Callable
from datetime import datetime, timezone

from honeypot_auditor import __version__
from honeypot_auditor.analyzer import build_report
from honeypot_auditor.config import (
    DEFAULT_TIMEOUT_SECONDS,
    is_private_or_loopback,
    merge_ports,
    parse_port_overrides,
    resolve_target,
)
from honeypot_auditor.models import Indicator
from honeypot_auditor.probes.core import probe_ftp, probe_smb, probe_ssh, probe_telnet
from honeypot_auditor.probes.deep import run_deep_probes
from honeypot_auditor.probes.extended import (
    probe_http,
    probe_redis,
    probe_sip,
    probe_smtp,
    probe_vnc,
)
from honeypot_auditor.probes.recon import nmap_scan, shodan_lookup
from honeypot_auditor.reporters.console import render
from honeypot_auditor.reporters.json_export import export
from honeypot_auditor.settings import settings

BANNER = (
    "Honeypot Auditor — authorized targets only. "
    "Probes are banner/state checks (no exploits, no SMTP DATA, cleanup of probe artifacts)."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="honeypot-auditor",
        description=BANNER,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--target", required=True, help="IP or hostname you are authorized to probe")
    p.add_argument(
        "--shodan-key",
        default=os.environ.get("SHODAN_API_KEY", ""),
        help="Shodan API key (or set SHODAN_API_KEY)",
    )
    p.add_argument("--output", default="", help="JSON report path (default: honeypot-audit-<ip>.json)")
    p.add_argument(
        "--preset",
        default="docker-research",
        choices=("iana", "docker-research"),
        help="Port map preset (iana=well-known ports, docker-research=non-privileged lab ports)",
    )
    p.add_argument("--ports", default="", help="Override ports, e.g. ssh=2222,http=8081")
    p.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Required when the target resolves to a public IP",
    )
    p.add_argument("--skip-nmap", action="store_true", help="Skip Nmap NSE scripts")
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


async def run_audit(args: argparse.Namespace) -> int:
    from rich.console import Console
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    console = Console()
    console.print(f"[dim]{BANNER}[/dim]")

    try:
        ip = resolve_target(args.target)
        ports = merge_ports(args.preset, parse_port_overrides(args.ports))
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    if not is_private_or_loopback(ip) and not args.confirm_authorized:
        console.print(
            "[red]Refusing public IP without --confirm-authorized. "
            "Probe only systems you own or have explicit permission to test.[/red]"
        )
        return 2

    public_target = not is_private_or_loopback(ip)

    if args.timeout <= 0:
        console.print("[red]--timeout must be positive[/red]")
        return 2

    settings.timeout_seconds = float(args.timeout)
    settings.deep = bool(args.deep)
    started = datetime.now(timezone.utc).isoformat()
    notes = [
        f"preset={args.preset} timeout={args.timeout}s deep={args.deep}",
        "Closed ports are skipped and do not raise the score.",
    ]
    if public_target and args.confirm_authorized:
        notes.append(
            "Public target: operator asserted authorization via --confirm-authorized."
        )
    if args.deep:
        notes.append("Deep mode: co-tenancy requires corroboration from another emulator tell.")

    jobs: list[tuple[str, Callable[[], list[Indicator]]]] = [
        ("shodan", lambda: shodan_lookup(ip, args.shodan_key or None)),
        ("nmap", lambda: nmap_scan(ip, ports, enabled=not args.skip_nmap)),
        ("ssh", lambda: probe_ssh(ip, ports["ssh"])),
        ("telnet", lambda: probe_telnet(ip, ports["telnet"])),
        ("smb", lambda: probe_smb(ip, ports["smb"])),
        ("ftp", lambda: probe_ftp(ip, ports["ftp"])),
        ("http", lambda: probe_http(ip, ports["http"])),
        ("redis", lambda: probe_redis(ip, ports["redis"])),
        ("smtp", lambda: probe_smtp(ip, ports["smtp"])),
        ("vnc", lambda: probe_vnc(ip, ports["vnc"])),
        ("sip", lambda: probe_sip(ip, ports["sip"])),
    ]
    if args.deep:
        jobs.append(("deep", lambda: run_deep_probes(ip, ports)))

    indicators: list[Indicator] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Auditing target…", total=len(jobs))
        batches = await asyncio.gather(*[_run_named(name, fn, progress, task_id) for name, fn in jobs])
        for batch in batches:
            indicators.extend(batch)

    finished = datetime.now(timezone.utc).isoformat()
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
    render(report, console=console)

    out = args.output or f"honeypot-audit-{ip.replace(':', '_')}.json"
    dest = export(report, out)
    console.print(f"[dim]JSON written to {dest}[/dim]")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(run_audit(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
