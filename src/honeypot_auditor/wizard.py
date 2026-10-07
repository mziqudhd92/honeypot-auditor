"""Interactive terminal wizard — step-by-step audits with Rich prompts.

Walks the user through target, preset, ports, depth, and authorization, runs
the audit, renders the standard Rich result tables, and persists every run to
the shared local SQLite database (see storage.py). Covers private targets
freely; public targets require an explicit authorization confirmation.
"""

from __future__ import annotations

import socket

from rich.console import Console
from rich.prompt import Confirm, IntPrompt, Prompt

from honeypot_auditor import storage
from honeypot_auditor.banner import print_cli_header
from honeypot_auditor.config import is_private_or_loopback
from honeypot_auditor.engine import Auditor
from honeypot_auditor.models import AuditReport
from honeypot_auditor.reporters.console import render

_PRESETS = ("both", "iana", "docker-research")


def _resolve_target(target: str) -> str:
    """Resolve a target to an IP (raises ValueError on garbage)."""
    target = (target or "").strip()
    if not target:
        raise ValueError("target is empty")
    return socket.gethostbyname(target)


def parse_ports(raw: str) -> list[str]:
    """Validate a comma-separated TCP port list; returns engine extra_ports form."""
    parts = [p.strip() for p in raw.replace(" ", "").split(",") if p.strip()]
    ports: list[int] = []
    for part in parts:
        if not part.isdigit():
            raise ValueError(f"port {part!r} is not a number")
        value = int(part)
        if not 1 <= value <= 65535:
            raise ValueError(f"port {value} out of range")
        if value in ports:
            continue
        ports.append(value)
    return [",".join(str(p) for p in ports)] if ports else []


def _build_auditor(
    *,
    target: str,
    preset: str,
    ports: str,
    deep: bool,
    timeout: int,
    confirm_authorized: bool,
) -> Auditor:
    return Auditor(
        target=target,
        preset=preset,
        extra_ports=[ports] if ports else [],
        timeout=float(timeout),
        deep=deep,
        confirm_authorized=confirm_authorized,
    )


def _ask_target(console: Console) -> str:
    while True:
        target = Prompt.ask("[bold]Step 1/5 — target[/bold] (IP, hostname, or /24 CIDR)").strip()
        try:
            resolved = _resolve_target(target)
        except OSError as exc:
            console.print(f"  [red]cannot resolve {target!r}: {exc}[/red]")
            continue
        except ValueError as exc:
            console.print(f"  [red]{exc}[/red]")
            continue
        private = is_private_or_loopback(resolved)
        console.print(
            f"  resolved to [bold]{resolved}[/bold] — "
            + (
                "[green]private/loopback target[/green]"
                if private
                else "[yellow]PUBLIC target[/yellow]"
            )
        )
        return target


def _ask_ports(console: Console) -> str:
    raw = Prompt.ask(
        "[bold]Step 3/5 — ports[/bold] (optional, comma-separated; empty = use preset)",
        default="",
    ).strip()
    try:
        return ",".join(p for p in parse_ports(raw))
    except ValueError as exc:
        console.print(f"  [red]{exc} — using the preset ports[/red]")
        return ""


def _run_one(console: Console) -> None:
    target = _ask_target(console)

    preset = Prompt.ask(
        "[bold]Step 2/5 — port preset[/bold]", choices=list(_PRESETS), default="both"
    )

    ports = _ask_ports(console)

    deep = Confirm.ask(
        "[bold]Step 4/5 — deep probes?[/bold] (shell semantics, OS coherence, FSM fuzz — more intrusive)",
        default=False,
    )
    timeout = IntPrompt.ask("[bold]Step 5/5 — socket timeout (seconds)[/bold]", default=3)
    if not 1 <= timeout <= 30:
        console.print("  [red]timeout out of range — using 3[/red]")
        timeout = 3

    resolved = _resolve_target(target)
    confirm_authorized = False
    if not is_private_or_loopback(resolved):
        console.print(
            "  [yellow]This target is PUBLIC. Only continue if you own it or have "
            "written permission. Misuse may violate law and provider terms.[/yellow]"
        )
        if not Confirm.ask("  I am authorized to probe this target", default=False):
            console.print("  [red]Aborted — no probes sent.[/red]")
            return

    auditor = _build_auditor(
        target=target,
        preset=preset,
        ports=ports,
        deep=deep,
        timeout=timeout,
        confirm_authorized=confirm_authorized,
    )
    with console.status("[bold green]Probing… banner/state checks only, no exploits"):
        try:
            report: AuditReport = auditor.run()
        except PermissionError:
            console.print("[red]Public target requires authorization confirmation.[/red]")
            return
        except Exception as exc:
            console.print(f"[red]Audit failed: {exc}[/red]")
            return

    render(report, console, verbose=False)
    try:
        audit_id = storage.save_report(report, deep=deep)
    except OSError as exc:
        console.print(f"[yellow]report not saved (storage error: {exc})[/yellow]")
        return
    console.print(f"[green]✓ saved to local SQLite as audit #{audit_id}[/green]")


def _show_history(console: Console) -> None:
    rows = storage.list_audits(limit=10)
    if not rows:
        console.print("[dim]No audits saved yet.[/dim]")
        return
    console.print("[bold]Recent audits (newest first):[/bold]")
    for row in rows:
        deep_mark = " [dim](deep)[/dim]" if row["deep"] else ""
        console.print(
            f"  #{row['id']:<4} {row['created_at']}  {row['target']:<28} "
            f"{row['score']:>5.1f}%  {row['threat_level']}{deep_mark}"
        )


def run_wizard(console: Console | None = None) -> int:
    console = console or Console()
    print_cli_header()
    console.print(
        "[bold]Interactive audit wizard[/bold] — step by step, non-destructive probes only."
    )
    console.print("[dim]Every run is saved to the local SQLite database.[/dim]\n")
    while True:
        _run_one(console)
        if Confirm.ask("\nAudit another target?", default=False):
            continue
        if Confirm.ask("Show recent audit history?", default=True):
            _show_history(console)
        break
    console.print("[dim]Done — hang up clean.[/dim]")
    return 0
