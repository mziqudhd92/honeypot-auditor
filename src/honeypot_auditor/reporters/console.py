"""Rich console summary."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from honeypot_auditor.models import AuditReport, Indicator

_LEVEL_STYLE = {
    "Confirmed Honeypot": "bold red",
    "Suspected Honeypot": "bold yellow",
    "Likely Real Host": "bold green",
    "Inconclusive": "bold cyan",
}


def render(report: AuditReport, console: Console | None = None) -> None:
    console = console or Console()
    style = _LEVEL_STYLE.get(report.threat_level, "bold")

    head = Table.grid(padding=(0, 2))
    head.add_column(style="dim")
    head.add_column()
    head.add_row("Target", f"{report.target} ({report.resolved_ip})")
    head.add_row("Honeyscore", f"[bold]{report.score:.1f}%[/bold]")
    head.add_row("Threat level", Text(report.threat_level, style=style))
    console.print(Panel(head, title="Honeypot Auditor", border_style="cyan"))

    weights = Table(title="Category contributions", show_lines=False)
    weights.add_column("Category")
    weights.add_column("Weight", justify="right")
    weights.add_column("Hit", justify="center")
    weights.add_column("Contribution", justify="right")
    labels = {
        "shodan": "Shodan Honeyscore / tags",
        "arbitrary_auth": "Arbitrary credential acceptance",
        "state_nonpersist": "State non-persistence",
        "static_signature": "Static software / banner match",
        "behavior": "Shell execution semantics",
        "coherence": "Cross-artifact OS coherence",
        "stack_fingerprint": "HASSH / TCP stack fingerprint",
        "proto_conformance": "Protocol FSM conformance",
        "cotenancy": "Multi-service honeypot buffet",
        "temporal": "Temporal / latency behavior",
    }
    for key, row in report.category_hits.items():
        hit = row.get("triggered")
        attempted = row.get("attempted")
        mark = "[red]yes[/red]" if hit else ("[dim]skip[/dim]" if not attempted else "[green]no[/green]")
        weights.add_row(
            labels.get(key, key),
            f"{row.get('weight', 0) * 100:.0f}%",
            mark,
            f"{row.get('contribution', 0):.0f}%",
        )
    console.print(weights)

    bullets = Table(title="Indicators", show_header=True)
    bullets.add_column("Status", width=10)
    bullets.add_column("Protocol", width=10)
    bullets.add_column("Finding")
    bullets.add_column("Detail")
    for ind in report.indicators:
        bullets.add_row(_status(ind), ind.protocol or "—", ind.title, (ind.detail or "")[:180])
    console.print(bullets)

    triggered = report.triggered()
    if triggered:
        console.print("[bold]Why this score[/bold]")
        for ind in triggered:
            console.print(f"  • [{ind.protocol}] {ind.title} — {ind.detail}")
    else:
        console.print("[dim]No honeypot indicators fired. Closed ports are skipped, not scored.[/dim]")

    for note in report.notes:
        console.print(f"[dim]{note}[/dim]")


def _status(ind: Indicator) -> str:
    if ind.skipped:
        return "[dim]skip[/dim]"
    if ind.triggered:
        return "[red]HIT[/red]"
    return "[green]clean[/green]"


def render_subnet_summary(
    target: str,
    reports: list[AuditReport],
    console: Console | None = None,
) -> None:
    console = console or Console()
    table = Table(title=f"Subnet scan — {target}", show_header=True)
    table.add_column("IP")
    table.add_column("Score", justify="right")
    table.add_column("Threat level")
    table.add_column("Hits", justify="right")
    for report in sorted(reports, key=lambda r: r.score, reverse=True):
        style = _LEVEL_STYLE.get(report.threat_level, "")
        table.add_row(
            report.resolved_ip,
            f"{report.score:.1f}%",
            Text(report.threat_level, style=style),
            str(len(report.triggered())),
        )
    console.print(table)
    flagged = [r for r in reports if r.score >= 30.0]
    if flagged:
        console.print(
            f"[bold]{len(flagged)}[/bold] host(s) scored ≥30% (suspected or confirmed honeypot)."
        )
    else:
        console.print("[dim]No hosts scored ≥30% in this subnet.[/dim]")
