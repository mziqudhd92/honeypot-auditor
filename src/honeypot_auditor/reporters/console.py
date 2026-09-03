"""Rich console summary."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from honeypot_auditor.config import BASIC_STRATEGIES, STRATEGY_LABELS
from honeypot_auditor.models import AuditReport, Indicator

_LEVEL_STYLE = {
    "Confirmed Honeypot": "bold red",
    "Suspected Honeypot": "bold yellow",
    "Likely Real Host": "bold green",
    "Inconclusive": "bold cyan",
    "Inconclusive (Low-confidence anomalies detected)": "bold magenta",
}


def render(report: AuditReport, console: Console | None = None, *, verbose: bool = False) -> None:
    console = console or Console()
    style = _LEVEL_STYLE.get(report.threat_level, "bold")

    head = Table.grid(padding=(0, 2))
    head.add_column(style="dim")
    head.add_column()
    head.add_row("Target", f"{report.target} ({report.resolved_ip})")
    head.add_row("Honeyscore", f"[bold]{report.score:.1f}%[/bold] (global)")
    if report.scoped_score is not None:
        head.add_row("Scoped Honeyscore", f"[bold]{report.scoped_score:.1f}%[/bold] (normalized)")
        effective = max(report.score, report.scoped_score)
        head.add_row("Effective score", f"{effective:.1f}% (max of global, scoped)")
    head.add_row("Confidence", report.confidence or "medium")
    if report.tactical_action:
        head.add_row("Tactical", report.tactical_action)
    head.add_row("Threat level", Text(report.threat_level, style=style))
    console.print(Panel(head, title="Honeypot Auditor", border_style="cyan"))

    if not verbose:
        return

    weights = Table(title="Strategy contributions", show_lines=False)
    weights.add_column("Strategy")
    weights.add_column("Weight", justify="right")
    weights.add_column("Hits", justify="right")
    weights.add_column("Intra", justify="right")
    weights.add_column("Hit", justify="center")
    weights.add_column("Contribution", justify="right")
    for key, row in report.category_hits.items():
        hit = row.get("triggered")
        attempted = row.get("attempted")
        mark = (
            "[red]yes[/red]"
            if hit
            else ("[dim]skip[/dim]" if not attempted else "[green]no[/green]")
        )
        hit_count = int(row.get("hit_count") or 0)
        intra = float(row.get("intra_category_bonus") or 0.0)
        if row.get("dynamic"):
            hits_cell = "—"
            intra_cell = "—"
            weight_cell = "bonus"
        else:
            hits_cell = str(hit_count) if hit_count else ("—" if not attempted else "0")
            intra_cell = f"+{intra:.1f}%" if intra else "—"
            weight_cell = f"{row.get('weight', 0) * 100:.0f}%"
        weights.add_row(
            STRATEGY_LABELS.get(key, key),
            weight_cell,
            hits_cell,
            intra_cell,
            mark,
            f"{row.get('contribution', 0):.1f}%",
        )
    console.print(weights)

    _print_score_formula(console, report)

    if report.protocol_strategies:
        proto = Table(title="Protocol strategies", show_lines=False)
        proto.add_column("Protocol", width=12)
        proto.add_column("Ports", width=12)
        for key in BASIC_STRATEGIES:
            proto.add_column(STRATEGY_LABELS.get(key, key))
        for row in report.protocol_strategies:
            proto.add_row(
                row["protocol"],
                ",".join(str(p) for p in row.get("ports") or []),
                *(_strategy_cell(row.get(key) or {}) for key in BASIC_STRATEGIES),
            )
        console.print(proto)

    bullets = Table(title="Indicators", show_header=True)
    bullets.add_column("Status", width=10)
    bullets.add_column("Fidelity", width=9)
    bullets.add_column("Protocol", width=12)
    bullets.add_column("Finding")
    bullets.add_column("Detail")
    for ind in report.indicators:
        bullets.add_row(
            _status(ind),
            ind.fidelity or "medium",
            ind.protocol or "—",
            ind.title,
            (ind.detail or "")[:160],
        )
    console.print(bullets)

    triggered = report.triggered()
    if triggered:
        console.print("[bold]Why this score[/bold]")
        for ind in triggered:
            fidelity = ind.fidelity or "medium"
            # Use Text so protocol tags like [pop3] are not parsed as Rich markup.
            console.print(
                Text(
                    f"  • [{ind.protocol or '—'}] ({fidelity}) "
                    f"{ind.title} — {ind.detail or ''}"
                )
            )
    else:
        console.print(
            "[dim]No honeypot indicators fired. Closed ports are skipped, not scored.[/dim]"
        )

    for note in report.notes:
        console.print(f"[dim]{note}[/dim]")


def _print_score_formula(console: Console, report: AuditReport) -> None:
    breakdown = report.score_breakdown
    if not breakdown:
        return

    category_total = float(breakdown.get("category_total_pct", 0) or 0)
    bonus_total = float(breakdown.get("bonus_total_pct", 0) or 0)
    raw = float(breakdown.get("raw_score_pct", 0) or 0)
    final = float(breakdown.get("final_score_pct", report.score) or report.score)

    formula = (
        f"categories {category_total:.1f}% + bonuses {bonus_total:.1f}% = raw {raw:.1f}%"
    )
    if breakdown.get("cap_applied"):
        formula += " → capped at 100%"
    if breakdown.get("decisive_override"):
        formula += " → repeated arbitrary auth override to 100%"
    formula += f" → global {final:.1f}%"
    console.print(f"[bold]Score formula[/bold]  {formula}")

    intra_parts = [
        f"{row.get('category')} +{row.get('intra_category_bonus_pct')}%"
        for row in breakdown.get("categories") or []
        if float(row.get("intra_category_bonus_pct") or 0) > 0
    ]
    if intra_parts:
        console.print(
            "[dim]Intra-category[/dim]  "
            + ", ".join(intra_parts)
            + "  (+7.5% per extra hit in same category, cap +15%)"
        )

    bonuses = breakdown.get("bonuses") or []
    if bonuses:
        parts = [
            f"{b.get('id')} +{float(b.get('contribution_pct') or 0):.1f}%" for b in bonuses
        ]
        console.print("[dim]Bonuses[/dim]  " + ", ".join(parts))

    scoped = breakdown.get("scoped") or {}
    if report.scoped_score is not None and scoped.get("applicable"):
        denom = float(scoped.get("denominator_pct") or 0)
        numer = float(scoped.get("numerator_pct") or 0)
        cats = ", ".join(scoped.get("in_scope_categories") or [])
        console.print(
            "[bold]Scoped formula[/bold]  "
            f"({numer:.1f}% / {denom:.1f}% in-scope) × 100 = "
            f"[bold]{report.scoped_score:.1f}%[/bold]"
            + (f"  [{cats}]" if cats else "")
        )
        console.print(
            "[dim]Threat level uses max(global, scoped) on single-port (-p) audits.[/dim]"
        )


def _strategy_cell(cell: dict) -> str:
    status = cell.get("status") or "n/a"
    playbook = (cell.get("playbook") or "").strip()
    if status == "n/a":
        return "[dim]—[/dim]"
    if status == "hit":
        mark = "[red]HIT[/red]"
    elif status == "skip":
        mark = "[dim]skip[/dim]"
    else:
        mark = "[green]clean[/green]"
    if playbook:
        return f"{mark}  {playbook}"
    return mark


def _status(ind: Indicator) -> str:
    if ind.skipped:
        return "[dim]skip[/dim]"
    if ind.suppressed:
        return "[yellow]supp[/yellow]"
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
    table.add_column("Scoped", justify="right")
    table.add_column("Threat level")
    table.add_column("Hits", justify="right")
    for report in sorted(reports, key=lambda r: r.score, reverse=True):
        style = _LEVEL_STYLE.get(report.threat_level, "")
        scoped = f"{report.scoped_score:.1f}%" if report.scoped_score is not None else "—"
        table.add_row(
            report.resolved_ip,
            f"{report.score:.1f}%",
            scoped,
            Text(report.threat_level, style=style),
            str(len(report.triggered())),
        )
    console.print(table)
    flagged = [
        r
        for r in reports
        if max(r.score, r.scoped_score or 0.0) >= 30.0
    ]
    if flagged:
        console.print(
            f"[bold]{len(flagged)}[/bold] host(s) scored ≥30% (suspected or confirmed honeypot)."
        )
    else:
        console.print("[dim]No hosts scored ≥30% in this subnet.[/dim]")
