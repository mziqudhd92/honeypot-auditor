"""Structured JSON export."""

from __future__ import annotations

import json
from pathlib import Path

from honeypot_auditor.models import AuditReport


def _report_payload(report: AuditReport) -> dict:
    return {
        "target": report.target,
        "resolved_ip": report.resolved_ip,
        "score": report.score,
        "threat_level": report.threat_level,
        "category_hits": report.category_hits,
        "ports": report.ports,
        "notes": report.notes,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "indicators": [i.as_dict() for i in report.indicators],
        "triggered": [i.as_dict() for i in report.triggered()],
    }


def export(report: AuditReport, path: str | Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(_report_payload(report), indent=2) + "\n", encoding="utf-8")
    return dest


def export_subnet(
    *,
    target: str,
    reports: list[AuditReport],
    path: str | Path,
    notes: list[str],
    started_at: str,
    finished_at: str,
) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    summary = [
        {
            "resolved_ip": r.resolved_ip,
            "score": r.score,
            "threat_level": r.threat_level,
            "triggered_count": len(r.triggered()),
        }
        for r in reports
    ]
    payload = {
        "scan_type": "subnet",
        "target": target,
        "host_count": len(reports),
        "started_at": started_at,
        "finished_at": finished_at,
        "notes": notes,
        "summary": summary,
        "hosts": [_report_payload(r) for r in reports],
    }
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return dest
