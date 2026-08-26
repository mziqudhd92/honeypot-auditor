"""Structured JSON export."""

from __future__ import annotations

import json
from pathlib import Path

from honeypot_auditor.models import AuditReport


def export(report: AuditReport, path: str | Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = {
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
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return dest
