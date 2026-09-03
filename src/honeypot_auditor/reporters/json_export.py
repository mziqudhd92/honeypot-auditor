"""Structured JSON export."""

from __future__ import annotations

import json
from pathlib import Path

from honeypot_auditor.models import AuditReport

REPORT_SCHEMA_VERSION = "1.0"


def _report_payload(report: AuditReport) -> dict:
    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "target": report.target,
        "resolved_ip": report.resolved_ip,
        "score": report.score,
        "scoped_score": report.scoped_score,
        "threat_level": report.threat_level,
        "category_hits": report.category_hits,
        "score_breakdown": report.score_breakdown,
        "protocol_strategies": report.protocol_strategies,
        "ports": report.ports,
        "notes": report.notes,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "indicators": [i.as_dict() for i in report.indicators],
        "triggered": [i.as_dict() for i in report.triggered()],
        "confidence": report.confidence,
        "proxy_detected": report.proxy_detected,
        "proxy_evidence": report.proxy_evidence,
        "proxy_context": report.proxy_context,
        "capability_warnings": report.capability_warnings,
        "capabilities": report.capabilities,
    }
    if report.tactical_action:
        payload["tactical_action"] = report.tactical_action
        payload["tactical_rationale"] = report.tactical_rationale
    if report.deception_leaks:
        payload["deception_leaks"] = report.deception_leaks
    if report.dual_stack:
        payload["dual_stack"] = report.dual_stack
    return payload


def _json_default(obj: object) -> str:
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    if isinstance(obj, bytearray):
        return bytes(obj).decode("utf-8", "replace")
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def export(report: AuditReport, path: str | Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(_report_payload(report), indent=2, default=_json_default) + "\n",
        encoding="utf-8",
    )
    return dest


def export_nmap_exclude(ip: str, path: str | Path) -> Path:
    """Append IP to nmap exclude list when Honeyscore >= 60."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    line = f"{ip}\n"
    if dest.exists():
        existing = dest.read_text(encoding="utf-8")
        if ip in existing.splitlines():
            return dest
        dest.write_text(existing + line, encoding="utf-8")
    else:
        dest.write_text(line, encoding="utf-8")
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
        "schema_version": REPORT_SCHEMA_VERSION,
        "scan_type": "subnet",
        "target": target,
        "host_count": len(reports),
        "started_at": started_at,
        "finished_at": finished_at,
        "notes": notes,
        "summary": summary,
        "hosts": [_report_payload(r) for r in reports],
    }
    dest.write_text(json.dumps(payload, indent=2, default=_json_default) + "\n", encoding="utf-8")
    return dest
