"""MISP event JSON file export (no live MISP push)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from honeypot_auditor.models import AuditReport
from honeypot_auditor.reporters.cti_context import build_cti_context
from honeypot_auditor.reporters.json_export import write_owner_only


def build_misp_event(report: AuditReport) -> dict:
    ctx = build_cti_context(report)
    attrs: list[dict] = [
        {
            "type": "ip-dst",
            "category": "Network activity",
            "value": ctx.resolved_ip,
            "to_ids": True,
            "comment": f"honeypot-auditor target score={ctx.score}",
        }
    ]
    for ind in ctx.triggered:
        attrs.append(
            {
                "type": "text",
                "category": "External analysis",
                "value": ind.id,
                "comment": (ind.detail or ind.title)[:500],
                "to_ids": False,
            }
        )
    ssh = (ctx.observables or {}).get("ssh") or {}
    if ssh.get("hassh_server"):
        attrs.append(
            {
                "type": "text",
                "category": "Network activity",
                "value": ssh["hassh_server"],
                "comment": "hassh_server",
                "to_ids": True,
            }
        )
    tls = (ctx.observables or {}).get("tls") or {}
    for key, misp_type in (
        ("ja3s", "ja3-fingerprint-md5"),
        ("ja4s", "text"),
        ("cert_sha256", "x509-fingerprint-sha256"),
    ):
        if tls.get(key):
            attrs.append(
                {
                    "type": misp_type,
                    "category": "Network activity",
                    "value": tls[key],
                    "comment": key,
                    "to_ids": True,
                }
            )
    tags = [{"name": t} for t in ctx.tags]
    tags.append({"name": "tlp:amber"})
    tags.append({"name": "honeypot-auditor"})
    return {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": f"honeypot-auditor {ctx.target} ({ctx.threat_level})",
            "threat_level_id": "2" if "Confirmed" in ctx.threat_level else "3",
            "analysis": "1",
            "distribution": "0",
            "Attribute": attrs,
            "Tag": tags,
            "date": (ctx.started_at or "")[:10] or "1970-01-01",
        }
    }


def build_misp_events(reports: list[AuditReport]) -> dict:
    """MISP search/export envelope: response entries are full {\"Event\": …} objects."""
    return {"response": [build_misp_event(report) for report in reports]}


def export_misp(report: AuditReport, path: str | Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    write_owner_only(dest, json.dumps(build_misp_event(report), indent=2) + "\n")
    return dest


def export_misp_many(reports: list[AuditReport], path: str | Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    write_owner_only(dest, json.dumps(build_misp_events(reports), indent=2) + "\n")
    return dest
