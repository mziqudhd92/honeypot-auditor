"""STIX 2.1 bundle export (file only; no live TAXII push)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from honeypot_auditor.models import AuditReport
from honeypot_auditor.reporters.cti_context import build_cti_context
from honeypot_auditor.reporters.json_export import write_owner_only


def _stix_id(obj_type: str) -> str:
    return f"{obj_type}--{uuid.uuid4()}"


def build_stix_bundle(report: AuditReport) -> dict:
    ctx = build_cti_context(report)
    objects: list[dict] = []
    ip_id = _stix_id("ipv4-addr")
    objects.append({"type": "ipv4-addr", "spec_version": "2.1", "id": ip_id, "value": ctx.resolved_ip})

    infra_id = _stix_id("infrastructure")
    objects.append(
        {
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": infra_id,
            "created": ctx.started_at or "1970-01-01T00:00:00.000Z",
            "modified": ctx.finished_at or ctx.started_at or "1970-01-01T00:00:00.000Z",
            "name": f"honeypot-auditor:{ctx.target}",
            "infrastructure_types": ["honeypot"] if "Confirmed" in ctx.threat_level else ["unknown"],
            "description": (
                f"Honeyscore={ctx.score} threat={ctx.threat_level}; "
                f"observables={json.dumps(ctx.observables)[:400]}"
            ),
        }
    )
    objects.append(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": _stix_id("relationship"),
            "created": ctx.started_at or "1970-01-01T00:00:00.000Z",
            "modified": ctx.finished_at or ctx.started_at or "1970-01-01T00:00:00.000Z",
            "relationship_type": "consists-of",
            "source_ref": infra_id,
            "target_ref": ip_id,
        }
    )
    for ind in ctx.triggered:
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _stix_id("indicator"),
                "created": ctx.started_at or "1970-01-01T00:00:00.000Z",
                "modified": ctx.finished_at or ctx.started_at or "1970-01-01T00:00:00.000Z",
                "name": ind.id,
                "description": ind.detail or ind.title,
                "pattern": f"[ipv4-addr:value = '{ctx.resolved_ip}']",
                "pattern_type": "stix",
                "valid_from": ctx.started_at or "1970-01-01T00:00:00.000Z",
                "labels": [ind.category, ind.fidelity] if ind.category else [ind.fidelity],
            }
        )
    # Surface key observables as additional SCOs when present.
    ssh = (ctx.observables or {}).get("ssh") or {}
    if ssh.get("hassh_server"):
        objects.append(
            {
                "type": "x-honeypot-auditor-hassh",
                "spec_version": "2.1",
                "id": _stix_id("x-honeypot-auditor-hassh"),
                "value": ssh["hassh_server"],
            }
        )
    tls = (ctx.observables or {}).get("tls") or {}
    for key in ("ja3s", "ja4s", "cert_sha256"):
        if tls.get(key):
            objects.append(
                {
                    "type": "x-honeypot-auditor-tls",
                    "spec_version": "2.1",
                    "id": _stix_id("x-honeypot-auditor-tls"),
                    "name": key,
                    "value": tls[key],
                }
            )
    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "spec_version": "2.1",
        "objects": objects,
    }


def export_stix(report: AuditReport, path: str | Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    write_owner_only(dest, json.dumps(build_stix_bundle(report), indent=2) + "\n")
    return dest
