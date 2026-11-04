"""STIX 2.1 bundle export (file only; no live TAXII push)."""

from __future__ import annotations

import ipaddress
import json
import uuid
from pathlib import Path

from honeypot_auditor.models import AuditReport
from honeypot_auditor.reporters.cti_context import build_cti_context
from honeypot_auditor.reporters.json_export import write_owner_only


def _stix_id(obj_type: str) -> str:
    return f"{obj_type}--{uuid.uuid4()}"


def _ip_sco_type(value: str) -> str:
    try:
        addr = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return "ipv4-addr"
    return "ipv6-addr" if isinstance(addr, ipaddress.IPv6Address) else "ipv4-addr"


def build_stix_bundle(report: AuditReport) -> dict:
    """Build a STIX 2.1 bundle using standard SCOs + Infrastructure + Indicator.

    Fingerprints (HASSH/JA3S/JA4S) ride as ``x_honeypot_auditor_*`` custom
    properties on the IP SCO (STIX-allowed vendor extensions) rather than
    inventing non-standard object types.
    """
    ctx = build_cti_context(report)
    objects: list[dict] = []
    created = ctx.started_at or "1970-01-01T00:00:00.000Z"
    modified = ctx.finished_at or created

    ip_type = _ip_sco_type(ctx.resolved_ip)
    ip_obj: dict = {
        "type": ip_type,
        "spec_version": "2.1",
        "id": _stix_id(ip_type),
        "value": ctx.resolved_ip,
    }
    ssh = (ctx.observables or {}).get("ssh") or {}
    tls = (ctx.observables or {}).get("tls") or {}
    ntlm = (ctx.observables or {}).get("ntlm") or {}
    if ssh.get("hassh_server"):
        ip_obj["x_honeypot_auditor_hassh_server"] = ssh["hassh_server"]
    if tls.get("ja3s"):
        ip_obj["x_honeypot_auditor_ja3s"] = tls["ja3s"]
    if tls.get("ja4s"):
        ip_obj["x_honeypot_auditor_ja4s"] = tls["ja4s"]
    if ntlm.get("challenge"):
        ip_obj["x_honeypot_auditor_ntlm_challenge"] = ntlm["challenge"]
    objects.append(ip_obj)
    ip_id = ip_obj["id"]

    x509_id = ""
    if tls.get("cert_sha256"):
        x509_id = _stix_id("x509-certificate")
        objects.append(
            {
                "type": "x509-certificate",
                "spec_version": "2.1",
                "id": x509_id,
                "hashes": {"SHA-256": tls["cert_sha256"]},
            }
        )

    infra_id = _stix_id("infrastructure")
    objects.append(
        {
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": infra_id,
            "created": created,
            "modified": modified,
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
            "created": created,
            "modified": modified,
            "relationship_type": "consists-of",
            "source_ref": infra_id,
            "target_ref": ip_id,
        }
    )
    if x509_id:
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship"),
                "created": created,
                "modified": modified,
                "relationship_type": "related-to",
                "source_ref": infra_id,
                "target_ref": x509_id,
            }
        )
    for ind in ctx.triggered:
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _stix_id("indicator"),
                "created": created,
                "modified": modified,
                "name": ind.id,
                "description": ind.detail or ind.title,
                "pattern": f"[{ip_type}:value = '{ctx.resolved_ip}']",
                "pattern_type": "stix",
                "valid_from": created,
                "labels": [ind.category, ind.fidelity] if ind.category else [ind.fidelity],
            }
        )
    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "spec_version": "2.1",
        "objects": objects,
    }


def build_stix_bundle_many(reports: list[AuditReport]) -> dict:
    """Merge per-host STIX objects into one 2.1 bundle (subnet exports)."""
    objects: list[dict] = []
    for report in reports:
        objects.extend(build_stix_bundle(report).get("objects") or [])
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


def export_stix_many(reports: list[AuditReport], path: str | Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    write_owner_only(dest, json.dumps(build_stix_bundle_many(reports), indent=2) + "\n")
    return dest
