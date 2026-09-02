"""SARIF 2.1.0 export for DevSecOps pipelines."""

from __future__ import annotations

import json
from pathlib import Path

from honeypot_auditor import __version__
from honeypot_auditor.models import AuditReport, Indicator

_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "honeypot-auditor"
_LEVEL_MAP = {"high": "error", "medium": "warning", "low": "note"}


def _indicator_level(ind: Indicator) -> str:
    if ind.category in ("arbitrary_auth", "state_nonpersist"):
        return "error"
    if ind.category in ("static_signature", "behavior", "stack_fingerprint"):
        return "warning"
    return "note"


def _indicator_result(ind: Indicator) -> dict:
    return {
        "ruleId": ind.id,
        "level": _indicator_level(ind),
        "message": {"text": ind.title if not ind.detail else f"{ind.title}: {ind.detail}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"probe://{ind.protocol or 'unknown'}"},
                }
            }
        ],
        "properties": {
            "category": ind.category,
            "triggered": ind.triggered,
            "suppressed": ind.suppressed,
            "remediation": ind.remediation,
            "evidence": ind.evidence[:500],
        },
    }


def build_sarif(report: AuditReport) -> dict:
    triggered = [i for i in report.indicators if i.triggered and not i.skipped]
    rules = []
    seen: set[str] = set()
    for ind in triggered:
        if ind.id in seen:
            continue
        seen.add(ind.id)
        rules.append(
            {
                "id": ind.id,
                "name": ind.id,
                "shortDescription": {"text": ind.title},
                "fullDescription": {"text": ind.remediation or ind.title},
            }
        )
    results = [_indicator_result(i) for i in triggered]
    if not results:
        summary_id = "honeypot-auditor.summary"
        rules.append(
            {
                "id": summary_id,
                "name": summary_id,
                "shortDescription": {"text": "Honeypot Auditor summary"},
                "fullDescription": {
                    "text": "No triggered decoy indicators; summary is always emitted for CI consumers."
                },
            }
        )
        results.append(
            {
                "ruleId": summary_id,
                "level": "note",
                "message": {
                    "text": (
                        f"Honeyscore {report.score}% — {report.threat_level} "
                        f"(confidence={report.confidence}, tactical={report.tactical_action})"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"target://{report.resolved_ip or report.target}"
                            }
                        }
                    }
                ],
                "properties": {
                    "category": "info",
                    "triggered": False,
                    "suppressed": False,
                    "remediation": "",
                    "evidence": "",
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": __version__,
                        "informationUri": "https://github.com/mziqudhd92/honeypot-auditor",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "honeyscore": report.score,
                    "confidence": report.confidence,
                    "tactical_action": report.tactical_action,
                    "target": report.target,
                    "resolved_ip": report.resolved_ip,
                },
            }
        ],
    }


def export_sarif(report: AuditReport, path: str | Path) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(build_sarif(report), indent=2) + "\n", encoding="utf-8")
    return dest
