"""Shared report → CTI context builder for STIX/MISP exporters."""

from __future__ import annotations

from dataclasses import dataclass, field

from honeypot_auditor.models import AuditReport, Indicator


@dataclass
class CtiContext:
    target: str
    resolved_ip: str
    score: float
    threat_level: str
    started_at: str
    finished_at: str
    observables: dict = field(default_factory=dict)
    triggered: list[Indicator] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def build_cti_context(report: AuditReport) -> CtiContext:
    tags = [
        f"honeypot-auditor:score={report.score}",
        f"honeypot-auditor:threat={report.threat_level}",
    ]
    if report.confidence:
        tags.append(f"honeypot-auditor:confidence={report.confidence}")
    for ind in report.triggered():
        tags.append(f"tell:{ind.id}")
    return CtiContext(
        target=report.target,
        resolved_ip=report.resolved_ip,
        score=report.score,
        threat_level=report.threat_level,
        started_at=report.started_at,
        finished_at=report.finished_at,
        observables=dict(report.observables or {}),
        triggered=list(report.triggered()),
        tags=tags,
    )
