"""Shared result types."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Indicator:
    id: str
    title: str
    category: str
    triggered: bool = False
    detail: str = ""
    protocol: str = ""
    evidence: str = ""
    skipped: bool = False
    skip_reason: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "triggered": self.triggered,
            "detail": self.detail,
            "protocol": self.protocol,
            "evidence": self.evidence,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "error": self.error,
        }


def skipped_indicator(
    indicator_id: str,
    title: str,
    category: str,
    reason: str,
    *,
    protocol: str = "",
    error: str = "",
) -> Indicator:
    return Indicator(
        id=indicator_id,
        title=title,
        category=category,
        skipped=True,
        skip_reason=reason,
        protocol=protocol,
        error=error,
        detail=reason,
    )


@dataclass
class AuditReport:
    target: str
    resolved_ip: str
    score: float
    threat_level: str
    category_hits: dict
    indicators: list[Indicator] = field(default_factory=list)
    ports: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def triggered(self) -> list[Indicator]:
        return [i for i in self.indicators if i.triggered and not i.skipped]


def optional_import(module: str):
    try:
        return __import__(module)
    except ImportError:
        return None
