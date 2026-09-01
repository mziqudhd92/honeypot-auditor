"""Shared result types."""

from __future__ import annotations

from dataclasses import dataclass, field


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, bytearray):
        return bytes(value).decode("utf-8", "replace")
    return value if isinstance(value, str) else str(value)


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
    remediation: str = ""
    fingerprint_type: str = ""
    requires_corroboration: bool = False
    suppressed: bool = False
    suppression_reason: str = ""
    tell_tier: str = "origin"

    def __post_init__(self) -> None:
        self.id = _as_text(self.id)
        self.title = _as_text(self.title)
        self.category = _as_text(self.category)
        self.detail = _as_text(self.detail)
        self.protocol = _as_text(self.protocol)
        self.evidence = _as_text(self.evidence)
        self.skip_reason = _as_text(self.skip_reason)
        self.error = _as_text(self.error)
        self.remediation = _as_text(self.remediation)
        self.fingerprint_type = _as_text(self.fingerprint_type)
        self.suppression_reason = _as_text(self.suppression_reason)
        self.tell_tier = _as_text(self.tell_tier) or "origin"

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
            "remediation": self.remediation,
            "fingerprint_type": self.fingerprint_type,
            "requires_corroboration": self.requires_corroboration,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "tell_tier": self.tell_tier,
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
    protocol_strategies: list[dict] = field(default_factory=list)
    confidence: str = "medium"
    proxy_detected: bool = False
    proxy_evidence: list[str] = field(default_factory=list)
    proxy_context: str = ""
    capability_warnings: list[str] = field(default_factory=list)
    capabilities: dict[str, bool] = field(default_factory=dict)
    tactical_action: str = ""
    tactical_rationale: str = ""
    deception_leaks: list[dict] = field(default_factory=list)
    dual_stack: dict = field(default_factory=dict)

    def triggered(self) -> list[Indicator]:
        return [i for i in self.indicators if i.triggered and not i.skipped and not i.suppressed]


def optional_import(module: str):
    try:
        return __import__(module)
    except ImportError:
        return None
