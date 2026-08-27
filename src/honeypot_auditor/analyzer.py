"""Risk aggregation: composite Honeyscore S = Σ (W_i · I_i)."""

from __future__ import annotations

from collections.abc import Iterable

from honeypot_auditor.config import (
    COTENANCY_CORROBORATION_CATEGORIES,
    DEEP_WEIGHTS,
    THREAT_CONFIRMED,
    THREAT_LEVELS,
    THREAT_SUSPECTED,
    WEIGHTS,
)
from honeypot_auditor.models import AuditReport, Indicator


def category_triggered(indicators: Iterable[Indicator], category: str) -> bool:
    for ind in indicators:
        if ind.skipped:
            continue
        if ind.category == category and ind.triggered:
            return True
    return False


def category_attempted(indicators: Iterable[Indicator], category: str) -> bool:
    for ind in indicators:
        if ind.category == category and not ind.skipped:
            return True
    return False


def _active_weights(deep: bool) -> dict[str, float]:
    if not deep:
        return dict(WEIGHTS)
    merged = dict(WEIGHTS)
    merged.update(DEEP_WEIGHTS)
    return merged


def apply_cotenancy_corroboration(indicators: list[Indicator]) -> list[Indicator]:
    """Co-tenancy scores only with corroboration; upgrade when buffet + other tells."""
    has_corroboration = any(
        ind.triggered and not ind.skipped and ind.category in COTENANCY_CORROBORATION_CATEGORIES
        for ind in indicators
    )
    out: list[Indicator] = []
    for ind in indicators:
        if ind.id != "deep.cotenancy":
            out.append(ind)
            continue
        # Parse "N responsive IT lures" from detail
        count = 0
        if " responsive IT lures" in ind.detail:
            try:
                count = int(ind.detail.split(" responsive IT lures", 1)[0].strip())
            except ValueError:
                count = len([x for x in ind.evidence.split(",") if x])
        threshold = 4 if has_corroboration else 8
        should_trigger = count >= threshold
        if should_trigger and not has_corroboration:
            out.append(
                Indicator(
                    id=ind.id,
                    title=ind.title,
                    category=ind.category,
                    triggered=False,
                    protocol=ind.protocol,
                    detail=f"{ind.detail} (suppressed: no corroborating tell)",
                    evidence=ind.evidence,
                )
            )
        elif should_trigger:
            out.append(
                Indicator(
                    id=ind.id,
                    title=ind.title,
                    category=ind.category,
                    triggered=True,
                    protocol=ind.protocol,
                    detail=f"{ind.detail} (>={threshold} with corroboration)",
                    evidence=ind.evidence,
                )
            )
        else:
            out.append(ind)
    return out


def compute_score(indicators: list[Indicator], *, deep: bool = False) -> tuple[float, dict]:
    weights = _active_weights(deep)
    hits = {}
    total = 0.0
    for category, weight in weights.items():
        hit = category_triggered(indicators, category)
        hits[category] = {
            "weight": weight,
            "triggered": hit,
            "contribution": (weight * 100.0) if hit else 0.0,
            "attempted": category_attempted(indicators, category),
        }
        if hit:
            total += weight * 100.0
    return round(total, 2), hits


def threat_level(score: float, indicators: list[Indicator]) -> str:
    attempted = [i for i in indicators if not i.skipped]
    if not attempted:
        return THREAT_LEVELS["inconclusive"]
    if score >= THREAT_CONFIRMED:
        return THREAT_LEVELS["confirmed"]
    if score >= THREAT_SUSPECTED:
        return THREAT_LEVELS["suspected"]
    return THREAT_LEVELS["likely_real"]


def build_report(
    *,
    target: str,
    resolved_ip: str,
    ports: dict,
    indicators: list[Indicator],
    notes: list[str],
    started_at: str,
    finished_at: str,
    deep: bool = False,
) -> AuditReport:
    if deep:
        indicators = apply_cotenancy_corroboration(indicators)
    score, hits = compute_score(indicators, deep=deep)
    return AuditReport(
        target=target,
        resolved_ip=resolved_ip,
        score=score,
        threat_level=threat_level(score, indicators),
        category_hits=hits,
        indicators=indicators,
        ports=ports,
        notes=notes,
        started_at=started_at,
        finished_at=finished_at,
    )
