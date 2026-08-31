"""Risk aggregation: composite Honeyscore S = Σ (W_i · I_i)."""

from __future__ import annotations

from collections.abc import Iterable

from honeypot_auditor.config import (
    BASIC_STRATEGIES,
    CORROBORATION_PROTOCOL_MAX_BONUS,
    CORROBORATION_PROTOCOL_STEP_PCT,
    CORROBORATION_PROTOCOL_THRESHOLD,
    COTENANCY_CORROBORATION_CATEGORIES,
    DEEP_WEIGHTS,
    PROTOCOL_STRATEGIES,
    THREAT_CONFIRMED,
    THREAT_LEVELS,
    THREAT_SUSPECTED,
    WEIGHTS,
    as_port_list,
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


def buffet_cotenancy_indicator(indicators: list[Indicator]) -> Indicator | None:
    """Score multi-lure buffets when several protocol probes fire with corroboration."""
    has_corroboration = any(
        ind.triggered and not ind.skipped and ind.category in COTENANCY_CORROBORATION_CATEGORIES
        for ind in indicators
    )
    if not has_corroboration:
        return None
    hit_protocols: list[str] = []
    seen: set[str] = set()
    for ind in indicators:
        if ind.skipped or not ind.triggered:
            continue
        if ind.category not in BASIC_STRATEGIES:
            continue
        proto = _protocol_name(ind.protocol)
        if proto not in PROTOCOL_STRATEGIES or proto in seen:
            continue
        seen.add(proto)
        hit_protocols.append(proto)
    threshold = 5
    if len(hit_protocols) < threshold:
        return None
    names = ", ".join(sorted(hit_protocols)[:12])
    if len(hit_protocols) > 12:
        names += ", …"
    return Indicator(
        id="cotenancy.buffet",
        title="Multiple protocol lures fired on one host",
        category="cotenancy",
        triggered=True,
        protocol="multi",
        detail=f"{len(hit_protocols)} protocol lures hit (>={threshold} with corroboration): {names}",
        evidence=",".join(sorted(hit_protocols)),
    )


def _protocol_hits(indicators: Iterable[Indicator]) -> list[str]:
    seen: set[str] = set()
    hits: list[str] = []
    for ind in indicators:
        if ind.skipped or not ind.triggered or ind.category not in BASIC_STRATEGIES:
            continue
        proto = _protocol_name(ind.protocol)
        if proto not in PROTOCOL_STRATEGIES or proto in seen:
            continue
        seen.add(proto)
        hits.append(proto)
    return sorted(hits)


def protocol_corroboration_bonus(indicators: list[Indicator]) -> tuple[float, Indicator | None]:
    """+5% per extra protocol lure beyond the first when basic tells already corroborate."""
    has_corroboration = any(
        ind.triggered and not ind.skipped and ind.category in COTENANCY_CORROBORATION_CATEGORIES
        for ind in indicators
    )
    if not has_corroboration:
        return 0.0, None
    protos = _protocol_hits(indicators)
    extra = max(0, len(protos) - CORROBORATION_PROTOCOL_THRESHOLD)
    bonus = min(CORROBORATION_PROTOCOL_MAX_BONUS, extra * CORROBORATION_PROTOCOL_STEP_PCT)
    if bonus <= 0:
        return 0.0, None
    names = ", ".join(protos[:12])
    if len(protos) > 12:
        names += ", …"
    return bonus, Indicator(
        id="corroboration.protocol_buffet",
        title="Multiple protocol tells corroborate the same host",
        category="corroboration",
        triggered=True,
        protocol="multi",
        detail=(
            f"+{bonus:.0f}% for {len(protos)} protocol lures "
            f"(>{CORROBORATION_PROTOCOL_THRESHOLD} at {CORROBORATION_PROTOCOL_STEP_PCT:.0f}% each): {names}"
        ),
        evidence=",".join(protos),
    )


def multi_user_arbitrary_auth(indicators: Iterable[Indicator]) -> bool:
    """Any-password on two random accounts is definitive — no real service does this."""
    for ind in indicators:
        if ind.skipped or not ind.triggered or ind.category != "arbitrary_auth":
            continue
        if "," in (ind.evidence or ""):
            return True
    return False


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
    return min(round(total, 2), 100.0), hits


def _protocol_name(protocol: str) -> str:
    return (protocol or "").split(":", 1)[0]


def protocol_strategy_matrix(
    indicators: Iterable[Indicator],
    ports: dict,
) -> list[dict]:
    """Per-protocol status of the three basic strategies for this audit."""
    rows: list[dict] = []
    for proto, catalog in PROTOCOL_STRATEGIES.items():
        port_list = as_port_list(ports.get(proto))
        if not port_list:
            continue
        proto_inds = [i for i in indicators if _protocol_name(i.protocol) == proto]
        cells: dict = {"protocol": proto, "ports": port_list}
        for strat in BASIC_STRATEGIES:
            playbook = catalog.get(strat) or ""
            if not playbook:
                cells[strat] = {"status": "n/a", "playbook": "", "detail": ""}
                continue
            matching = [i for i in proto_inds if i.category == strat]
            if not matching:
                cells[strat] = {"status": "skip", "playbook": playbook, "detail": "no indicator emitted"}
                continue
            live = [i for i in matching if not i.skipped]
            if not live:
                cells[strat] = {
                    "status": "skip",
                    "playbook": playbook,
                    "detail": matching[0].skip_reason or matching[0].detail,
                }
                continue
            hits = [i for i in live if i.triggered]
            if hits:
                cells[strat] = {"status": "hit", "playbook": playbook, "detail": hits[0].detail}
            else:
                cells[strat] = {"status": "clean", "playbook": playbook, "detail": live[0].detail}
        rows.append(cells)
    return rows


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
    if not any(i.category == "cotenancy" for i in indicators):
        buffet = buffet_cotenancy_indicator(indicators)
        if buffet is not None:
            indicators = [*indicators, buffet]
    score, hits = compute_score(indicators, deep=deep)
    bonus, corroboration = protocol_corroboration_bonus(indicators)
    if corroboration is not None:
        indicators = [*indicators, corroboration]
    if bonus > 0:
        score = min(round(score + bonus, 2), 100.0)
        hits["corroboration"] = {
            "weight": 0.0,
            "triggered": True,
            "contribution": bonus,
            "attempted": True,
            "dynamic": True,
        }
    if multi_user_arbitrary_auth(indicators):
        score = 100.0
        for key in hits:
            hits[key]["contribution"] = 0.0
        hits["arbitrary_auth"]["triggered"] = True
        hits["arbitrary_auth"]["contribution"] = 100.0
        hits["arbitrary_auth"]["dynamic"] = True
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
        protocol_strategies=protocol_strategy_matrix(indicators, ports),
    )
