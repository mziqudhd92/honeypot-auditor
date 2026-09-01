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
        if ind.skipped or ind.suppressed:
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


def compute_confidence(indicators: list[Indicator], *, deep: bool = False) -> str:
    """Derive low/medium/high confidence from audit breadth."""
    attempted = [i for i in indicators if not i.skipped]
    if not attempted:
        return "low"
    skipped_ratio = sum(1 for i in indicators if i.skipped) / max(len(indicators), 1)
    if skipped_ratio > 0.5:
        return "low"
    triggered = [i for i in attempted if i.triggered and not i.suppressed]
    protos = _protocol_hits(indicators)
    categories = {i.category for i in triggered}
    if len(triggered) <= 1 and len(protos) < 3:
        return "low"
    deep_cats = sum(1 for c in categories if c in DEEP_WEIGHTS)
    if len(protos) >= 5 or (deep and deep_cats >= 3):
        return "high"
    if len(protos) >= 3 and len(categories) >= 2:
        return "medium"
    return "medium" if len(protos) >= 3 else "low"


def collect_proxy_evidence(indicators: list[Indicator]) -> list[str]:
    """Gather reverse-proxy/CDN evidence from HTTP indicator wire captures."""
    from honeypot_auditor.httpwire import parse_header_map
    from honeypot_auditor.proxy_detect import detect_proxy_from_headers

    evidence: list[str] = []
    for ind in indicators:
        if ind.suppression_reason == "reverse_proxy_detected":
            evidence.append(f"indicator:{ind.id}")
        if not ind.evidence:
            continue
        if ind.id.startswith("http.") or ind.protocol.startswith("http"):
            headers = parse_header_map(ind.evidence)
            if headers:
                evidence.extend(detect_proxy_from_headers(headers).evidence)
        if ind.fingerprint_type in ("tls_ja3s", "tls_ja4s") and "cdn" in ind.detail.lower():
            evidence.append(f"tls_cdn:{ind.id}")
    return list(dict.fromkeys(evidence))


def apply_proxy_suppression(
    indicators: list[Indicator], proxy_detected: bool
) -> list[Indicator]:
    """Suppress edge-tier tells when proxy detected."""
    if not proxy_detected:
        return list(indicators)
    out: list[Indicator] = []
    for ind in indicators:
        if ind.tell_tier == "edge" and ind.triggered:
            out.append(
                Indicator(
                    id=ind.id,
                    title=ind.title,
                    category=ind.category,
                    triggered=False,
                    detail=f"{ind.detail} (suppressed: reverse proxy/CDN detected — origin tells still active)",
                    protocol=ind.protocol,
                    evidence=ind.evidence,
                    skipped=ind.skipped,
                    skip_reason=ind.skip_reason,
                    error=ind.error,
                    remediation=ind.remediation,
                    fingerprint_type=ind.fingerprint_type,
                    requires_corroboration=ind.requires_corroboration,
                    tell_tier=ind.tell_tier,
                    suppressed=True,
                    suppression_reason="reverse_proxy_detected",
                )
            )
        else:
            out.append(ind)
    return out


def compute_tactical_action(
    score: float,
    confidence: str,
    *,
    proxy_detected: bool,
    threat_level: str,
    indicators: list[Indicator],
) -> tuple[str, str]:
    """Formal Go/No-Go matrix for authorized red-team use."""
    if proxy_detected:
        return (
            "INCONCLUSIVE",
            "Edge proxy masks L4/TLS origin; use origin tells and manual verify.",
        )
    attempted = [i for i in indicators if not i.skipped]
    if not attempted or threat_level == "Inconclusive":
        skipped_ratio = sum(1 for i in indicators if i.skipped) / max(len(indicators), 1)
        if skipped_ratio > 0.5 or threat_level == "Inconclusive":
            return "INCONCLUSIVE", "Insufficient probe coverage or inconclusive threat level."
    if score >= 60:
        if confidence == "low":
            return (
                "PROCEED_CAUTION",
                "High score from limited probe breadth — verify manually.",
            )
        return "SKIP_TARGET", "High-confidence decoy signature."
    if score < 30 and confidence in ("medium", "high"):
        return "PIVOT_POSSIBLE", "Production-like behavior across protocols."
    if 30 <= score < 60:
        return "PROCEED_CAUTION", "Ambiguous — partial decoy signals."
    return "INCONCLUSIVE", "No clear tactical recommendation."


def apply_stack_corroboration(indicators: list[Indicator]) -> list[Indicator]:
    """Suppress requires_corroboration indicators without another category hit."""
    has_other = any(
        i.triggered
        and not i.skipped
        and not i.suppressed
        and not i.requires_corroboration
        and i.category not in ("corroboration", "info")
        for i in indicators
    )
    out: list[Indicator] = []
    for ind in indicators:
        if ind.requires_corroboration and ind.triggered and not has_other:
            out.append(
                Indicator(
                    id=ind.id,
                    title=ind.title,
                    category=ind.category,
                    triggered=False,
                    detail=f"{ind.detail} (suppressed: no corroborating tell)",
                    protocol=ind.protocol,
                    evidence=ind.evidence,
                    requires_corroboration=ind.requires_corroboration,
                    tell_tier=ind.tell_tier,
                )
            )
        else:
            out.append(ind)
    return out


def redact_indicators(indicators: list[Indicator]) -> list[Indicator]:
    from honeypot_auditor.redact import redact

    out: list[Indicator] = []
    honeytoken = False
    for ind in indicators:
        ev, found = redact(ind.evidence)
        det, found2 = redact(ind.detail)
        honeytoken = honeytoken or found or found2
        out.append(
            Indicator(
                id=ind.id,
                title=ind.title,
                category=ind.category,
                triggered=ind.triggered,
                detail=det,
                protocol=ind.protocol,
                evidence=ev,
                skipped=ind.skipped,
                skip_reason=ind.skip_reason,
                error=ind.error,
                remediation=ind.remediation,
                fingerprint_type=ind.fingerprint_type,
                requires_corroboration=ind.requires_corroboration,
                suppressed=ind.suppressed,
                suppression_reason=ind.suppression_reason,
                tell_tier=ind.tell_tier,
            )
        )
    if honeytoken:
        out.append(
            Indicator(
                id="info.honeytoken_detected",
                title="Synthetic credential pattern redacted from output",
                category="info",
                triggered=True,
                protocol="info",
                detail="Honeytoken patterns were redacted before export",
            )
        )
    return out


def build_deception_leaks(indicators: list[Indicator]) -> list[dict]:
    """Rank triggered tells for blue-team remediation."""
    from honeypot_auditor.config import DEEP_WEIGHTS, WEIGHTS

    weights = {**WEIGHTS, **DEEP_WEIGHTS}
    rows: list[dict] = []
    for ind in indicators:
        if not ind.triggered and not ind.suppressed:
            continue
        w = weights.get(ind.category, 0.1)
        rows.append(
            {
                "id": ind.id,
                "remediation": ind.remediation or ind.detail,
                "severity": "high" if w >= 0.25 else "medium" if w >= 0.15 else "low",
                "suppressed": ind.suppressed,
                "weight": w,
            }
        )
    rows.sort(key=lambda r: (-r["weight"], r["id"]))
    for i, row in enumerate(rows, 1):
        row["rank"] = i
    return rows


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
    capabilities: dict[str, bool] | None = None,
    capability_warnings: list[str] | None = None,
) -> AuditReport:
    indicators = redact_indicators(indicators)
    proxy_evidence = collect_proxy_evidence(indicators)
    proxy_detected = bool(proxy_evidence)
    proxy_context = "edge_proxy_present" if proxy_detected else ""
    indicators = apply_proxy_suppression(indicators, proxy_detected)
    if deep:
        indicators = apply_cotenancy_corroboration(indicators)
        indicators = apply_stack_corroboration(indicators)
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
    confidence = compute_confidence(indicators, deep=deep)
    tactical_action, tactical_rationale = compute_tactical_action(
        score,
        confidence,
        proxy_detected=proxy_detected,
        threat_level=threat_level(score, indicators),
        indicators=indicators,
    )
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
        confidence=confidence,
        proxy_detected=proxy_detected,
        proxy_evidence=proxy_evidence,
        proxy_context=proxy_context,
        capability_warnings=capability_warnings or [],
        capabilities=capabilities or {},
        tactical_action=tactical_action,
        tactical_rationale=tactical_rationale,
        deception_leaks=build_deception_leaks(indicators),
    )
