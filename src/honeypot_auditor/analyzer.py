"""Risk aggregation: composite Honeyscore S = Σ (W_i · I_i)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from honeypot_auditor.config import (
    BASIC_STRATEGIES,
    CORROBORATION_PROTOCOL_MAX_BONUS,
    CORROBORATION_PROTOCOL_STEP_PCT,
    CORROBORATION_PROTOCOL_THRESHOLD,
    COTENANCY_CORROBORATION_CATEGORIES,
    DEEP_WEIGHTS,
    HIGH_SIGNAL_BONUS_PCT,
    HIGH_SIGNAL_FIDELITIES,
    INTRA_CATEGORY_MAX_BONUS_PCT,
    INTRA_CATEGORY_STEP_PCT,
    PROTOCOL_STRATEGIES,
    THREAT_CONFIRMED,
    THREAT_LEVELS,
    THREAT_SUSPECTED,
    WEIGHTS,
    as_port_list,
)
from honeypot_auditor.models import AuditReport, Indicator


def category_triggered(indicators: Iterable[Indicator], category: str) -> bool:
    return category_hit_count(indicators, category) > 0


def category_hit_count(indicators: Iterable[Indicator], category: str) -> int:
    return sum(
        1
        for ind in indicators
        if ind.category == category
        and ind.triggered
        and not ind.skipped
        and not ind.suppressed
    )


def category_attempted(indicators: Iterable[Indicator], category: str) -> bool:
    for ind in indicators:
        if ind.category == category and not ind.skipped:
            return True
    return False


def _intra_category_bonus(hit_count: int) -> float:
    """Diminishing corroboration for extra hits in the same category."""
    if hit_count <= 1:
        return 0.0
    return min(INTRA_CATEGORY_MAX_BONUS_PCT, (hit_count - 1) * INTRA_CATEGORY_STEP_PCT)


def unique_ports(ports: dict) -> list[int]:
    found: list[int] = []
    for value in ports.values():
        found.extend(as_port_list(value))
    return sorted(set(found))


def is_targeted_single_port(ports: dict) -> bool:
    """True when the audit surface is a single TCP port (typical `-p` scan)."""
    return len(unique_ports(ports)) == 1


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
                replace(
                    ind,
                    triggered=False,
                    detail=f"{ind.detail} (suppressed: no corroborating tell)",
                )
            )
        elif should_trigger:
            out.append(
                replace(
                    ind,
                    triggered=True,
                    detail=f"{ind.detail} (>={threshold} with corroboration)",
                )
            )
        else:
            out.append(ind)
    return out


def silent_accept_cluster_indicator(indicators: list[Indicator]) -> Indicator | None:
    """≥2 silent-accept ports is a classic tarpit / non-speaking listener cluster."""
    hits = [
        ind
        for ind in indicators
        if ind.triggered and not ind.skipped and ind.id.endswith(".silent_accept")
    ]
    if len(hits) < 2:
        return None
    labels = sorted({f"{_protocol_name(ind.protocol)}" for ind in hits})
    return Indicator(
        id="cotenancy.silent_accept_cluster",
        title="Multiple ports accept TCP then return no application response",
        category="cotenancy",
        triggered=True,
        protocol="multi",
        detail=f"{len(hits)} silent-accept faces across {', '.join(labels)}",
        evidence=",".join(sorted(ind.id for ind in hits)),
        remediation="Refuse unused listeners or speak the expected protocol; silent accepts look like tarpits",
    )


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


def _is_high_signal(ind: Indicator) -> bool:
    return (ind.fidelity or "").lower() in HIGH_SIGNAL_FIDELITIES


def high_signal_bonus(indicators: list[Indicator]) -> tuple[float, Indicator | None]:
    """Bonus for fidelity=high/decisive tells (e.g. Cowrie KEX, POP3 auth-failed blanket)."""
    hits = [
        ind
        for ind in indicators
        if ind.triggered and not ind.skipped and not ind.suppressed and _is_high_signal(ind)
    ]
    if not hits:
        return 0.0, None
    names = ", ".join(sorted({ind.id for ind in hits}))
    return HIGH_SIGNAL_BONUS_PCT, Indicator(
        id="corroboration.high_signal",
        title="High-signal decoy fingerprint",
        category="corroboration",
        triggered=True,
        protocol="multi",
        fidelity="high",
        detail=f"+{HIGH_SIGNAL_BONUS_PCT:.0f}% for high-fidelity tell(s): {names}",
        evidence=names,
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
        hit_count = category_hit_count(indicators, category)
        hit = hit_count > 0
        primary = (weight * 100.0) if hit else 0.0
        intra = _intra_category_bonus(hit_count) if hit else 0.0
        contribution = primary + intra
        hits[category] = {
            "weight": weight,
            "triggered": hit,
            "hit_count": hit_count,
            "intra_category_bonus": intra,
            "contribution": contribution,
            "attempted": category_attempted(indicators, category),
        }
        if hit:
            total += contribution
    return min(round(total, 2), 100.0), hits


def compute_scoped_score(
    category_hits: dict,
    *,
    bonus_total_pct: float,
    ports: dict,
    decisive_override: bool = False,
    deep: bool = False,
) -> tuple[float | None, dict]:
    """Normalize global contributions against in-scope category weight for `-p` scans.

    Scoped = (category_total + bonuses) / (Σ in_scope_weights × 100) × 100

    In-scope categories are those the probed protocol(s) can exercise (basic strategies
    with a playbook), plus any other category that was actually attempted. Auth-gated
    skips (e.g. SSH state checks) stay in the denominator so single-port audits are
    not over-normalized.
    """
    detail: dict = {
        "applicable": False,
        "reason": "full_or_multi_port_surface",
        "attempted_weight": 0.0,
        "denominator_pct": 0.0,
        "numerator_pct": 0.0,
        "score_pct": None,
    }
    if not is_targeted_single_port(ports):
        return None, detail

    weights = _active_weights(deep)
    in_scope: set[str] = set()
    for proto in ports:
        catalog = PROTOCOL_STRATEGIES.get(proto) or {}
        for strat in BASIC_STRATEGIES:
            if catalog.get(strat):
                in_scope.add(strat)

    category_total = 0.0
    for category, row in category_hits.items():
        if row.get("dynamic"):
            continue
        category_total += float(row.get("contribution", 0.0))
        if row.get("attempted"):
            in_scope.add(category)

    attempted_weight = sum(weights[c] for c in in_scope if c in weights)
    detail["reason"] = "single_port_scan"
    detail["attempted_weight"] = round(attempted_weight, 4)
    detail["in_scope_categories"] = sorted(in_scope)
    if attempted_weight <= 0:
        detail["reason"] = "single_port_no_attempted_categories"
        return None, detail

    denominator = attempted_weight * 100.0
    numerator = category_total + bonus_total_pct
    scoped = 100.0 if decisive_override else min(100.0, round(numerator / denominator * 100.0, 2))
    detail.update(
        {
            "applicable": True,
            "denominator_pct": round(denominator, 2),
            "numerator_pct": round(numerator, 2),
            "score_pct": scoped,
            "decisive_override": bool(decisive_override),
        }
    )
    return scoped, detail


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
                cells[strat] = {
                    "status": "skip",
                    "playbook": playbook,
                    "detail": "no indicator emitted",
                }
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


def threat_level(
    score: float,
    indicators: list[Indicator],
    *,
    scoped_score: float | None = None,
) -> str:
    attempted = [i for i in indicators if not i.skipped]
    if not attempted:
        return THREAT_LEVELS["inconclusive"]
    effective = score if scoped_score is None else max(score, scoped_score)
    if effective >= THREAT_CONFIRMED:
        return THREAT_LEVELS["confirmed"]
    if effective >= THREAT_SUSPECTED:
        return THREAT_LEVELS["suspected"]
    triggered = [i for i in attempted if i.triggered and not i.suppressed]
    if triggered:
        return THREAT_LEVELS["anomalies"]
    return THREAT_LEVELS["likely_real"]


def compute_confidence(indicators: list[Indicator], *, deep: bool = False) -> str:
    """Derive low/medium/high confidence from audit breadth."""
    if multi_user_arbitrary_auth(indicators):
        return "high"
    relevant = [i for i in indicators if not _is_never_applicable_skip(i)]
    attempted = [i for i in relevant if not i.skipped]
    if not attempted:
        return "low"
    skipped_ratio = sum(1 for i in relevant if i.skipped) / max(len(relevant), 1)
    triggered = [i for i in attempted if i.triggered and not i.suppressed]
    protos = _protocol_hits(indicators)
    categories = {i.category for i in triggered}
    high_signal = any(_is_high_signal(i) for i in triggered)

    if skipped_ratio > 0.5:
        level = "low"
    elif len(triggered) <= 1 and len(protos) < 3:
        level = "low"
    else:
        deep_cats = sum(1 for c in categories if c in DEEP_WEIGHTS)
        if len(protos) >= 5 or (deep and deep_cats >= 3):
            level = "high"
        elif len(protos) >= 3 and len(categories) >= 2:
            level = "medium"
        else:
            level = "medium" if len(protos) >= 3 else "low"

    # A high-fidelity pre-auth fingerprint (Cowrie KEX facade) is medium even alone.
    if high_signal and level == "low":
        return "medium"
    return level


_NEVER_APPLICABLE_SKIP_MARKERS = (
    "no api key",
    "connection refused",
    "closed port or filtered",
    "closed port",
    "safe-mode",
    "disabled (",
    "not installed",
    "pass --with-nmap",
    "needs the requests package",
    "no session (auth failed)",
    "need two sessions",
)


def _is_never_applicable_skip(ind: Indicator) -> bool:
    """Skips that should not drag confidence down (missing optional deps / closed ports)."""
    if not ind.skipped:
        return False
    reason = f"{ind.skip_reason or ''} {ind.detail or ''}".lower()
    return any(marker in reason for marker in _NEVER_APPLICABLE_SKIP_MARKERS)


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


def apply_proxy_suppression(indicators: list[Indicator], proxy_detected: bool) -> list[Indicator]:
    """Suppress edge-tier tells when proxy detected."""
    if not proxy_detected:
        return list(indicators)
    out: list[Indicator] = []
    for ind in indicators:
        if ind.tell_tier == "edge" and ind.triggered:
            out.append(
                replace(
                    ind,
                    triggered=False,
                    detail=(
                        f"{ind.detail} (suppressed: reverse proxy/CDN detected — "
                        "origin tells still active)"
                    ),
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
    relevant = [i for i in indicators if not _is_never_applicable_skip(i)]
    attempted = [i for i in relevant if not i.skipped]
    triggered = [i for i in attempted if i.triggered and not i.suppressed]
    if not attempted or threat_level == "Inconclusive" or threat_level.startswith(
        "Inconclusive ("
    ):
        denom = max(len(relevant), 1)
        skipped_ratio = sum(1 for i in relevant if i.skipped) / denom
        if skipped_ratio > 0.5 or threat_level == "Inconclusive":
            return "INCONCLUSIVE", "Insufficient probe coverage or inconclusive threat level."
        if threat_level.startswith("Inconclusive (") and triggered:
            return (
                "PROCEED_CAUTION",
                "Low-confidence anomalies — verify manually before pivoting.",
            )
    if multi_user_arbitrary_auth(indicators) and score >= 60:
        return (
            "SKIP_TARGET",
            "Multi-user any-password is a definitive low-interaction decoy signature.",
        )
    if score >= 60:
        if confidence == "low":
            return (
                "PROCEED_CAUTION",
                "High score from limited probe breadth — verify manually.",
            )
        return "SKIP_TARGET", "High-confidence decoy signature."
    if score < 30 and not triggered and confidence in ("medium", "high"):
        return "PIVOT_POSSIBLE", "Production-like behavior across protocols."
    if 30 <= score < 60:
        return "PROCEED_CAUTION", "Ambiguous — partial decoy signals."
    if triggered:
        return "PROCEED_CAUTION", "Low-confidence anomalies — verify manually."
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
                replace(
                    ind,
                    triggered=False,
                    detail=f"{ind.detail} (suppressed: no corroborating tell)",
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
        out.append(replace(ind, evidence=ev, detail=det))
    if honeytoken:
        out.append(
            Indicator(
                id="info.honeytoken_detected",
                title="Synthetic credential pattern redacted from output",
                category="info",
                triggered=True,
                protocol="info",
                detail="Honeytoken patterns were redacted before export",
                fidelity="low",
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


def build_score_breakdown(
    category_hits: dict,
    *,
    protocol_bonus: float,
    high_signal_bonus_pct: float,
    decisive_override: bool,
    scoped: dict | None = None,
) -> dict:
    """Build an additive, machine-readable explanation of the headline score."""
    categories: list[dict[str, str | float | bool | int]] = []
    for category, row in category_hits.items():
        if row.get("dynamic"):
            continue
        categories.append(
            {
                "category": category,
                "weight_pct": round(float(row.get("weight", 0.0)) * 100.0, 2),
                "attempted": bool(row.get("attempted")),
                "triggered": bool(row.get("triggered")),
                "hit_count": int(row.get("hit_count") or 0),
                "intra_category_bonus_pct": round(float(row.get("intra_category_bonus") or 0.0), 2),
                "contribution_pct": round(float(row.get("contribution", 0.0)), 2),
            }
        )
    category_total = round(sum(float(row["contribution_pct"]) for row in categories), 2)
    bonuses: list[dict[str, str | float]] = []
    if protocol_bonus:
        bonuses.append(
            {
                "id": "protocol_corroboration",
                "contribution_pct": round(protocol_bonus, 2),
            }
        )
    if high_signal_bonus_pct:
        bonuses.append(
            {
                "id": "high_signal_fingerprint",
                "contribution_pct": round(high_signal_bonus_pct, 2),
            }
        )
    bonus_total = round(sum(float(row["contribution_pct"]) for row in bonuses), 2)
    raw_score = round(category_total + bonus_total, 2)
    capped_score = min(raw_score, 100.0)
    final_score = 100.0 if decisive_override else capped_score
    payload: dict = {
        "formula": (
            "min(category_total + bonus_total, 100); "
            "intra-category +7.5% per extra hit (cap +15%); "
            "repeated arbitrary auth overrides to 100"
        ),
        "categories": categories,
        "category_total_pct": category_total,
        "bonuses": bonuses,
        "bonus_total_pct": bonus_total,
        "raw_score_pct": raw_score,
        "cap_applied": raw_score > 100.0,
        "score_before_override_pct": capped_score,
        "decisive_override": "multi_user_arbitrary_auth" if decisive_override else None,
        "final_score_pct": final_score,
    }
    if scoped:
        payload["scoped"] = scoped
    return payload


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
    if not any(i.id == "cotenancy.silent_accept_cluster" for i in indicators):
        cluster = silent_accept_cluster_indicator(indicators)
        if cluster is not None:
            indicators = [*indicators, cluster]
    if not any(i.id == "cotenancy.buffet" for i in indicators):
        buffet = buffet_cotenancy_indicator(indicators)
        if buffet is not None:
            indicators = [*indicators, buffet]
    score, hits = compute_score(indicators, deep=deep)
    bonus, corroboration = protocol_corroboration_bonus(indicators)
    if corroboration is not None:
        indicators = [*indicators, corroboration]
    signal_bonus, signal_ind = high_signal_bonus(indicators)
    if signal_ind is not None:
        indicators = [*indicators, signal_ind]
    total_bonus = bonus + signal_bonus
    if total_bonus > 0:
        score = min(round(score + total_bonus, 2), 100.0)
        hits["corroboration"] = {
            "weight": 0.0,
            "triggered": True,
            "contribution": total_bonus,
            "attempted": True,
            "dynamic": True,
        }
    decisive_override = multi_user_arbitrary_auth(indicators)
    scoped_score, scoped_detail = compute_scoped_score(
        hits,
        bonus_total_pct=total_bonus,
        ports=ports,
        decisive_override=decisive_override,
        deep=deep,
    )
    score_breakdown = build_score_breakdown(
        hits,
        protocol_bonus=bonus,
        high_signal_bonus_pct=signal_bonus,
        decisive_override=decisive_override,
        scoped=scoped_detail,
    )
    score = score_breakdown["final_score_pct"]
    if decisive_override:
        score = 100.0
        # Keep secondary category contributions visible for analysts; the
        # any-password bonus caps the headline score without erasing other hits.
        hits["arbitrary_auth"]["triggered"] = True
        hits["arbitrary_auth"]["contribution"] = 100.0
        hits["arbitrary_auth"]["dynamic"] = True
        if scoped_score is not None:
            scoped_score = 100.0
            scoped_detail["score_pct"] = 100.0
            score_breakdown["scoped"] = scoped_detail
    level = threat_level(score, indicators, scoped_score=scoped_score)
    confidence = compute_confidence(indicators, deep=deep)
    effective = score if scoped_score is None else max(score, scoped_score)
    tactical_action, tactical_rationale = compute_tactical_action(
        effective,
        confidence,
        proxy_detected=proxy_detected,
        threat_level=level,
        indicators=indicators,
    )
    return AuditReport(
        target=target,
        resolved_ip=resolved_ip,
        score=score,
        threat_level=level,
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
        score_breakdown=score_breakdown,
        scoped_score=scoped_score,
    )
