"""Evaluate declarative signature packs against probe indicator evidence."""

from __future__ import annotations

import logging
from pathlib import Path

from honeypot_auditor.httpwire import parse_header_names
from honeypot_auditor.models import Indicator
from honeypot_auditor.settings import settings
from honeypot_auditor.signatures.loader import (
    SignaturePack,
    SignatureRule,
    load_core_pack,
    load_signature_file,
    match_rule,
)

_log = logging.getLogger(__name__)


def _load_active_pack() -> SignaturePack:
    if settings.signature_pack == "core":
        return load_core_pack()
    contrib = Path(__file__).resolve().parents[1] / "signatures" / "contrib"
    if contrib.is_dir():
        rules = []
        for pattern in ("*.json", "*.yaml", "*.yml"):
            for path in sorted(contrib.glob(pattern)):
                rules.extend(load_signature_file(path).rules)
        if rules:
            return SignaturePack(name="community", version="1", rules=rules)
    return load_core_pack()


def _indicator_body(ind: Indicator) -> bytes:
    text = ind.evidence or ind.detail or ""
    return text.encode("latin-1", "replace")


def _indicator_headers(ind: Indicator) -> list[str] | None:
    raw = ind.evidence or ind.detail or ""
    if "HTTP/" not in raw and "\r\n" not in raw and "\n" not in raw:
        return None
    return parse_header_names(raw)


def _indicator_ja3s(ind: Indicator) -> str:
    import json

    raw = ind.evidence
    if not raw or not isinstance(raw, str):
        return ""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    return str(data.get("ja3s", "") or "")


def evaluate_signatures(indicators: list[Indicator]) -> list[Indicator]:
    """Return additional indicators triggered by declarative signature rules."""
    try:
        pack = _load_active_pack()
    except Exception as exc:
        _log.warning("signature pack load failed: %s", exc)
        return []
    if not pack.rules:
        _log.warning(
            "signature pack %r has no rules (missing package data?)",
            getattr(pack, "name", settings.signature_pack),
        )
        return []
    out: list[Indicator] = []
    existing_ids = {i.id for i in indicators}
    for rule in pack.rules:
        if rule.id in existing_ids:
            continue
        if _rule_matches_any(rule, indicators):
            out.append(
                Indicator(
                    id=rule.id,
                    title=rule.title,
                    category=rule.category,
                    triggered=True,
                    protocol="signature",
                    detail=f"signature pack {pack.name} primitive={rule.primitive}",
                    remediation=rule.remediation,
                    fingerprint_type=f"sig_{rule.primitive}",
                )
            )
    return out


def _rule_matches_any(rule: SignatureRule, indicators: list[Indicator]) -> bool:
    for ind in indicators:
        if ind.skipped:
            continue
        body = _indicator_body(ind)
        headers = _indicator_headers(ind)
        ja3s = _indicator_ja3s(ind)
        if rule.primitive == "ja3s_equals":
            expect = str(rule.params.get("expect", ""))
            if ja3s and expect and ja3s == expect:
                return True
            continue
        if match_rule(rule, body=body, headers=headers, ja3s=ja3s):
            return True
    return False
