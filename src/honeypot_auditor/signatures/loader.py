"""Declarative signature loader and matcher."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BANNED_KEYS = frozenset({"match", "exec", "eval", "hook", "python", "import"})

ALLOWED_PRIMITIVES = frozenset(
    {
        "exact_bytes",
        "regex",
        "header_sequence",
        "header_absent",
        "ja3s_equals",
        "http2_settings_sequence",
        "jmespath",
    }
)


@dataclass
class SignatureRule:
    id: str
    title: str
    category: str = "static_signature"
    primitive: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""


@dataclass
class SignaturePack:
    name: str
    version: str
    rules: list[SignatureRule] = field(default_factory=list)


def _core_dir() -> Path:
    return Path(__file__).resolve().parent / "core"


def validate_signature_doc(doc: dict) -> list[str]:
    """Return validation errors (empty if valid)."""
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["root must be an object"]
    for key in doc:
        if key in BANNED_KEYS:
            errors.append(f"banned key: {key}")
    rules = doc.get("rules")
    if not isinstance(rules, list):
        errors.append("rules must be a list")
        return errors
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"rules[{i}] must be an object")
            continue
        for key in rule:
            if key in BANNED_KEYS:
                errors.append(f"rules[{i}] banned key: {key}")
        prim = rule.get("primitive", "")
        if prim and prim not in ALLOWED_PRIMITIVES:
            errors.append(f"rules[{i}] unknown primitive: {prim}")
        if prim == "regex":
            pattern = (rule.get("params") or {}).get("pattern", "")
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"rules[{i}] invalid regex: {exc}")
        if prim == "exact_bytes":
            needle = (rule.get("params") or {}).get("value", "")
            if needle is None or needle == "":
                errors.append(f"rules[{i}] exact_bytes value must be non-empty")
    return errors


def load_signature_file(path: Path) -> SignaturePack:
    raw = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError("pyyaml required for YAML signatures") from exc
        doc = yaml.safe_load(raw)
    else:
        doc = json.loads(raw)
    errors = validate_signature_doc(doc)
    if errors:
        raise ValueError("; ".join(errors))
    rules: list[SignatureRule] = []
    for rule in doc.get("rules", []):
        rules.append(
            SignatureRule(
                id=str(rule.get("id", "")),
                title=str(rule.get("title", "")),
                category=str(rule.get("category", "static_signature")),
                primitive=str(rule.get("primitive", "")),
                params=dict(rule.get("params") or {}),
                remediation=str(rule.get("remediation", "")),
            )
        )
    return SignaturePack(
        name=str(doc.get("name", path.stem)),
        version=str(doc.get("version", "1")),
        rules=rules,
    )


def load_core_pack() -> SignaturePack:
    rules: list[SignatureRule] = []
    for path in sorted(_core_dir().glob("*.json")):
        pack = load_signature_file(path)
        rules.extend(pack.rules)
    return SignaturePack(name="core", version="1", rules=rules)


def match_rule(
    rule: SignatureRule,
    *,
    body: bytes = b"",
    headers: list[str] | None = None,
    ja3s: str = "",
) -> bool:
    params = rule.params
    if rule.primitive == "exact_bytes":
        needle = params.get("value", "")
        if isinstance(needle, str):
            needle = needle.encode("latin-1")
        if not needle:
            return False
        return needle in body
    if rule.primitive == "regex":
        pattern = params.get("pattern", "")
        text = body.decode("latin-1", "replace")
        return bool(re.search(pattern, text))
    if rule.primitive == "header_sequence":
        expected = params.get("names") or []
        return headers is not None and headers == list(expected)
    if rule.primitive == "header_absent":
        name = str(params.get("name", "")).lower()
        if headers is None:
            return False
        lower = [h.lower() for h in headers]
        return name not in lower
    if rule.primitive == "ja3s_equals":
        expect = str(params.get("expect", ""))
        observed = str(params.get("observed", ja3s))
        return bool(expect) and observed == expect
    if rule.primitive == "http2_settings_sequence":
        order = params.get("order") or []
        return headers is not None and headers == list(order)
    if rule.primitive == "jmespath":
        return False  # evaluated by caller with parsed JSON
    return False
