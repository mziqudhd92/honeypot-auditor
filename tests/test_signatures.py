"""Declarative signature loader tests."""

from __future__ import annotations

from honeypot_auditor.signatures.loader import (
    load_core_pack,
    load_signature_file,
    match_rule,
    validate_signature_doc,
)


def test_core_pack_loads():
    pack = load_core_pack()
    assert len(pack.rules) >= 2


def test_exact_bytes_rejects_empty_needle():
    from honeypot_auditor.signatures.loader import SignatureRule, match_rule

    rule = SignatureRule(
        id="bad.empty",
        title="empty",
        primitive="exact_bytes",
        params={"value": ""},
    )
    assert match_rule(rule, body=b"anything") is False
    errors = validate_signature_doc(
        {
            "name": "x",
            "version": "1",
            "rules": [
                {
                    "id": "bad.empty",
                    "title": "empty",
                    "primitive": "exact_bytes",
                    "params": {"value": ""},
                }
            ],
        }
    )
    assert any("non-empty" in e for e in errors)


def test_validate_rejects_banned_keys():
    errors = validate_signature_doc({"match": "evil()", "rules": []})
    assert any("banned" in e for e in errors)


def test_match_regex_primitive():
    from pathlib import Path

    path = (
        Path(__file__).resolve().parents[1] / "src/honeypot_auditor/signatures/core/ftp_desert.json"
    )
    pack = load_signature_file(path)
    rule = pack.rules[0]
    assert match_rule(rule, body=b"500 Unknown command")


def test_malicious_yaml_cannot_exec():
    doc = {"rules": [{"id": "x", "primitive": "exec", "params": {}}]}
    errors = validate_signature_doc(doc)
    assert errors
