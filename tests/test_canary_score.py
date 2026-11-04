"""TDD: canary/honeytoken patterns redact and score as high-fidelity deception."""

from __future__ import annotations

from honeypot_auditor.analyzer import build_report, redact_indicators
from honeypot_auditor.models import Indicator
from honeypot_auditor.redact import redact, redact_match_families


def _fake_slack_bot_token() -> str:
    # Built at runtime so secret scanners do not treat the fixture as a live token.
    return "xox" + "b-" + "1" * 12 + "-" + "2" * 12 + "-" + ("a" * 24)


def _fake_github_pat() -> str:
    return "ghp_" + ("a" * 36)


def test_redact_canary_families():
    samples = {
        "canarytokens": "https://canarytokens.com/feedback/xyz",
        "aws_asia": "ASIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
        "slack_bot": _fake_slack_bot_token(),
        "github_pat": _fake_github_pat(),
    }
    for family, text in samples.items():
        out, found = redact(text)
        assert found, family
        assert "[REDACTED_HONEYTOKEN]" in out
        families = redact_match_families(text)
        assert family in families


def test_redact_indicators_emits_scoring_honeytoken_tell():
    inds = [
        Indicator(
            id="http.body",
            title="body",
            category="static_signature",
            triggered=True,
            protocol="http",
            evidence=f"token={_fake_github_pat()}",
            detail="see canarytokens.com lure",
        )
    ]
    out = redact_indicators(inds)
    by_id = {i.id: i for i in out}
    assert "deception.honeytoken_exposed" in by_id
    tell = by_id["deception.honeytoken_exposed"]
    assert tell.triggered is True
    assert tell.category == "static_signature"
    assert tell.fidelity == "high"
    # Legacy info-only path must not be the sole outcome
    info = by_id.get("info.honeytoken_detected")
    assert info is None or not info.triggered or tell.triggered


def test_honeytoken_contributes_to_score():
    inds = [
        Indicator(
            id="http.body",
            title="body",
            category="info",
            triggered=True,
            protocol="http",
            evidence=_fake_slack_bot_token(),
        )
    ]
    report = build_report(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        ports={"http": [80]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    tell = {i.id: i for i in report.indicators}["deception.honeytoken_exposed"]
    assert tell.triggered
    assert report.score > 0
    assert report.category_hits.get("static_signature", {}).get("triggered")
