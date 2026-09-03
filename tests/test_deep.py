"""Tests for deep-mode scoring and utilities."""

from __future__ import annotations

from honeypot_auditor.analyzer import apply_cotenancy_corroboration, build_report, compute_score
from honeypot_auditor.hassh import SSHKexInit, hassh_algo_mismatch
from honeypot_auditor.models import Indicator


def _ind(category: str, triggered: bool, **kwargs) -> Indicator:
    return Indicator(
        id=f"{category}.t", title=category, category=category, triggered=triggered, **kwargs
    )


def test_deep_weights_add_behavior():
    inds = [_ind("behavior", True)]
    score, hits = compute_score(inds, deep=True)
    assert score == 18.0
    assert hits["behavior"]["triggered"]


def test_cotenancy_suppressed_without_corroboration():
    inds = [
        Indicator(
            id="deep.cotenancy",
            title="cotenancy",
            category="cotenancy",
            triggered=True,
            detail="8 responsive IT lures: ftp:21, http:80",
            evidence="ftp:21,http:80",
        )
    ]
    adjusted = apply_cotenancy_corroboration(inds)
    assert not adjusted[0].triggered
    assert "suppressed" in adjusted[0].detail


def test_cotenancy_allowed_with_corroboration():
    inds = [
        _ind("static_signature", True),
        Indicator(
            id="deep.cotenancy",
            title="cotenancy",
            category="cotenancy",
            triggered=False,
            detail="5 responsive IT lures: ftp:8021, http:8024",
            evidence="ftp:8021,http:8024",
        ),
    ]
    adjusted = apply_cotenancy_corroboration(inds)
    cot = next(i for i in adjusted if i.category == "cotenancy")
    assert cot.triggered


def test_hassh_twisted_mismatch():
    kex = SSHKexInit(
        kex="diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
        host_key="ssh-rsa",
        enc_c2s="aes128-ctr",
        enc_s2c="aes128-ctr",
        mac_c2s="hmac-sha1",
        mac_s2c="hmac-sha1",
        comp_c2s="none",
        comp_s2c="none",
    )
    triggered, detail = hassh_algo_mismatch("SSH-2.0-OpenSSH_9.2p1 Debian", kex)
    assert triggered
    assert "Twisted" in detail or "legacy" in detail


def test_chn_like_report_stays_real_host():
    inds = [
        _ind("arbitrary_auth", False),
        _ind("behavior", False, skipped=True),
        _ind("stack_fingerprint", False),
        Indicator(id="deep.cotenancy", title="cotenancy", category="cotenancy", triggered=True),
    ]
    report = build_report(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        ports={},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
        deep=True,
    )
    assert report.score < 30.0
    assert report.threat_level == "Inconclusive (Low-confidence anomalies detected)"
