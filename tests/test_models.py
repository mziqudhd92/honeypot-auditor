"""Model field tests."""

from __future__ import annotations

from honeypot_auditor.models import AuditReport, Indicator


def test_indicator_as_dict_includes_new_fields():
    ind = Indicator(
        id="http.header_order",
        title="HTTP header order",
        category="static_signature",
        triggered=True,
        remediation="Align header order with production nginx",
        fingerprint_type="http_header_order",
        tell_tier="edge",
    )
    d = ind.as_dict()
    assert d["remediation"] == "Align header order with production nginx"
    assert d["fingerprint_type"] == "http_header_order"
    assert d["tell_tier"] == "edge"
    assert d["requires_corroboration"] is False
    assert d["suppressed"] is False
    assert d["status"] == "triggered"
    assert d["provenance"] == {"kind": "built-in", "provider": "honeypot-auditor"}


def test_indicator_status_and_plugin_provenance():
    ind = Indicator(
        id="intel.example.lookup",
        title="lookup",
        category="info",
        skipped=True,
        skip_reason="not configured",
        protocol="intel:example",
    )
    data = ind.as_dict()
    assert data["status"] == "skipped"
    assert data["provenance"] == {"kind": "passive-intel-plugin", "provider": "example"}


def test_audit_report_extended_fields():
    report = AuditReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        score=50.0,
        threat_level="Suspected Honeypot",
        category_hits={},
        confidence="medium",
        proxy_detected=True,
        proxy_evidence=["cf-ray: abc"],
        proxy_context="edge_proxy_present",
        capability_warnings=["raw_sockets_disabled"],
        capabilities={"raw_sockets": False},
        score_breakdown={"final_score_pct": 50.0},
    )
    assert report.confidence == "medium"
    assert report.proxy_detected
    assert report.capabilities["raw_sockets"] is False
    assert report.score_breakdown["final_score_pct"] == 50.0


def test_triggered_excludes_suppressed():
    ind = Indicator(
        id="x",
        title="x",
        category="static_signature",
        triggered=True,
        suppressed=True,
    )
    report = AuditReport(
        target="t",
        resolved_ip="t",
        score=0,
        threat_level="Likely Real Host",
        category_hits={},
        indicators=[ind],
    )
    assert report.triggered() == []
