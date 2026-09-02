"""SARIF export tests."""

from __future__ import annotations

from honeypot_auditor.models import AuditReport, Indicator
from honeypot_auditor.reporters.sarif import build_sarif, build_sarif_many, export_sarif


def test_sarif_schema_fields(tmp_path):
    report = AuditReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        score=75.0,
        threat_level="Suspected Honeypot",
        category_hits={},
        indicators=[
            Indicator(
                id="ssh.static",
                title="SSH lure banner",
                category="static_signature",
                triggered=True,
                protocol="ssh",
                remediation="Fix banner",
            )
        ],
        confidence="high",
        tactical_action="SKIP_TARGET",
    )
    sarif = build_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    assert run["results"]
    assert run["tool"]["driver"]["name"] == "honeypot-auditor"
    assert run["properties"]["honeyscore"] == 75.0
    assert run["properties"]["report_schema_version"] == "1.0"
    assert run["properties"]["confidence"] == "high"
    assert run["properties"]["tactical_action"] == "SKIP_TARGET"
    path = export_sarif(report, tmp_path / "out.sarif")
    assert path.is_file()
    assert "ssh.static" in path.read_text(encoding="utf-8")


def test_sarif_emits_summary_when_no_hits():
    report = AuditReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        score=0.0,
        threat_level="Likely Real Host",
        category_hits={},
        indicators=[],
        confidence="low",
        tactical_action="INCONCLUSIVE",
    )
    sarif = build_sarif(report)
    run = sarif["runs"][0]
    assert run["results"]
    assert run["results"][0]["ruleId"] == "honeypot-auditor.summary"
    assert run["tool"]["driver"]["rules"]
    assert run["properties"]["honeyscore"] == 0.0


def test_sarif_golden_snapshot_keys():
    """Stable SARIF shape for DevSecOps consumers."""
    report = AuditReport(
        target="lab.example",
        resolved_ip="10.0.0.1",
        score=60.0,
        threat_level="Confirmed Honeypot",
        category_hits={},
        indicators=[
            Indicator(
                id="http.wildcard_host",
                title="wildcard",
                category="proto_conformance",
                triggered=True,
                protocol="http",
                detail="accepted",
            )
        ],
        confidence="medium",
        tactical_action="INCONCLUSIVE",
    )
    sarif = build_sarif(report)
    result = sarif["runs"][0]["results"][0]
    assert set(result.keys()) >= {"ruleId", "level", "message", "locations", "properties"}
    assert result["ruleId"] == "http.wildcard_host"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "targets/10.0.0.1.txt"
    )
    assert len(result["partialFingerprints"]["primaryLocationLineHash"]) == 64
    assert "evidence" in result["properties"]
    assert "remediation" in result["properties"]


def test_sarif_excludes_suppressed_findings():
    report = AuditReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        score=0.0,
        threat_level="Likely Real Host",
        category_hits={},
        indicators=[
            Indicator(
                id="http.edge",
                title="edge tell",
                category="static_signature",
                triggered=True,
                suppressed=True,
                protocol="http",
            )
        ],
    )
    result = build_sarif(report)["runs"][0]["results"][0]
    assert result["ruleId"] == "honeypot-auditor.summary"


def test_sarif_many_uses_one_run_per_host():
    reports = [
        AuditReport(
            target=f"host-{index}",
            resolved_ip=f"192.0.2.{index}",
            score=0.0,
            threat_level="Likely Real Host",
            category_hits={},
        )
        for index in (1, 2)
    ]
    sarif = build_sarif_many(reports)
    assert len(sarif["runs"]) == 2
    assert [run["properties"]["resolved_ip"] for run in sarif["runs"]] == [
        "192.0.2.1",
        "192.0.2.2",
    ]
