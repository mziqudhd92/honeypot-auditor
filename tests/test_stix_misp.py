"""TDD: STIX 2.1 + MISP file export from AuditReport (no network I/O)."""

from __future__ import annotations

import json
from pathlib import Path

from honeypot_auditor.analyzer import build_report
from honeypot_auditor.cli import build_parser
from honeypot_auditor.models import Indicator
from honeypot_auditor.reporters import misp_export, stix_export


def _mini_report():
    return build_report(
        target="203.0.113.50",
        resolved_ip="203.0.113.50",
        ports={"ssh": [22], "http": [443]},
        indicators=[
            Indicator(
                id="deep.hassh",
                title="HASSH",
                category="stack_fingerprint",
                triggered=True,
                protocol="ssh",
                evidence=json.dumps({"hassh_server": "aabbccddeeff00112233445566778899"}),
                fidelity="high",
            ),
            Indicator(
                id="ssh.arbitrary_auth",
                title="auth",
                category="arbitrary_auth",
                triggered=True,
                protocol="ssh",
                fidelity="decisive",
            ),
        ],
        notes=[],
        started_at="2026-11-04T00:00:00+00:00",
        finished_at="2026-11-04T00:00:10+00:00",
        deep=True,
    )


def test_stix_bundle_shape():
    report = _mini_report()
    bundle = stix_export.build_stix_bundle(report)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert "id" in bundle and bundle["id"].startswith("bundle--")
    types = {o["type"] for o in bundle["objects"]}
    assert "infrastructure" in types or "indicator" in types
    assert "ipv4-addr" in types or "observed-data" in types or any(
        o.get("type") == "ipv4-addr" for o in bundle["objects"]
    )


def test_misp_event_has_attributes_and_tags():
    report = _mini_report()
    event = misp_export.build_misp_event(report)
    assert "Event" in event
    ev = event["Event"]
    assert ev.get("info")
    assert isinstance(ev.get("Attribute"), list) and ev["Attribute"]
    assert isinstance(ev.get("Tag"), list) and ev["Tag"]


def test_cli_format_accepts_stix_and_misp():
    parser = build_parser()
    for fmt in ("stix", "misp"):
        args = parser.parse_args(["--target", "127.0.0.1", "--format", fmt])
        assert args.format == fmt


def test_stix_misp_export_writes_owner_only(tmp_path: Path):
    report = _mini_report()
    stix_path = stix_export.export_stix(report, tmp_path / "out.stix.json")
    misp_path = misp_export.export_misp(report, tmp_path / "out.misp.json")
    assert stix_path.is_file()
    assert misp_path.is_file()
    stix = json.loads(stix_path.read_text(encoding="utf-8"))
    assert stix["type"] == "bundle"
    misp = json.loads(misp_path.read_text(encoding="utf-8"))
    assert "Event" in misp
