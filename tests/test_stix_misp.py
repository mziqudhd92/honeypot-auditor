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
                evidence=json.dumps(
                    {"hassh_server": "aabbccddeeff00112233445566778899"}  # pragma: allowlist secret
                ),
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
    # Attach TLS cert hash so x509-certificate SCO is emitted.
    report.observables = {
        "ssh": {"hassh_server": "aabbccddeeff00112233445566778899"},  # pragma: allowlist secret
        "tls": {
            "ja3s": "cafebabedeadbeefcafebabedeadbeef",  # pragma: allowlist secret
            "cert_sha256": "ab" * 32,
        },
    }
    bundle = stix_export.build_stix_bundle(report)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert "id" in bundle and bundle["id"].startswith("bundle--")
    types = {o["type"] for o in bundle["objects"]}
    assert "infrastructure" in types
    assert "indicator" in types
    assert "ipv4-addr" in types
    assert "x509-certificate" in types
    # No invented object types — fingerprints live as custom props on ipv4-addr.
    assert not any(t.startswith("x-honeypot-auditor-") for t in types)
    ipv4 = next(o for o in bundle["objects"] if o["type"] == "ipv4-addr")
    assert ipv4.get("x_honeypot_auditor_hassh_server")
    assert ipv4.get("x_honeypot_auditor_ja3s")
    x509 = next(o for o in bundle["objects"] if o["type"] == "x509-certificate")
    assert x509["hashes"]["SHA-256"] == "ab" * 32


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


def test_subnet_stix_misp_many_exports(tmp_path: Path):
    reports = [_mini_report(), _mini_report()]
    stix_path = stix_export.export_stix_many(reports, tmp_path / "subnet.stix.json")
    misp_path = misp_export.export_misp_many(reports, tmp_path / "subnet.misp.json")
    stix = json.loads(stix_path.read_text(encoding="utf-8"))
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) >= 2
    misp = json.loads(misp_path.read_text(encoding="utf-8"))
    assert isinstance(misp.get("response"), list) and len(misp["response"]) == 2
    assert all("Event" in entry for entry in misp["response"])


def test_stix_ipv6_uses_ipv6_addr_sco():
    report = build_report(
        target="2001:db8::1",
        resolved_ip="2001:db8::1",
        ports={"ssh": [22]},
        indicators=[
            Indicator(
                id="ssh.arbitrary_auth",
                title="auth",
                category="arbitrary_auth",
                triggered=True,
                protocol="ssh",
                fidelity="decisive",
            )
        ],
        notes=[],
        started_at="2026-11-04T00:00:00+00:00",
        finished_at="2026-11-04T00:00:10+00:00",
    )
    report.observables = {"tls": {"cert_sha256": "cd" * 32}}
    bundle = stix_export.build_stix_bundle(report)
    types = {o["type"] for o in bundle["objects"]}
    assert "ipv6-addr" in types
    assert "ipv4-addr" not in types
    assert "x509-certificate" in types
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    x509_id = next(o["id"] for o in bundle["objects"] if o["type"] == "x509-certificate")
    assert any(r.get("target_ref") == x509_id for r in rels)
    for ind in (o for o in bundle["objects"] if o["type"] == "indicator"):
        assert "ipv6-addr:value" in ind["pattern"]


def test_export_suffix_does_not_double_compound():
    from honeypot_auditor.cli import _with_export_suffix

    assert _with_export_suffix("out.stix.json", ".stix.json").name == "out.stix.json"
    assert _with_export_suffix("out.misp.json", ".misp.json").name == "out.misp.json"
    assert _with_export_suffix("out.json", ".stix.json").name == "out.stix.json"
    assert _with_export_suffix("honeypot-audit-1.2.3.4.stix.json", ".stix.json").name.endswith(
        ".stix.json"
    )
    assert ".stix.stix.json" not in str(_with_export_suffix("a.stix.json", ".stix.json"))
