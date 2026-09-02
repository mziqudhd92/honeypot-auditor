"""Reporter output tests."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console

from honeypot_auditor.analyzer import build_report
from honeypot_auditor.models import Indicator
from honeypot_auditor.reporters.console import render
from honeypot_auditor.reporters.json_export import export


def _sample_report():
    return build_report(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        ports={"ssh": 22},
        indicators=[
            Indicator(
                id="ssh.test",
                title="test",
                category="static_signature",
                triggered=True,
                protocol="ssh",
                detail="ok",
            ),
            Indicator(
                id="ssh.clean",
                title="clean",
                category="static_signature",
                triggered=False,
                protocol="ssh",
                detail="",
            ),
        ],
        notes=["test"],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
    )


def test_json_export_roundtrip(tmp_path: Path):
    report = _sample_report()
    dest = export(report, tmp_path / "out.json")
    data = json.loads(dest.read_text())
    assert data["score"] == report.score
    assert data["indicators"][0]["id"] == "ssh.test"
    assert len(data["triggered"]) == 1
    assert data["protocol_strategies"][0]["protocol"] == "ssh"
    assert data["protocol_strategies"][0]["static_signature"]["status"] == "hit"


def test_json_export_coerces_bytes_evidence(tmp_path: Path):
    report = build_report(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        ports={"smtp": 25},
        indicators=[
            Indicator(
                id="deep.smtp_fsm",
                title="SMTP FSM",
                category="proto_conformance",
                triggered=False,
                protocol="smtp",
                evidence=b"250-PIPELINING\r\n250 HELP",
            )
        ],
        notes=[],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
    )
    dest = export(report, tmp_path / "bytes.json")
    data = json.loads(dest.read_text())
    assert data["indicators"][0]["evidence"] == "250-PIPELINING\r\n250 HELP"



def test_console_render_compact_by_default():
    buf = StringIO()
    render(_sample_report(), console=Console(file=buf, width=120, force_terminal=True))
    out = buf.getvalue()
    assert "Honeypot Auditor" in out
    assert "Honeyscore" in out
    assert "Strategy" not in out
    assert "Protocol strategies" not in out
    assert "Indicators" not in out
    assert "Why this score" not in out
    assert "test" not in out


def test_console_render_verbose_includes_strategy_tables():
    buf = StringIO()
    render(
        _sample_report(),
        console=Console(file=buf, width=120, force_terminal=True),
        verbose=True,
    )
    out = buf.getvalue()
    assert "Strategy" in out
    assert "Protocol strategies" in out


def test_console_render_verbose_includes_indicators():
    buf = StringIO()
    render(
        _sample_report(),
        console=Console(file=buf, width=120, force_terminal=True),
        verbose=True,
    )
    out = buf.getvalue()
    assert "Indicators" in out
    assert "Why this score" in out
    assert "test" in out


def test_json_export_nmap_exclude_and_subnet(tmp_path: Path):
    from honeypot_auditor.reporters.json_export import export_nmap_exclude, export_subnet

    exclude = tmp_path / "exclude.txt"
    export_nmap_exclude("203.0.113.9", exclude)
    export_nmap_exclude("203.0.113.9", exclude)  # idempotent
    export_nmap_exclude("203.0.113.10", exclude)
    assert exclude.read_text(encoding="utf-8").splitlines() == ["203.0.113.9", "203.0.113.10"]

    report = _sample_report()
    report.deception_leaks = [{"rank": 1, "id": "ssh.test"}]
    dest = export_subnet(
        target="203.0.113.0/24",
        reports=[report],
        path=tmp_path / "subnet.json",
        notes=["lab"],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
    )
    data = json.loads(dest.read_text(encoding="utf-8"))
    assert data["scan_type"] == "subnet"
    assert data["host_count"] == 1
    assert data["hosts"][0]["deception_leaks"][0]["id"] == "ssh.test"


def test_json_default_bytearray_and_reject():
    from honeypot_auditor.reporters import json_export

    assert json_export._json_default(bytearray(b"abc")) == "abc"
    try:
        json_export._json_default(object())
        raise AssertionError("expected TypeError")
    except TypeError:
        pass
