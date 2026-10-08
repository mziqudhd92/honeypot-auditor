"""HTML / CSV / Markdown export tests."""

from __future__ import annotations

import csv
import io
import stat

from honeypot_auditor.reporters.text_export import (
    build_csv_text,
    build_html,
    build_markdown,
    export_csv,
    export_html,
    export_markdown,
)


def _payload() -> dict:
    return {
        "schema_version": "1.0",
        "target": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "score": 72.5,
        "threat_level": "Confirmed Honeypot",
        "confidence": "high",
        "started_at": "2026-10-08T10:00:00+00:00",
        "finished_at": "2026-10-08T10:00:42+00:00",
        "tactical_action": "SKIP_TARGET",
        "tactical_rationale": "decoy confirmed",
        "triggered": [
            {
                "id": "ssh.arbitrary_auth",
                "category": "arbitrary_auth",
                "detail": "random user_a12:**** accepted <script>alert(1)</script>",
            }
        ],
        "indicators": [
            {
                "id": "ssh.arbitrary_auth",
                "category": "arbitrary_auth",
                "protocol": "ssh",
                "triggered": True,
                "skipped": False,
                "title": "SSH arbitrary credential acceptance",
                "detail": "random user_a12:**** accepted",
            },
            {
                "id": "ssh.banner",
                "category": "static_signature",
                "protocol": "ssh",
                "triggered": False,
                "skipped": True,
                "title": "SSH static banner signature",
                "detail": "timeout",
            },
        ],
        "protocol_strategies": [
            {"protocol": "ssh", "ports": [22], "arbitrary_auth": {"status": "hit"}}
        ],
    }


def test_markdown_contains_summary_and_tells():
    md = build_markdown(_payload())
    assert "# Honeypot audit — 127.0.0.1" in md
    assert "72.5%" in md and "Confirmed Honeypot" in md
    assert "ssh.arbitrary_auth" in md
    assert "| Protocol | Ports | Strategies fired |" in md


def test_html_escapes_probe_evidence():
    page = build_html(_payload())
    assert "<script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "Confirmed Honeypot" in page
    assert 'style="width:72.5%' in page


def test_csv_rows_and_ordering():
    text = build_csv_text(_payload())
    rows = list(csv.reader(io.StringIO(text)))
    header, first, second = rows[0], rows[1], rows[2]
    assert header[0] == "target" and "indicator_id" in header
    assert first[5] == "ssh.arbitrary_auth" and first[8] == "yes"  # triggered first
    assert second[5] == "ssh.banner" and second[8] == "no"
    assert "127.0.0.1" in first


def test_exports_write_owner_only_files(tmp_path):
    payload = _payload()
    for dest, fn in (
        (tmp_path / "r.md", export_markdown),
        (tmp_path / "r.html", export_html),
        (tmp_path / "r.csv", export_csv),
    ):
        out = fn(payload, dest)
        assert out.exists()
        mode = stat.S_IMODE(out.stat().st_mode) & 0o777
        assert mode == 0o600, f"{out} not owner-only"


def test_subnet_builders():
    payload = {
        "target": "192.168.1.0/24",
        "host_count": 1,
        "started_at": "t0",
        "finished_at": "t1",
        "hosts": [
            {
                "resolved_ip": "192.168.1.5",
                "score": 80.0,
                "threat_level": "Confirmed Honeypot",
                "triggered": [{"id": "x"}],
            }
        ],
    }
    from honeypot_auditor.reporters.text_export import (
        build_html_subnet,
        build_markdown_subnet,
    )

    assert "192.168.1.5" in build_html_subnet(payload)
    assert "Confirmed Honeypot" in build_markdown_subnet(payload)
