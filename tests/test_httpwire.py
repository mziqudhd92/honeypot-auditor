"""HTTP wire parsing tests."""

from __future__ import annotations

from pathlib import Path

from honeypot_auditor.httpwire import parse_header_map, parse_header_names

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "http"


def test_parse_header_names_preserves_order():
    raw = (FIXTURES / "nginx.raw").read_text()
    names = parse_header_names(raw)
    assert names == ["Server", "Date", "Content-Type", "Content-Length", "Connection"]


def test_parse_header_map_lowercase_keys():
    raw = (FIXTURES / "python-trap.raw").read_text()
    m = parse_header_map(raw)
    assert m["server"].startswith("Werkzeug")
    assert "date" not in m


def test_cloudflare_fixture_has_proxy_headers():
    raw = (FIXTURES / "cloudflare-proxied.raw").read_text()
    m = parse_header_map(raw)
    assert "cf-ray" in m
    assert "via" in m
