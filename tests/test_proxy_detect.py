"""Proxy detection tests."""

from __future__ import annotations

from pathlib import Path

from honeypot_auditor.httpwire import parse_header_map
from honeypot_auditor.proxy_detect import detect_proxy, should_suppress

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "http"


def test_detect_proxy_cloudflare_fixture():
    raw = (FIXTURES / "cloudflare-proxied.raw").read_text()
    headers = parse_header_map(raw)
    result = detect_proxy({"headers": headers})
    assert result.detected
    assert any("cf-ray" in e for e in result.evidence)
    assert result.context == "edge_proxy_present"


def test_nginx_not_proxy():
    raw = (FIXTURES / "nginx.raw").read_text()
    headers = parse_header_map(raw)
    result = detect_proxy({"headers": headers})
    assert not result.detected


def test_should_suppress_edge_only():
    assert should_suppress("edge", proxy_detected=True)
    assert not should_suppress("origin", proxy_detected=True)
    assert not should_suppress("behavior", proxy_detected=True)
    assert not should_suppress("edge", proxy_detected=False)
