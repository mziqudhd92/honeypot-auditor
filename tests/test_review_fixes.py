"""Integration tests for code-review remediation items."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

from honeypot_auditor.analyzer import build_report, category_triggered
from honeypot_auditor.cli import _passive_score_high
from honeypot_auditor.models import Indicator
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.probes.recon import _shodan_port_indicators
from honeypot_auditor.settings import settings
from honeypot_auditor.signatures.evaluate import evaluate_signatures

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "http"


def test_proxy_suppression_suppresses_edge_tls_not_wildcard_host():
    cf_raw = (FIXTURES / "cloudflare-proxied.raw").read_text()
    indicators = [
        Indicator(
            id="http.wildcard_host",
            title="HTTP accepts invalid Host header",
            category="proto_conformance",
            triggered=True,
            protocol="http",
            detail="wildcard accepted",
            tell_tier="origin",
        ),
        Indicator(
            id="http.header_order",
            title="HTTP header order lure",
            category="static_signature",
            triggered=True,
            protocol="http",
            evidence=cf_raw,
            tell_tier="edge",
        ),
        Indicator(
            id="deep.tls_stack",
            title="TLS lure",
            category="stack_fingerprint",
            triggered=True,
            protocol="tls",
            detail="ja3s=lure",
            tell_tier="edge",
        ),
    ]
    report = build_report(
        target="203.0.113.1",
        resolved_ip="203.0.113.1",
        ports={"http": [80]},
        indicators=indicators,
        notes=[],
        started_at="t0",
        finished_at="t1",
    )
    by_id = {i.id: i for i in report.indicators}
    assert by_id["http.wildcard_host"].triggered
    assert by_id["deep.tls_stack"].suppressed
    assert not by_id["deep.tls_stack"].triggered
    assert report.tactical_action == "INCONCLUSIVE"


def test_category_triggered_ignores_suppressed():
    inds = [
        Indicator(
            id="x",
            title="x",
            category="static_signature",
            triggered=True,
            suppressed=True,
        )
    ]
    assert not category_triggered(inds, "static_signature")


def test_evaluate_signatures_fires_from_http_evidence():
    evidence = (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx\r\n"
        "Date: Mon, 01 Sep 2025 12:00:00 GMT\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    inds = [
        Indicator(
            id="http.dynamic_headers",
            title="HTTP headers",
            category="static_signature",
            triggered=False,
            protocol="http",
            evidence=evidence,
        )
    ]
    sig_inds = evaluate_signatures(inds)
    assert any(i.id == "http.header_order_lure" for i in sig_inds)


def test_passive_score_high_buffet_and_open_ports():
    host_info = {"data": [{"product": "Cowrie", "port": p} for p in range(1, 9)]}
    port_inds = _shodan_port_indicators(host_info)
    assert _passive_score_high(port_inds)


@patch.object(settings, "safe_mode", True)
def test_safe_mode_ssh_skips_auth():
    import honeypot_auditor.probes.ssh as ssh_mod

    with patch.object(ssh_mod, "tcp_transact") as mock_tcp:
        mock_tcp.return_value = (b"SSH-2.0-OpenSSH_8.9\r\n", "")
        with patch.object(ssh_mod, "optional_import") as mock_import:
            inds = ssh_mod.probe_ssh("127.0.0.1", 22)
            mock_import.assert_not_called()
    by_id = {i.id: i for i in inds}
    assert by_id["ssh.arbitrary_auth"].skipped
    assert "ssh.kex_facade" in by_id


@patch.object(settings, "safe_mode", True)
@patch.object(settings, "proxy_url", "socks5h://127.0.0.1:9050")
def test_create_connection_uses_proxy_when_configured():
    from honeypot_auditor import proxy_transport

    mock_sock = MagicMock()
    socks_mod = MagicMock()
    socks_mod.SOCKS5 = 5
    socks_mod.socksocket.return_value = mock_sock

    with patch.object(proxy_transport, "require_pysocks"):
        with patch.dict("sys.modules", {"socks": socks_mod}):
            sock = proxy_transport.create_connection("203.0.113.1", 443, 1.0)
    socks_mod.socksocket.return_value.set_proxy.assert_called_once()
    socks_mod.socksocket.return_value.connect.assert_called_with(("203.0.113.1", 443))
    assert sock is mock_sock


def test_plugins_merge_into_probe_registry():
    assert isinstance(PROBE_BY_PROTOCOL, dict)
    assert "ssh" in PROBE_BY_PROTOCOL


def test_dual_stack_mismatch_rebuilds_score():
    import argparse

    from honeypot_auditor.cli import _audit_dual_stack

    args = argparse.Namespace(
        deep=False,
        safe_mode=False,
        shodan_key="",
        with_nmap=False,
        preset="lab",
        ports="",
        extra_ports="",
        timeout=3.0,
        verbose=False,
        output="",
        format="json",
        confirm_authorized=True,
        proxy="",
        proxy_allow_local_dns=False,
        passive_first=False,
        osint_only=False,
        dual_stack=True,
        max_concurrent=32,
        seed=None,
        signature_pack="core",
        jitter_ms="",
        jitter=0.0,
        profile="audit",
    )
    ports = {"http": [80]}

    async def fake_audit(ip, _args, _ports, **kwargs):
        if ":" not in ip:
            indicators = [
                Indicator(
                    id="arbitrary_auth.t", title="a", category="arbitrary_auth", triggered=True
                ),
                Indicator(id="state.t", title="s", category="state_nonpersist", triggered=True),
                Indicator(id="static.t", title="s", category="static_signature", triggered=True),
            ]
        else:
            indicators = []
        return build_report(
            target=ip,
            resolved_ip=ip,
            ports=_ports,
            indicators=indicators,
            notes=[],
            started_at="t0",
            finished_at="t1",
            deep=False,
        )

    with patch(
        "honeypot_auditor.cli._resolve_dual_stack", return_value=(["203.0.113.1"], ["2001:db8::1"])
    ):
        with patch("honeypot_auditor.cli._audit_host", side_effect=fake_audit):
            report = asyncio.run(_audit_dual_stack("example.com", args, ports))
    assert any(i.id == "info.ip_version_mismatch" for i in report.triggered())
    assert report.score != 0
