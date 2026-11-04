"""TDD: C2 panel_or_decoy vs decoy_clone — canned HTTP only."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from honeypot_auditor.analyzer import build_report
from honeypot_auditor.config.signatures.c2_decoy import classify_c2_http_face
from honeypot_auditor.models import Indicator
from honeypot_auditor.probes import http as http_probe


def test_stock_cs_404_alone_is_panel_or_decoy_not_confirmed():
    ind_id, detail, fidelity, needs_corr, fp = classify_c2_http_face(
        status=404,
        content_type="text/plain",
        body=b"",
    )
    assert ind_id == "http.c2_panel_or_decoy"
    assert needs_corr is True
    assert fp == ""
    assert fidelity in ("low", "medium")

    report = build_report(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        ports={"http": [80]},
        indicators=[
            Indicator(
                id=ind_id,
                title="C2",
                category="static_signature",
                triggered=True,
                protocol="http",
                detail=detail,
                fidelity=fidelity,
                requires_corroboration=needs_corr,
                fingerprint_type=fp,
            )
        ],
        notes=[],
        started_at="",
        finished_at="",
    )
    # Alone → suppressed / not a Confirmed honeypot headline
    assert "Confirmed" not in report.threat_level
    gated = {i.id: i for i in report.indicators}["http.c2_panel_or_decoy"]
    assert gated.triggered is False  # suppressed without corroboration


def test_static_mythic_ui_without_backend_is_decoy_clone():
    body = b"<html><title>Mythic</title><script>apollo-client</script>web_ui</html>"
    ind_id, detail, fidelity, needs_corr, fp = classify_c2_http_face(
        status=200,
        content_type="text/html",
        body=body,
        graphql_ok=False,
        websocket_upgrade=False,
    )
    assert ind_id == "http.c2_decoy_clone"
    assert fidelity == "high"
    assert needs_corr is False
    assert fp == "c2_decoy"
    assert "Mythic" in detail or "mythic" in detail.lower()


def test_static_ui_with_graphql_backend_is_ambiguous_panel():
    body = b"<html><title>Mythic</title>web_ui</html>"
    ind_id, detail, fidelity, needs_corr, fp = classify_c2_http_face(
        status=200,
        content_type="text/html",
        body=body,
        graphql_ok=True,
    )
    assert ind_id == "http.c2_panel_or_decoy"
    assert needs_corr is True
    assert fp == ""
    assert "dynamic" in detail.lower() or "backend" in detail.lower()


def test_probe_http_emits_c2_decoy_clone_from_canned_get():
    requests = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {"Content-Type": "text/html", "Server": "nginx"}
    resp.content = b"<html><title>Cobalt Strike</title><body>teamserver login</body></html>"
    resp.text = resp.content.decode()
    requests.get.return_value = resp
    requests.put.side_effect = Exception("skip")
    requests.post.side_effect = Exception("skip")
    requests.delete.side_effect = Exception("skip")
    requests.head.side_effect = Exception("skip")

    with (
        patch.object(http_probe, "optional_import", return_value=requests),
        patch.object(http_probe, "tcp_transact", return_value=(b"HTTP/1.1 200 OK\r\n\r\n", "")),
        patch.object(http_probe, "is_safe_mode", return_value=False),
        patch.object(http_probe, "_probe_c2_dynamic_backend", return_value=(False, False, False)),
    ):
        inds = http_probe.probe_http("127.0.0.1", 80)

    by_id = {i.id: i for i in inds}
    assert "http.c2_decoy_clone" in by_id
    assert by_id["http.c2_decoy_clone"].triggered is True
    assert by_id["http.c2_decoy_clone"].fingerprint_type == "c2_decoy"
    assert "http.c2_panel_or_decoy" not in by_id or not by_id["http.c2_panel_or_decoy"].triggered
