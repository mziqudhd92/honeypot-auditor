"""TDD: C2 panel_or_decoy vs decoy_clone — canned HTTP only."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from honeypot_auditor.analyzer import apply_stack_corroboration, build_report
from honeypot_auditor.config.signatures.c2_decoy import (
    classify_c2_http_face,
    match_c2_stock_tls_cert,
)
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


def test_cs_stock_tls_cert_is_ambiguous_only():
    assert match_c2_stock_tls_cert("CN=Major Cobalt Strike, O=Cobalt Strike")
    assert match_c2_stock_tls_cert("serialNumber=146473198")
    assert match_c2_stock_tls_cert("CN=real.corp.example") is None
    # Short hex serial fragments must not false-positive.
    assert match_c2_stock_tls_cert("serialNumber=008b") is None
    assert match_c2_stock_tls_cert("serial=0x008b") is None


def test_bare_implant_is_not_sliver_ui():
    from honeypot_auditor.config.signatures.c2_decoy import match_c2_static_ui_clone

    assert match_c2_static_ui_clone(b"<html>medical implant catalog</html>") is None
    assert match_c2_static_ui_clone(b"<html>Sliver C2 console</html>")


def test_c2_panel_scores_only_with_ungated_corroboration():
    panel = Indicator(
        id="http.c2_panel_or_decoy",
        title="C2",
        category="static_signature",
        triggered=True,
        protocol="http",
        fidelity="medium",
        requires_corroboration=True,
    )
    alone = apply_stack_corroboration([panel])
    assert alone[0].triggered is False

    with_ssh = apply_stack_corroboration(
        [
            panel,
            Indicator(
                id="ssh.arbitrary_auth",
                title="auth",
                category="arbitrary_auth",
                triggered=True,
                protocol="ssh",
                fidelity="decisive",
            ),
        ]
    )
    by_id = {i.id: i for i in with_ssh}
    assert by_id["http.c2_panel_or_decoy"].triggered is True
    report = build_report(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        ports={"ssh": [22], "http": [80]},
        indicators=with_ssh,
        notes=[],
        started_at="",
        finished_at="",
    )
    assert report.score > 0
    assert "Confirmed" in report.threat_level or report.score >= 30


def test_graphql_html_error_page_does_not_mark_dynamic():
    assert http_probe._looks_like_graphql_response(
        404, "text/html", b"<html>no data available</html>"
    ) is False
    assert http_probe._looks_like_graphql_response(
        200, "application/json", b'{"message":"not found","data":null}'
    ) is False
    assert http_probe._looks_like_graphql_response(
        200, "application/json", b'{"data":{"__typename":"Query"}}'
    ) is True
    assert http_probe._looks_like_graphql_response(
        400, "application/json", b'{"errors":[{"message":"syntax"}]}'
    ) is True


def test_probe_c2_backend_ignores_static_graphql_404_html():
    requests = MagicMock()
    bad = MagicMock()
    bad.status_code = 404
    bad.headers = {"Content-Type": "text/html"}
    bad.content = b"<html>Cannot POST /graphql - no data</html>"
    requests.post.return_value = bad
    requests.get.return_value = bad
    gql, ws, api = http_probe._probe_c2_dynamic_backend(requests, "http://127.0.0.1")
    assert (gql, ws, api) == (False, False, False)


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


def test_safe_mode_does_not_emit_high_fidelity_decoy_clone():
    """Without backend probes, C2-looking HTML must stay ambiguous panel_or_decoy."""
    inds = http_probe._c2_face_indicators(
        "127.0.0.1",
        80,
        get_status=200,
        get_headers={"content-type": "text/html"},
        get_body=b"<html><title>Mythic</title>apollo-client web_ui</html>",
        requests_mod=None,
    )
    assert len(inds) == 1
    assert inds[0].id == "http.c2_panel_or_decoy"
    assert inds[0].requires_corroboration is True
    assert inds[0].fingerprint_type == ""
    assert inds[0].fidelity != "high"
