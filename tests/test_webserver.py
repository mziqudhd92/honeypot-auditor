"""Local web UI tests: routing, localhost binding, SQLite persistence, security."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from honeypot_auditor import storage
from honeypot_auditor.webserver import create_server


@pytest.fixture()
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("HONEYPOT_AUDITOR_DB", str(tmp_path / "audits.db"))
    srv = create_server(0)  # ephemeral port, 127.0.0.1 only
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    host, port = srv.server_address[:2]
    assert host == "127.0.0.1", "the UI must bind to localhost only"
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    srv.server_close()


def _get(url: str):
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.status, resp.read()


def test_index_serves_xp_css_page(server):
    status, body = _get(server + "/")
    assert status == 200
    assert b"/static/XP.css" in body
    assert b"H-AUDITOR.EXE" in body


def test_static_assets_served(server):
    status, body = _get(server + "/static/XP.css")
    assert status == 200
    assert b"XP.css" in body[:64]
    status, _ = _get(server + "/static/ms_sans_serif.woff2")
    assert status == 200
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _get(server + "/static/../../etc/passwd")
    assert excinfo.value.code in (400, 403, 404)


def test_audit_run_persists_to_sqlite(server):
    request = urllib.request.Request(
        server + "/api/audit",
        data=json.dumps({"target": "127.0.0.1", "ports": "9", "timeout": 1}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as resp:
        payload = json.loads(resp.read())
    assert "score" in payload and "threat_level" in payload
    assert payload["audit_id"] >= 1

    rows = storage.list_audits()
    assert len(rows) == 1 and rows[0]["target"] == "127.0.0.1"

    status, body = _get(server + "/api/audits")
    assert status == 200 and json.loads(body)["audits"]
    status, body = _get(f"{server}/api/audits/{payload['audit_id']}")
    assert status == 200 and json.loads(body)["report"]["target"] == "127.0.0.1"


def test_public_target_without_confirmation_is_rejected(server):
    # 1.1.1.1 is genuinely public: the engine raises PermissionError before any
    # probe is sent (note: TEST-NET ranges count as private per ipaddress.is_private).
    request = urllib.request.Request(
        server + "/api/audit",
        data=json.dumps({"target": "1.1.1.1", "ports": "9", "timeout": 1}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=30)
        raise AssertionError("expected 403")
    except urllib.error.HTTPError as excinfo:
        assert excinfo.code == 403
        assert "author" in json.loads(excinfo.read())["error"]


def test_bad_params_return_400(server):
    request = urllib.request.Request(
        server + "/api/audit",
        data=json.dumps({"target": "", "ports": "9"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=10)
        raise AssertionError("expected 400")
    except urllib.error.HTTPError as excinfo:
        assert excinfo.code == 400


def test_unknown_routes_404(server):
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _get(server + "/nope")
    assert excinfo.value.code == 404


def test_spoofed_subdomain_host_is_rejected(server):
    """127.0.0.1.evil.com must NOT pass the localhost guard (prefix bug)."""
    request = urllib.request.Request(server + "/api/audits")
    request.add_header("Host", "127.0.0.1.evil.com")
    try:
        urllib.request.urlopen(request, timeout=10)
        raise AssertionError("expected 403")
    except urllib.error.HTTPError as excinfo:
        assert excinfo.code == 403


def test_localhost_host_with_port_is_accepted(server):
    request = urllib.request.Request(server + "/api/audits")
    # urllib already sets Host: 127.0.0.1:<port>; assert the happy path still works.
    with urllib.request.urlopen(request, timeout=10) as resp:
        assert resp.status == 200


def test_foreign_origin_post_is_rejected(server):
    """Cross-site text/plain POSTs must not trigger audits (CSRF)."""
    request = urllib.request.Request(
        server + "/api/audit",
        data=json.dumps({"target": "127.0.0.1", "ports": "9", "timeout": 1}).encode(),
        headers={
            "Content-Type": "text/plain",
            "Origin": "https://evil.example",
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=10)
        raise AssertionError("expected 403")
    except urllib.error.HTTPError as excinfo:
        assert excinfo.code == 403
        assert "origin" in json.loads(excinfo.read())["error"]


def test_local_origin_post_is_accepted(server):
    request = urllib.request.Request(
        server + "/api/audit",
        data=json.dumps({"target": "127.0.0.1", "ports": "9", "timeout": 1}).encode(),
        headers={
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8337",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as resp:
        assert resp.status == 200


def test_host_header_ipv6_bracket_parsing():
    from honeypot_auditor.webserver import _Handler

    assert _Handler._hostname_from_host_header("[::1]:8337") == "::1"
    assert _Handler._hostname_from_host_header("127.0.0.1:8337") == "127.0.0.1"
    assert _Handler._hostname_from_host_header("localhost") == "localhost"
