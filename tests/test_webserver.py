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


def _get_request(url: str) -> urllib.request.Request:
    return urllib.request.Request(url)


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


def test_stored_audit_downloads_in_all_formats(server):
    # run one audit to populate storage
    request = urllib.request.Request(
        server + "/api/audit",
        data=json.dumps({"target": "127.0.0.1", "ports": "9", "timeout": 1}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as resp:
        audit_id = json.loads(resp.read())["audit_id"]
    for fmt, marker in (
        ("json", b"threat_level"),
        ("html", b"Triggered tells"),
        ("csv", b"indicator_id"),
        ("md", b"# Honeypot audit"),
    ):
        with urllib.request.urlopen(
            f"{server}/api/audits/{audit_id}/download/{fmt}", timeout=10
        ) as resp:
            body = resp.read()
            assert resp.status == 200
            assert marker in body
            assert "attachment" in resp.headers.get("Content-Disposition", "")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(f"{server}/api/audits/{audit_id}/download/xml", timeout=10)
    assert excinfo.value.code == 400


def _post(url: str, body: bytes, headers: dict | None = None) -> urllib.request.Request:
    return urllib.request.Request(
        url, data=body, headers=headers or {"Content-Type": "application/json"}, method="POST"
    )


def _expect_error(request: urllib.request.Request, code: int, timeout: int = 10) -> dict:
    try:
        urllib.request.urlopen(request, timeout=timeout)
        raise AssertionError(f"expected HTTP {code}")
    except urllib.error.HTTPError as excinfo:
        assert excinfo.code == code
        return json.loads(excinfo.read())


@pytest.mark.parametrize(
    ("params", "message"),
    [
        ({"target": "127.0.0.1", "preset": "nsa"}, "preset"),
        ({"target": "127.0.0.1", "timeout": "fast"}, "timeout must be a number"),
        ({"target": "127.0.0.1", "timeout": None}, "timeout must be a number"),
        ({"target": "127.0.0.1", "timeout": 0.1}, "between 0.5 and 30"),
        ({"target": "127.0.0.1", "timeout": 31}, "between 0.5 and 30"),
    ],
)
def test_invalid_params_are_rejected_with_400(server, params, message):
    err = _expect_error(_post(server + "/api/audit", json.dumps(params).encode()), 400)
    assert message in err["error"]


def test_post_to_unknown_path_is_404(server):
    err = _expect_error(
        _post(server + "/api/nope", json.dumps({"target": "127.0.0.1"}).encode()), 404
    )
    assert err["error"] == "not found"


@pytest.mark.parametrize(
    "body",
    [
        b"this is not json",
        b"[1, 2, 3]",  # valid JSON, but not an object
        b'"just a string"',
    ],
)
def test_post_with_malformed_json_body_is_400(server, body):
    err = _expect_error(_post(server + "/api/audit", body), 400)
    assert err["error"] == "invalid JSON body"


def test_post_with_foreign_referer_is_rejected(server):
    err = _expect_error(
        _post(
            server + "/api/audit",
            json.dumps({"target": "127.0.0.1", "timeout": 1}).encode(),
            headers={"Content-Type": "application/json", "Referer": "https://evil.example/"},
        ),
        403,
    )
    assert "origin" in err["error"]


def test_post_with_local_referer_is_accepted(server):
    with urllib.request.urlopen(
        _post(
            server + "/api/audit",
            json.dumps({"target": "127.0.0.1", "ports": "9", "timeout": 1}).encode(),
            headers={
                "Content-Type": "application/json",
                "Referer": "http://localhost/anything",
            },
        ),
        timeout=120,
    ) as resp:
        assert resp.status == 200


def test_post_returning_500_on_internal_failure(server, monkeypatch):
    from honeypot_auditor import webserver

    def _save_boom(*_a, **_k):
        raise OSError("sqlite is on fire")

    monkeypatch.setattr(webserver.storage, "save_report", _save_boom)
    err = _expect_error(
        _post(
            server + "/api/audit",
            json.dumps({"target": "127.0.0.1", "ports": "9", "timeout": 1}).encode(),
        ),
        500,
        timeout=120,
    )
    assert "audit failed" in err["error"] and "sqlite is on fire" in err["error"]


def test_bad_audit_id_is_400(server):
    err = _expect_error(_get_request(f"{server}/api/audits/not-a-number"), 400)
    assert err["error"] == "bad audit id"


def test_missing_audit_is_404(server):
    err = _expect_error(_get_request(f"{server}/api/audits/999999"), 404)
    assert err["error"] == "not found"


@pytest.mark.parametrize(
    ("path", "message"),
    [
        # missing format segment: handled by the audit-id branch
        ("/api/audits/1/download", "bad audit id"),
        # too many segments: handled by the download-path branch
        ("/api/audits/1/download/json/extra", "bad download path"),
    ],
)
def test_malformed_download_paths_are_400(server, path, message):
    err = _expect_error(_get_request(server + path), 400)
    assert err["error"] == message


def test_download_with_bad_audit_id_is_400(server):
    err = _expect_error(_get_request(f"{server}/api/audits/xyz/download/json"), 400)
    assert err["error"] == "bad audit id"


def test_download_of_missing_audit_is_404(server):
    err = _expect_error(_get_request(f"{server}/api/audits/424242/download/json"), 404)
    assert err["error"] == "not found"


def test_static_asset_missing_on_disk_is_404(server, monkeypatch, tmp_path):
    from honeypot_auditor import webserver

    # XP.css is a known asset name, but point the static dir at an empty dir
    monkeypatch.setattr(webserver, "_DATA_DIR", tmp_path)
    err = _expect_error(_get_request(server + "/static/XP.css"), 404)
    assert err["error"] == "not found"


def test_run_webserver_rejects_bad_port(capsys):
    from honeypot_auditor import webserver

    assert webserver.run_webserver(["--port", "not-a-number"]) == 2
    assert "--port requires a number" in capsys.readouterr().out


def test_run_webserver_serves_until_interrupted(monkeypatch, capsys):
    from honeypot_auditor import webserver

    class _FakeServer:
        server_address = ("127.0.0.1", 8337)

        def serve_forever(self):
            raise KeyboardInterrupt  # simulate Ctrl+C on first loop tick

        def server_close(self):
            self.closed = True

    fake = _FakeServer()
    monkeypatch.setattr(webserver, "create_server", lambda port: fake)
    assert webserver.run_webserver(["--port", "8337"]) == 0
    out = capsys.readouterr().out
    assert "http://127.0.0.1:8337" in out
    assert fake.closed

    # default argv serves on DEFAULT_PORT
    fake2 = _FakeServer()
    monkeypatch.setattr(webserver, "create_server", lambda port: fake2)
    assert webserver.run_webserver(None) == 0
