"""Docker Engine API non-compliance probe tests."""

from __future__ import annotations

import json
from unittest.mock import patch

import honeypot_auditor.probes.docker as docker
from honeypot_auditor.analyzer import build_report
from honeypot_auditor.models import Indicator
from honeypot_auditor.settings import settings


def _http_bytes(
    status: int, body: dict | list | str | bytes, *, headers: dict[str, str] | None = None
) -> bytes:
    if isinstance(body, (dict, list)):
        payload = json.dumps(body).encode()
        default_ctype = "application/json"
    elif isinstance(body, bytes):
        payload = body
        default_ctype = "text/plain; charset=utf-8"
    else:
        payload = body.encode()
        default_ctype = "text/plain; charset=utf-8"
    hdrs = {"Content-Type": default_ctype, "Content-Length": str(len(payload))}
    if headers:
        hdrs.update(headers)
    head = f"HTTP/1.1 {status} OK\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    return head.encode() + payload


_VERSION = {
    "Platform": {"Name": "Docker Engine - Community"},
    "Version": "24.0.7",
    "ApiVersion": "1.43",
    "MinAPIVersion": "1.12",
    "GitCommit": "af5ee6c",
    "GoVersion": "go1.20.10",
    "Os": "linux",
    "Arch": "amd64",
    "KernelVersion": "6.5.0-15-generic",
    "BuildTime": "2023-10-26T09:08:23.000000000+00:00",
}

_STOCK_VERSION = {
    "Version": "20.10.0",
    "ApiVersion": "1.41",
    "GitCommit": "deadbeef",
    "GoVersion": "go1.13.15",
    "Os": "linux",
    "Arch": "amd64",
}

_INFO = {
    "ID": "ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ12:3456:7890:ABCD:EFGH:IJKL",
    "Containers": 2,
    "ContainersRunning": 1,
    "ContainersPaused": 0,
    "ContainersStopped": 1,
    "Images": 5,
    "Driver": "overlay2",
    "Name": "prod-docker-01",
    "ServerVersion": "24.0.7",
    "OperatingSystem": "Ubuntu 22.04.3 LTS",
    "Architecture": "x86_64",
    "NCPU": 4,
    "MemTotal": 8283754496,
    "DockerRootDir": "/var/lib/docker",
    "KernelVersion": "6.5.0-15-generic",
}


def _conformant_tcp(host, port, payload=b"", **kwargs):
    text = payload.decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0]
    if first.startswith("GET /_ping"):
        return _http_bytes(200, "OK"), ""
    if first.startswith("GET /version"):
        return _http_bytes(200, _VERSION), ""
    if first.startswith("GET /info"):
        return _http_bytes(200, _INFO), ""
    if first.startswith("GET /_hpa_nonexistent_"):
        return _http_bytes(404, {"message": "page not found"}), ""
    if first.startswith("DELETE /_ping") or first.startswith("PUT /_ping"):
        return _http_bytes(404, {"message": "page not found"}), ""
    return b"", "unexpected"


def test_docker_shape_helpers():
    assert docker._is_ping_ok(200, b"OK")
    assert docker._is_ping_ok(200, b"OK\n")
    assert not docker._is_ping_ok(200, b"PONG")
    assert docker._is_docker_version(_VERSION)
    assert not docker._is_docker_version({"ok": True})
    assert not docker._is_docker_version({"ApiVersion": "1.0", "Version": "x"})
    assert docker._is_docker_info(_INFO)
    assert not docker._is_docker_info(_VERSION)


def test_docker_thin_apiversion_alone_is_not_a_speaker():
    """ApiVersion+Version without Engine shape must not unlock deep tells / decisive stock."""
    thin = {"ApiVersion": "1.0", "Version": "honeypot"}

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /_ping"):
            return _http_bytes(200, "OK"), ""
        if first.startswith("GET /version"):
            return _http_bytes(200, thin), ""
        return b"", "unexpected"

    with patch.object(docker, "tcp_transact", side_effect=fake_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["docker.version_framing"].triggered
    assert by_id["docker.version_framing"].fidelity == "medium"
    assert by_id["docker.stock_version"].skipped
    assert by_id["docker.path_facade"].skipped


def test_docker_ports_in_presets():
    from honeypot_auditor.config import (
        PORT_PRESET_DOCKER_RESEARCH,
        PORT_PRESET_IANA,
        probe_port_map,
        protocol_for_port,
    )

    assert PORT_PRESET_IANA["docker"] == 2375
    assert PORT_PRESET_DOCKER_RESEARCH["docker"] == 12375
    both = probe_port_map("both")
    assert 2375 in both["docker"]
    assert 12375 in both["docker"]
    assert protocol_for_port(2375) == "docker"
    assert protocol_for_port(12375) == "docker"


def test_docker_info_unauthorized_is_skipped():
    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /info"):
            return _http_bytes(401, {"message": "unauthorized"}), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(docker, "tcp_transact", side_effect=fake_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    info = {i.id: i for i in inds}["docker.info_stub"]
    assert info.skipped
    assert not info.triggered


def test_docker_method_405_is_not_stub():
    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("DELETE /_ping") or first.startswith("PUT /_ping"):
            return _http_bytes(405, {"message": "method not allowed"}), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(docker, "tcp_transact", side_effect=fake_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    assert not {i.id: i for i in inds}["docker.method_stub"].triggered


def test_docker_tls_hint_is_never_applicable_skip():
    from honeypot_auditor.analyzer import _is_never_applicable_skip

    with patch.object(docker, "tcp_transact", side_effect=_conformant_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    tls = {i.id: i for i in inds}["docker.tls_hint_mismatch"]
    assert tls.skipped
    assert "out of scope" in tls.skip_reason
    assert _is_never_applicable_skip(tls)


def test_docker_conformant_daemon_is_clean():
    with patch.object(docker, "tcp_transact", side_effect=_conformant_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    assert not any(ind.triggered for ind in inds)
    assert len(inds) == 7
    assert {i.id: i for i in inds}["docker.tls_hint_mismatch"].skipped


def test_docker_honeypot_tells_fire():
    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /_ping"):
            return _http_bytes(200, "OK"), ""
        if first.startswith("GET /version"):
            return _http_bytes(200, _STOCK_VERSION), ""
        if first.startswith("GET /info"):
            return _http_bytes(200, _STOCK_VERSION), ""
        if first.startswith("GET /_hpa_nonexistent_"):
            return _http_bytes(200, _STOCK_VERSION), ""
        if first.startswith("DELETE /_ping") or first.startswith("PUT /_ping"):
            return _http_bytes(200, "OK"), ""
        return b"", "unexpected"

    with patch.object(docker, "tcp_transact", side_effect=fake_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["docker.stock_version"].triggered
    assert not by_id["docker.stock_version"].requires_corroboration
    assert by_id["docker.path_facade"].triggered
    assert by_id["docker.method_stub"].triggered
    assert by_id["docker.info_stub"].triggered


def test_docker_generic_apiversion_alone_requires_corroboration():
    version = {
        "Version": "24.0.7",
        "ApiVersion": "1.41",
        "GitCommit": "af5ee6c",
        "GoVersion": "go1.20.10",
        "Os": "linux",
        "Arch": "amd64",
    }

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /version"):
            return _http_bytes(200, version), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(docker, "tcp_transact", side_effect=fake_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    stock = {i.id: i for i in inds}["docker.stock_version"]
    assert stock.triggered
    assert stock.requires_corroboration
    assert "ApiVersion=1.41" in stock.detail


def test_docker_decisive_gitcommit_scores_alone():
    version = dict(_VERSION)
    version["GitCommit"] = "deadbeef"

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /version"):
            return _http_bytes(200, version), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(docker, "tcp_transact", side_effect=fake_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    stock = {i.id: i for i in inds}["docker.stock_version"]
    assert stock.triggered
    assert not stock.requires_corroboration
    assert "GitCommit=deadbeef" in stock.detail


def test_docker_generic_version_alone_requires_corroboration():
    version = dict(_VERSION)
    version["Version"] = "20.10.0"
    version["ApiVersion"] = "1.43"

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /version"):
            return _http_bytes(200, version), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(docker, "tcp_transact", side_effect=fake_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    stock = {i.id: i for i in inds}["docker.stock_version"]
    assert stock.triggered
    assert stock.requires_corroboration
    assert "Version=20.10.0" in stock.detail


def test_docker_gated_stock_suppressed_in_default_report():
    inds = [
        Indicator(
            id="docker.stock_version",
            title="Docker version metadata matches a stock honeypot lure",
            category="static_signature",
            triggered=True,
            protocol="docker",
            detail="ApiVersion=1.41",
            requires_corroboration=True,
        )
    ]

    report = build_report(
        target="203.0.113.10",
        resolved_ip="203.0.113.10",
        ports={"docker": [2375]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )

    stock = {ind.id: ind for ind in report.indicators}["docker.stock_version"]
    assert not stock.triggered
    assert report.score == 0.0
    assert "suppressed: no corroborating tell" in stock.detail


def test_docker_gated_stock_kept_with_ungated_tell():
    inds = [
        Indicator(
            id="docker.stock_version",
            title="Docker version metadata matches a stock honeypot lure",
            category="static_signature",
            triggered=True,
            protocol="docker",
            detail="ApiVersion=1.41",
            requires_corroboration=True,
        ),
        Indicator(
            id="docker.path_facade",
            title="Docker answers unknown API paths with a version/info-shaped 200",
            category="static_signature",
            triggered=True,
            protocol="docker",
            detail="GET /_hpa_nonexistent_x returned 200",
            fidelity="high",
        ),
    ]

    report = build_report(
        target="203.0.113.10",
        resolved_ip="203.0.113.10",
        ports={"docker": [2375]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
        deep=False,
    )

    by_id = {ind.id: ind for ind in report.indicators}
    assert by_id["docker.stock_version"].triggered
    assert "suppressed" not in by_id["docker.stock_version"].detail
    assert report.score > 0


def test_docker_ping_framing_on_non_ok():
    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /_ping"):
            return _http_bytes(200, "PONG"), ""
        if first.startswith("GET /version"):
            return _http_bytes(200, _VERSION), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(docker, "tcp_transact", side_effect=fake_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["docker.ping_framing"].triggered
    assert not by_id["docker.version_framing"].triggered


def test_docker_version_framing_skips_deep_probes():
    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /_ping"):
            return _http_bytes(200, "OK"), ""
        if first.startswith("GET /version"):
            return _http_bytes(200, {"hello": "world"}), ""
        return b"", "unexpected"

    with patch.object(docker, "tcp_transact", side_effect=fake_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["docker.ping_framing"].triggered
    assert by_id["docker.version_framing"].triggered
    assert all(i.skipped or i.id in {"docker.ping_framing", "docker.version_framing"} for i in inds)
    assert len(inds) == 7


def test_docker_connection_error_skips_suite():
    with patch.object(docker, "tcp_transact", return_value=(b"", "Connection refused")):
        inds = docker.probe_docker("127.0.0.1", 2375)
    assert len(inds) == 7
    assert all(ind.skipped for ind in inds)


def test_docker_info_missing_fields_is_stub():
    thin_info = {"ServerVersion": "24.0.7", "Name": "node"}

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /info"):
            return _http_bytes(200, thin_info), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(docker, "tcp_transact", side_effect=fake_tcp):
        inds = docker.probe_docker("127.0.0.1", 2375)
    assert {i.id: i for i in inds}["docker.info_stub"].triggered


def test_docker_safe_mode_framing_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        with patch.object(docker, "tcp_transact", side_effect=_conformant_tcp):
            inds = docker.probe_docker("127.0.0.1", 2375)
    finally:
        settings.safe_mode = old
    by_id = {ind.id: ind for ind in inds}
    assert len(inds) == 7
    assert not by_id["docker.ping_framing"].triggered
    assert not by_id["docker.version_framing"].triggered
    assert by_id["docker.path_facade"].skipped
    assert by_id["docker.method_stub"].skipped
    assert by_id["docker.stock_version"].skipped
    assert by_id["docker.info_stub"].skipped
    assert by_id["docker.tls_hint_mismatch"].skipped
