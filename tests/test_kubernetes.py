"""Kubernetes API server non-compliance probe tests."""

from __future__ import annotations

import json
from unittest.mock import patch

import honeypot_auditor.probes.kubernetes as k8s
from honeypot_auditor.analyzer import build_report
from honeypot_auditor.models import Indicator
from honeypot_auditor.settings import settings


def _http_bytes(status: int, body: dict | list | str | bytes, *, headers: dict[str, str] | None = None) -> bytes:
    if isinstance(body, (dict, list)):
        payload = json.dumps(body).encode()
    elif isinstance(body, str):
        payload = body.encode()
    else:
        payload = body
    hdrs = {"Content-Type": "application/json", "Content-Length": str(len(payload))}
    if headers:
        hdrs.update(headers)
    if isinstance(body, str) and not body.strip().startswith(("{", "[")):
        hdrs["Content-Type"] = "text/plain"
    head = f"HTTP/1.1 {status} OK\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    return head.encode() + payload


_VERSION = {
    "major": "1",
    "minor": "29",
    "gitVersion": "v1.29.2",
    "gitCommit": "abcdef0123456789",
    "gitTreeState": "clean",
    "buildDate": "2024-02-14T10:00:00Z",
    "goVersion": "go1.21.7",
    "compiler": "gc",
    "platform": "linux/amd64",
}

_STOCK_VERSION = {
    "major": "1",
    "minor": "18",
    "gitVersion": "v1.18.0+kube-honeypot",
    "gitCommit": "deadbeef",
    "platform": "honeypot/amd64",
}

_API_VERSIONS = {
    "kind": "APIVersions",
    "versions": ["v1"],
    "serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0", "serverAddress": "10.0.0.1:6443"}],
}

_API_RESOURCE_LIST = {
    "kind": "APIResourceList",
    "groupVersion": "v1",
    "resources": [
        {"name": "pods", "singularName": "pod", "namespaced": True, "kind": "Pod"},
        {"name": "secrets", "singularName": "secret", "namespaced": True, "kind": "Secret"},
    ],
}

_POD_LIST = {
    "kind": "PodList",
    "apiVersion": "v1",
    "items": [{"metadata": {"name": "nginx"}, "status": {"phase": "Running"}}],
}


def _conformant_exchange(host, port, method, path, **kwargs):
    if method == "GET" and path in ("/livez", "/healthz"):
        return 200, {"content-type": "text/plain"}, b"ok", ""
    if method == "GET" and path == "/version":
        return 200, {"content-type": "application/json"}, json.dumps(_VERSION).encode(), ""
    if method == "DELETE" and path == "/version":
        return 405, {"content-type": "application/json"}, b'{"kind":"Status","status":"Failure"}', ""
    if method == "GET" and path == "/api":
        return 200, {"content-type": "application/json"}, json.dumps(_API_VERSIONS).encode(), ""
    if method == "GET" and path.startswith("/_hpa_nonexistent_"):
        return 404, {"content-type": "application/json"}, b'{"kind":"Status","status":"Failure","code":404}', ""
    if method == "GET" and path == "/api/v1":
        return 200, {"content-type": "application/json"}, json.dumps(_API_RESOURCE_LIST).encode(), ""
    return 0, {}, b"", "unexpected"


def test_k8s_shape_helpers():
    assert k8s._is_health_ok(200, b"ok")
    assert k8s._is_health_ok(200, b"ok\n")
    assert not k8s._is_health_ok(200, b"healthy")
    assert k8s._is_version_doc(_VERSION)
    assert not k8s._is_version_doc({"ok": True})
    assert k8s._is_api_versions(_API_VERSIONS)
    assert not k8s._is_api_versions(_VERSION)
    assert k8s._is_api_resource_list(_API_RESOURCE_LIST)
    assert k8s._looks_like_object_list(_POD_LIST)


def test_k8s_conformant_api_is_clean():
    with patch.object(k8s, "_http_exchange", side_effect=_conformant_exchange):
        inds = k8s.probe_kubernetes("127.0.0.1", 6443)
    assert not any(ind.triggered for ind in inds)
    assert len(inds) == 7


def test_k8s_honeypot_tells_fire():
    def fake_ex(host, port, method, path, **kwargs):
        if method == "GET" and path in ("/livez", "/healthz"):
            return 200, {}, json.dumps(_STOCK_VERSION).encode(), ""
        if path == "/version":
            return 200, {}, json.dumps(_STOCK_VERSION).encode(), ""
        if method == "GET" and path == "/api":
            return 200, {}, json.dumps(_STOCK_VERSION).encode(), ""
        if method == "GET" and path.startswith("/_hpa_nonexistent_"):
            return 200, {}, json.dumps(_STOCK_VERSION).encode(), ""
        if method == "GET" and path == "/api/v1":
            return 200, {}, json.dumps(_POD_LIST).encode(), ""
        return 0, {}, b"", "unexpected"

    with patch.object(k8s, "_http_exchange", side_effect=fake_ex):
        inds = k8s.probe_kubernetes("127.0.0.1", 6443)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["kubernetes.health_framing"].triggered
    assert not by_id["kubernetes.version_framing"].triggered  # parseable, but stock
    assert by_id["kubernetes.api_framing"].triggered
    assert by_id["kubernetes.path_facade"].triggered
    assert by_id["kubernetes.method_stub"].triggered
    assert by_id["kubernetes.stock_version"].triggered
    assert not by_id["kubernetes.stock_version"].requires_corroboration
    assert by_id["kubernetes.unauthenticated_ok"].triggered


def test_k8s_generic_gitversion_requires_corroboration():
    root = dict(_VERSION)
    root["gitVersion"] = "v1.18.0"

    def fake_ex(host, port, method, path, **kwargs):
        if method == "GET" and path in ("/livez", "/healthz"):
            return 200, {}, b"ok", ""
        if method == "GET" and path == "/version":
            return 200, {}, json.dumps(root).encode(), ""
        return _conformant_exchange(host, port, method, path, **kwargs)

    with patch.object(k8s, "_http_exchange", side_effect=fake_ex):
        inds = k8s.probe_kubernetes("127.0.0.1", 6443)
    stock = {i.id: i for i in inds}["kubernetes.stock_version"]
    assert stock.triggered
    assert stock.requires_corroboration
    assert "gitVersion=v1.18.0" in stock.detail


def test_k8s_gated_stock_suppressed_in_default_report():
    inds = [
        Indicator(
            id="kubernetes.stock_version",
            title="Kubernetes version metadata matches a stock honeypot lure",
            category="static_signature",
            triggered=True,
            protocol="kubernetes",
            detail="gitVersion=v1.18.0",
            requires_corroboration=True,
        )
    ]
    report = build_report(
        target="203.0.113.10",
        resolved_ip="203.0.113.10",
        ports={"kubernetes": [6443]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    stock = {ind.id: ind for ind in report.indicators}["kubernetes.stock_version"]
    assert not stock.triggered
    assert report.score == 0.0
    assert "suppressed: no corroborating tell" in stock.detail


def test_k8s_gated_stock_kept_with_ungated_tell():
    inds = [
        Indicator(
            id="kubernetes.stock_version",
            title="Kubernetes version metadata matches a stock honeypot lure",
            category="static_signature",
            triggered=True,
            protocol="kubernetes",
            detail="gitVersion=v1.18.0",
            requires_corroboration=True,
        ),
        Indicator(
            id="kubernetes.path_facade",
            title="Kubernetes answers unknown API paths with a version-shaped 200",
            category="static_signature",
            triggered=True,
            protocol="kubernetes",
            detail="unknown path echoed /version",
            fidelity="high",
        ),
    ]
    report = build_report(
        target="203.0.113.10",
        resolved_ip="203.0.113.10",
        ports={"kubernetes": [6443]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
        deep=False,
    )
    by_id = {ind.id: ind for ind in report.indicators}
    assert by_id["kubernetes.stock_version"].triggered
    assert "suppressed" not in by_id["kubernetes.stock_version"].detail
    assert report.score > 0


def test_k8s_api_v1_resource_list_is_not_unauth_tell():
    with patch.object(k8s, "_http_exchange", side_effect=_conformant_exchange):
        inds = k8s.probe_kubernetes("127.0.0.1", 6443)
    assert not {i.id: i for i in inds}["kubernetes.unauthenticated_ok"].triggered


def test_k8s_api_v1_401_is_clean():
    def fake_ex(host, port, method, path, **kwargs):
        if method == "GET" and path == "/api/v1":
            return 401, {}, b'{"kind":"Status","status":"Failure","code":401}', ""
        return _conformant_exchange(host, port, method, path, **kwargs)

    with patch.object(k8s, "_http_exchange", side_effect=fake_ex):
        inds = k8s.probe_kubernetes("127.0.0.1", 6443)
    assert not {i.id: i for i in inds}["kubernetes.unauthenticated_ok"].triggered


def test_k8s_tls_preferred_on_api_ports():
    calls: list[tuple[str, int]] = []

    def fake_tls(host, port, timeout):
        calls.append(("tls", port))
        raise OSError("refused")

    def fake_plain(host, port, timeout):
        calls.append(("plain", port))
        raise OSError("refused")

    with patch.object(k8s, "create_tls_connection", side_effect=fake_tls):
        with patch.object(k8s, "create_connection", side_effect=fake_plain):
            inds = k8s.probe_kubernetes("127.0.0.1", 6443)
    assert ("tls", 6443) in calls
    assert ("plain", 6443) not in calls
    assert all(ind.skipped for ind in inds)

    calls.clear()
    with patch.object(k8s, "create_tls_connection", side_effect=fake_tls):
        with patch.object(k8s, "create_connection", side_effect=fake_plain):
            k8s.probe_kubernetes("127.0.0.1", 16443)
    assert ("tls", 16443) in calls
    assert ("plain", 16443) not in calls


def test_k8s_connection_error_skips_suite():
    with patch.object(k8s, "_http_exchange", return_value=(0, {}, b"", "Connection refused")):
        inds = k8s.probe_kubernetes("127.0.0.1", 6443)
    assert len(inds) == 7
    assert all(ind.skipped for ind in inds)


def test_k8s_non_speaker_triggers_framing():
    with patch.object(
        k8s,
        "_http_exchange",
        return_value=(200, {}, json.dumps({"hello": "world"}).encode(), ""),
    ):
        inds = k8s.probe_kubernetes("127.0.0.1", 6443)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["kubernetes.health_framing"].triggered
    assert by_id["kubernetes.version_framing"].triggered
    assert all(
        i.skipped or i.id in {"kubernetes.health_framing", "kubernetes.version_framing"}
        for i in inds
    )
    assert len(inds) == 7


def test_k8s_safe_mode_framing_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        with patch.object(k8s, "_http_exchange", side_effect=_conformant_exchange):
            inds = k8s.probe_kubernetes("127.0.0.1", 6443)
    finally:
        settings.safe_mode = old
    by_id = {ind.id: ind for ind in inds}
    assert len(inds) == 7
    assert not by_id["kubernetes.health_framing"].triggered
    assert not by_id["kubernetes.version_framing"].triggered
    assert by_id["kubernetes.api_framing"].skipped
    assert by_id["kubernetes.path_facade"].skipped
    assert by_id["kubernetes.method_stub"].skipped
    assert by_id["kubernetes.stock_version"].skipped
    assert by_id["kubernetes.unauthenticated_ok"].skipped


def test_k8s_ports_wired():
    from honeypot_auditor.config import PROTOCOL_STRATEGIES, probe_port_map, protocol_for_port

    assert protocol_for_port(6443) == "kubernetes"
    assert protocol_for_port(16443) == "kubernetes"
    ports = probe_port_map("both")
    assert ports["kubernetes"] == [6443, 16443]
    assert "kubernetes" in PROTOCOL_STRATEGIES
    assert PROTOCOL_STRATEGIES["kubernetes"]["static_signature"]
    assert not PROTOCOL_STRATEGIES["kubernetes"]["arbitrary_auth"]
    assert not PROTOCOL_STRATEGIES["kubernetes"]["state_nonpersist"]
