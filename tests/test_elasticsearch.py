"""Elasticsearch HTTP API non-compliance probe tests."""

from __future__ import annotations

import json
from unittest.mock import patch

import honeypot_auditor.probes.elasticsearch as es
from honeypot_auditor.settings import settings


def _http_bytes(status: int, body: dict | str, *, headers: dict[str, str] | None = None) -> bytes:
    if isinstance(body, dict):
        payload = json.dumps(body).encode()
    else:
        payload = body.encode() if isinstance(body, str) else body
    hdrs = {"Content-Type": "application/json", "Content-Length": str(len(payload))}
    if headers:
        hdrs.update(headers)
    head = f"HTTP/1.1 {status} OK\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    return head.encode() + payload


_ROOT = {
    "name": "node-prod-1",
    "cluster_name": "prod-logs-eu",
    "cluster_uuid": "abcd",
    "version": {"number": "8.12.2", "build_flavor": "default"},
    "tagline": "You Know, for Search",
}

_STOCK_ROOT = {
    "name": "elastichoney",
    "cluster_name": "elasticsearch",
    "cluster_uuid": "deadbeef",
    "version": {"number": "1.4.4", "build_flavor": "default"},
    "tagline": "You Know, for Search",
}


def test_es_root_shape_helper():
    assert es._is_es_root(_ROOT)
    assert not es._is_es_root({"ok": True})


def test_es_conformant_cluster_is_clean():
    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / HTTP/"):
            return (
                _http_bytes(
                    200,
                    _ROOT,
                    headers={"X-Elastic-Product": "Elasticsearch"},
                ),
                "",
            )
        if first.startswith("GET /hpa-audit-"):
            return (
                _http_bytes(
                    404,
                    {
                        "error": {
                            "type": "index_not_found_exception",
                            "reason": "no such index",
                        },
                        "status": 404,
                    },
                ),
                "",
            )
        if first.startswith("GET /_hpa_nonexistent_"):
            return (
                _http_bytes(
                    400,
                    {"error": {"type": "invalid_index_name_exception", "reason": "invalid"}},
                ),
                "",
            )
        if first.startswith("DELETE / HTTP/"):
            return (
                _http_bytes(
                    405,
                    {"error": {"type": "method_not_allowed", "reason": "DELETE not allowed"}},
                ),
                "",
            )
        return b"", "unexpected"

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    assert not any(ind.triggered for ind in inds)
    assert len(inds) == 6


def test_es_honeypot_tells_fire():
    def fake_tcp(host, port, payload=b"", **kwargs):
        # Always return stock root — classic ElasticHoney-class stub.
        return _http_bytes(200, _STOCK_ROOT), ""

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["elasticsearch.stock_cluster"].triggered
    assert by_id["elasticsearch.missing_index_ok"].triggered
    assert by_id["elasticsearch.path_facade"].triggered
    assert by_id["elasticsearch.method_stub"].triggered


def test_es_product_header_mismatch_on_modern_version():
    modern = dict(_ROOT)
    modern["version"] = {"number": "8.11.0"}

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / HTTP/"):
            return _http_bytes(200, modern), ""  # no X-Elastic-Product
        if first.startswith("GET /hpa-audit-"):
            return (
                _http_bytes(
                    404,
                    {"error": {"type": "index_not_found_exception"}, "status": 404},
                ),
                "",
            )
        if first.startswith("GET /_hpa_nonexistent_"):
            return _http_bytes(404, {"error": {"type": "no_handler_found_exception"}}), ""
        if first.startswith("DELETE /"):
            return _http_bytes(405, {"error": {"type": "method_not_allowed"}}), ""
        return b"", "unexpected"

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    assert {i.id: i for i in inds}["elasticsearch.product_header"].triggered


def test_es_connection_error_skips_suite():
    with patch.object(es, "tcp_transact", return_value=(b"", "Connection refused")):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    assert len(inds) == 6
    assert all(ind.skipped for ind in inds)


def test_es_non_speaker_triggers_framing():
    with patch.object(
        es,
        "tcp_transact",
        return_value=(_http_bytes(200, {"hello": "world"}), ""),
    ):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["elasticsearch.root_framing"].triggered
    assert all(i.skipped or i.id == "elasticsearch.root_framing" for i in inds)


def test_es_safe_mode_handshake_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        with patch.object(
            es,
            "tcp_transact",
            return_value=(
                _http_bytes(200, _ROOT, headers={"X-Elastic-Product": "Elasticsearch"}),
                "",
            ),
        ):
            inds = es.probe_elasticsearch("127.0.0.1", 9200)
    finally:
        settings.safe_mode = old
    by_id = {ind.id: ind for ind in inds}
    assert len(inds) == 6
    assert not by_id["elasticsearch.root_framing"].triggered
    assert by_id["elasticsearch.missing_index_ok"].skipped
