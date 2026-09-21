"""Elasticsearch HTTP API non-compliance probe tests."""

from __future__ import annotations

import json
from unittest.mock import patch

import honeypot_auditor.probes.elasticsearch as es
from honeypot_auditor.analyzer import build_report
from honeypot_auditor.models import Indicator
from honeypot_auditor.settings import settings


def _http_bytes(status: int, body: dict | list | str, *, headers: dict[str, str] | None = None) -> bytes:
    if isinstance(body, (dict, list)):
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
    "cluster_uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "version": {"number": "8.12.2", "build_flavor": "default", "lucene_version": "9.9.2"},
    "tagline": "You Know, for Search",
}

_STOCK_ROOT = {
    "name": "elastichoney",
    "cluster_name": "elasticsearch",
    "cluster_uuid": "deadbeef",
    "version": {"number": "1.4.4", "build_flavor": "default"},
    "tagline": "You Know, for Search",
}

_HEALTH = {
    "cluster_name": "prod-logs-eu",
    "status": "yellow",
    "timed_out": False,
    "number_of_nodes": 3,
    "number_of_data_nodes": 3,
    "active_primary_shards": 10,
    "active_shards": 20,
}

_NODES = {
    "cluster_name": "prod-logs-eu",
    "nodes": {
        "n1": {"name": "node-prod-1", "version": "8.12.2"},
    },
}

_ES_IDS = {
    "elasticsearch.arbitrary_auth",
    "elasticsearch.state_nonpersist",
    "elasticsearch.root_framing",
    "elasticsearch.stock_cluster",
    "elasticsearch.missing_index_ok",
    "elasticsearch.path_facade",
    "elasticsearch.method_stub",
    "elasticsearch.cluster_health_stub",
    "elasticsearch.cat_stub",
    "elasticsearch.content_type",
    "elasticsearch.content_negotiation",
    "elasticsearch.product_header",
}

_FIXED_CREDS = (("probeuser10", "probepass79"), ("hpa_highentropyuser0001", "HighEntropyPassw0rd!!!!!!!!"))


def _conformant_tcp(host, port, payload=b"", **kwargs):
    text = payload.decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0]
    has_auth = "authorization:" in text.lower()
    wants_yaml = "accept: application/yaml" in text.lower()
    if first.startswith("GET / HTTP/") or first.startswith("HEAD / HTTP/"):
        if has_auth and first.startswith("GET /"):
            return (
                _http_bytes(
                    401,
                    {
                        "error": {
                            "type": "security_exception",
                            "reason": "unable to authenticate user",
                        },
                        "status": 401,
                    },
                ),
                "",
            )
        if wants_yaml and first.startswith("GET /"):
            # Real ES natively serves YAML via Accept negotiation.
            yaml_root = (
                b"---\n"
                b'name: "node-prod-1"\n'
                b'cluster_name: "prod-logs-eu"\n'
                b'cluster_uuid: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"\n'
                b'version:\n  number: "8.12.2"\n'
                b'tagline: "You Know, for Search"\n'
            )
            head = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/yaml\r\n"
                "X-Elastic-Product: Elasticsearch\r\n"
                f"Content-Length: {len(yaml_root)}\r\n\r\n"
            ).encode()
            return head + yaml_root, ""
        body = b"" if first.startswith("HEAD ") else None
        raw = _http_bytes(
            200,
            _ROOT if body is None else "",
            headers={"X-Elastic-Product": "Elasticsearch"},
        )
        if first.startswith("HEAD "):
            # Strip entity body for HEAD.
            head, _, _rest = raw.partition(b"\r\n\r\n")
            return head + b"\r\n\r\n", ""
        return raw, ""
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
    if first.startswith("GET /_nodes"):
        return _http_bytes(200, _NODES), ""
    if first.startswith("GET /_cluster/health"):
        return _http_bytes(200, _HEALTH), ""
    if first.startswith("GET /_cat/health"):
        return _http_bytes(200, [{"epoch": "1", "cluster": "prod-logs-eu", "status": "yellow"}]), ""
    if first.startswith("DELETE /") or first.startswith("PUT /"):
        return (
            _http_bytes(
                405,
                {"error": {"type": "method_not_allowed", "reason": "not allowed"}},
            ),
            "",
        )
    return b"", "unexpected"


def test_es_root_shape_helper():
    assert es._is_es_root(_ROOT)
    assert not es._is_es_root({"ok": True})
    assert es._is_cluster_health(_HEALTH)
    assert not es._is_cluster_health(_ROOT)


def test_es_conformant_cluster_is_clean():
    with (
        patch.object(es, "tcp_transact", side_effect=_conformant_tcp),
        patch.object(es, "entropy_varied_creds", return_value=_FIXED_CREDS),
        patch.object(es, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    assert {i.id for i in inds} == _ES_IDS
    assert not any(ind.triggered for ind in inds)
    assert len(inds) == len(_ES_IDS)


def test_es_honeypot_tells_fire():
    def fake_tcp(host, port, payload=b"", **kwargs):
        return _http_bytes(200, _STOCK_ROOT), ""

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["elasticsearch.stock_cluster"].triggered
    # Decisive name/version/UUID combinations should score without corroboration.
    assert not by_id["elasticsearch.stock_cluster"].requires_corroboration
    assert by_id["elasticsearch.missing_index_ok"].triggered
    assert by_id["elasticsearch.path_facade"].triggered
    assert by_id["elasticsearch.method_stub"].triggered
    assert by_id["elasticsearch.cluster_health_stub"].triggered
    assert by_id["elasticsearch.cat_stub"].triggered


def test_es_common_version_alone_requires_corroboration():
    """Production-shaped cluster on a still-deployed release must not score alone."""
    root = {
        "name": "node-prod-1",
        "cluster_name": "prod-logs-eu",
        "cluster_uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "version": {"number": "7.17.0", "build_flavor": "default"},
        "tagline": "You Know, for Search",
    }

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / HTTP/"):
            return _http_bytes(200, root, headers={"X-Elastic-Product": "Elasticsearch"}), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    stock = {i.id: i for i in inds}["elasticsearch.stock_cluster"]
    assert stock.triggered
    assert stock.requires_corroboration
    assert "version=7.17.0" in stock.detail


def test_es_frozen_version_on_unique_cluster_is_decisive():
    root = {
        "name": "node-prod-1",
        "cluster_name": "prod-logs-eu",
        "cluster_uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "version": {"number": "1.4.4", "build_flavor": "default"},
        "tagline": "You Know, for Search",
    }

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / HTTP/"):
            return _http_bytes(200, root), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    stock = {i.id: i for i in inds}["elasticsearch.stock_cluster"]
    assert stock.triggered
    assert not stock.requires_corroboration
    assert "version=1.4.4" in stock.detail


def test_es_generic_node_name_alone_requires_corroboration():
    root = dict(_ROOT)
    root["name"] = "node-1"

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / HTTP/"):
            return _http_bytes(200, root, headers={"X-Elastic-Product": "Elasticsearch"}), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    stock = {i.id: i for i in inds}["elasticsearch.stock_cluster"]
    assert stock.triggered
    assert stock.requires_corroboration
    assert "name=node-1" in stock.detail


def test_es_common_version_is_suppressed_in_default_report():
    inds = [
        Indicator(
            id="elasticsearch.stock_cluster",
            title="Elasticsearch cluster metadata matches a stock honeypot lure",
            category="static_signature",
            triggered=True,
            protocol="elasticsearch",
            detail="version=7.17.0",
            requires_corroboration=True,
        )
    ]

    report = build_report(
        target="203.0.113.10",
        resolved_ip="203.0.113.10",
        ports={"elasticsearch": [9200]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )

    stock = {ind.id: ind for ind in report.indicators}["elasticsearch.stock_cluster"]
    assert not stock.triggered
    assert report.score == 0.0
    assert "suppressed: no corroborating tell" in stock.detail


def test_es_gated_stock_kept_with_ungated_tell():
    """Common-version stock stays live when another ES tell corroborates."""
    inds = [
        Indicator(
            id="elasticsearch.stock_cluster",
            title="Elasticsearch cluster metadata matches a stock honeypot lure",
            category="static_signature",
            triggered=True,
            protocol="elasticsearch",
            detail="version=7.17.0",
            requires_corroboration=True,
        ),
        Indicator(
            id="elasticsearch.missing_index_ok",
            title="Elasticsearch returns success for a nonexistent index",
            category="static_signature",
            triggered=True,
            protocol="elasticsearch",
            detail="GET /hpa-audit-x returned 200",
            fidelity="high",
        ),
    ]

    report = build_report(
        target="203.0.113.10",
        resolved_ip="203.0.113.10",
        ports={"elasticsearch": [9200]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
        deep=False,
    )

    by_id = {ind.id: ind for ind in report.indicators}
    assert by_id["elasticsearch.stock_cluster"].triggered
    assert "suppressed" not in by_id["elasticsearch.stock_cluster"].detail
    assert report.score > 0


def test_es_short_uuid_with_generic_cluster_requires_corroboration():
    """Short UUID must not lift the gate when only generic cluster_name is present."""
    root = {
        "name": "node-prod-1",
        "cluster_name": "elasticsearch",
        "cluster_uuid": "abc",
        "version": {"number": "8.12.2", "build_flavor": "default"},
        "tagline": "You Know, for Search",
    }

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / HTTP/"):
            return _http_bytes(200, root, headers={"X-Elastic-Product": "Elasticsearch"}), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    stock = {i.id: i for i in inds}["elasticsearch.stock_cluster"]
    assert stock.triggered
    assert stock.requires_corroboration
    assert "cluster_uuid=abc" in stock.detail


def test_es_product_header_mismatch_on_modern_version():
    modern = dict(_ROOT)
    modern["version"] = {"number": "8.11.0", "build_flavor": "default"}

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / HTTP/"):
            return _http_bytes(200, modern), ""  # no X-Elastic-Product
        if first.startswith("HEAD /"):
            head, _, _ = _http_bytes(200, modern).partition(b"\r\n\r\n")
            return head + b"\r\n\r\n", ""
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
        if first.startswith("GET /_cluster/health"):
            return _http_bytes(200, _HEALTH), ""
        if first.startswith("GET /_cat/health"):
            return _http_bytes(200, [{"status": "green"}]), ""
        if first.startswith("DELETE /") or first.startswith("PUT /"):
            return _http_bytes(405, {"error": {"type": "method_not_allowed"}}), ""
        return b"", "unexpected"

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    assert {i.id: i for i in inds}["elasticsearch.product_header"].triggered


def test_es_content_type_facade():
    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / HTTP/"):
            return (
                _http_bytes(
                    200,
                    _ROOT,
                    headers={
                        "Content-Type": "text/html",
                        "X-Elastic-Product": "Elasticsearch",
                    },
                ),
                "",
            )
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    assert {i.id: i for i in inds}["elasticsearch.content_type"].triggered


def test_es_head_body_is_method_stub():
    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("HEAD /"):
            return _http_bytes(200, _ROOT, headers={"X-Elastic-Product": "Elasticsearch"}), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with patch.object(es, "tcp_transact", side_effect=fake_tcp):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    assert {i.id: i for i in inds}["elasticsearch.method_stub"].triggered


def test_es_connection_error_skips_suite():
    with patch.object(es, "tcp_transact", return_value=(b"", "Connection refused")):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    assert len(inds) == len(_ES_IDS)
    assert {i.id for i in inds} == _ES_IDS
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
    assert len(inds) == len(_ES_IDS)


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
    assert len(inds) == len(_ES_IDS)
    assert {i.id for i in inds} == _ES_IDS
    assert not by_id["elasticsearch.root_framing"].triggered
    assert by_id["elasticsearch.arbitrary_auth"].skipped
    assert by_id["elasticsearch.state_nonpersist"].skipped
    assert by_id["elasticsearch.missing_index_ok"].skipped
    assert by_id["elasticsearch.cluster_health_stub"].skipped


def test_es_arbitrary_auth_dual_basic():
    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        has_auth = "authorization:" in text.lower()
        if first.startswith("GET / HTTP/") and has_auth:
            return _http_bytes(200, _ROOT, headers={"X-Elastic-Product": "Elasticsearch"}), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with (
        patch.object(es, "tcp_transact", side_effect=fake_tcp),
        patch.object(es, "entropy_varied_creds", return_value=_FIXED_CREDS),
        patch.object(es, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    auth = {i.id: i for i in inds}["elasticsearch.arbitrary_auth"]
    assert not auth.triggered
    assert "credential gate" in auth.detail


def test_es_arbitrary_auth_after_anonymous_challenge():
    """401 on anonymous GET /, then any Basic unlocks the root."""

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        has_auth = "authorization:" in text.lower()
        if first.startswith("GET / HTTP/") and has_auth:
            return _http_bytes(200, _ROOT, headers={"X-Elastic-Product": "Elasticsearch"}), ""
        if first.startswith("GET / HTTP/"):
            return (
                _http_bytes(
                    401,
                    {"error": {"type": "security_exception", "reason": "missing credentials"}, "status": 401},
                ),
                "",
            )
        return _conformant_tcp(host, port, payload, **kwargs)

    with (
        patch.object(es, "tcp_transact", side_effect=fake_tcp),
        patch.object(es, "entropy_varied_creds", return_value=_FIXED_CREDS),
        patch.object(es, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    auth = {i.id: i for i in inds}["elasticsearch.arbitrary_auth"]
    assert auth.triggered
    assert auth.fidelity == "decisive"
    assert "," in (auth.evidence or "")


def test_es_state_nonpersist_version_mismatch():
    bad_nodes = {
        "cluster_name": "prod-logs-eu",
        "nodes": {"n1": {"name": "node-prod-1", "version": "1.4.4"}},
    }

    def fake_tcp(host, port, payload=b"", **kwargs):
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /_nodes"):
            return _http_bytes(200, bad_nodes), ""
        return _conformant_tcp(host, port, payload, **kwargs)

    with (
        patch.object(es, "tcp_transact", side_effect=fake_tcp),
        patch.object(es, "entropy_varied_creds", return_value=_FIXED_CREDS),
        patch.object(es, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    state = {i.id: i for i in inds}["elasticsearch.state_nonpersist"]
    assert state.triggered
    assert state.category == "state_nonpersist"
    assert "version" in state.detail


def test_es_yaml_negotiation_json_only_skin():
    """JSON-only reply to Accept: application/yaml → gated content_negotiation hit."""

    def fake_tcp(host, port, payload=b"", **kwargs):
        del host, port
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / HTTP/") or first.startswith("HEAD / HTTP/"):
            if "authorization:" in text.lower():
                return (
                    _http_bytes(
                        401,
                        {
                            "error": {
                                "type": "security_exception",
                                "reason": "unable to authenticate user",
                            },
                            "status": 401,
                        },
                    ),
                    "",
                )
            # Skin: same JSON root regardless of Accept.
            return (
                _http_bytes(200, _ROOT, headers={"X-Elastic-Product": "Elasticsearch"}),
                "",
            )
        if first.startswith("GET /hpa-audit-"):
            return (
                _http_bytes(
                    404,
                    {"error": {"type": "index_not_found_exception", "reason": "no such index"}},
                ),
                "",
            )
        if first.startswith("GET /_hpa_nonexistent_"):
            return (_http_bytes(400, {"error": {"type": "invalid_index_name_exception"}}), "")
        if first.startswith("GET /_nodes"):
            return _http_bytes(200, _NODES), ""
        if first.startswith("GET /_cluster/health"):
            return _http_bytes(200, _HEALTH), ""
        if first.startswith("GET /_cat/health"):
            return _http_bytes(200, [{"epoch": "1", "cluster": "prod-logs-eu", "status": "yellow"}]), ""
        if first.startswith("DELETE /") or first.startswith("PUT /"):
            return (_http_bytes(405, {"error": {"type": "method_not_allowed"}}), "")
        return b"", "unexpected"

    with (
        patch.object(es, "tcp_transact", side_effect=fake_tcp),
        patch.object(es, "entropy_varied_creds", return_value=_FIXED_CREDS),
        patch.object(es, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    by_id = {i.id: i for i in inds}
    yaml_ind = by_id["elasticsearch.content_negotiation"]
    assert yaml_ind.triggered
    assert not yaml_ind.skipped
    assert yaml_ind.requires_corroboration is True
    assert "JSON" in yaml_ind.detail


def test_es_yaml_negotiation_conformant_is_clean():
    with (
        patch.object(es, "tcp_transact", side_effect=_conformant_tcp),
        patch.object(es, "entropy_varied_creds", return_value=_FIXED_CREDS),
        patch.object(es, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = es.probe_elasticsearch("127.0.0.1", 9200)
    by_id = {i.id: i for i in inds}
    yaml_ind = by_id["elasticsearch.content_negotiation"]
    assert not yaml_ind.triggered
    assert not yaml_ind.skipped
    assert "yaml honored" in yaml_ind.detail
