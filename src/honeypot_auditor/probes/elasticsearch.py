"""Elasticsearch HTTP API fingerprint engine.

Protocol non-compliance strategies (read-only — never index/delete/bulk write):
  · arbitrary_auth — anonymous GET / challenged 401/403, then two entropy-varied
    Basic headers both return the root document
  · state_nonpersist — root cluster UUID/version vs /_nodes or /_cluster/health
  · static_signature — stock cluster/version/tagline/uuid lures; missing-index 200;
    unknown API path returns root-shaped 200; DELETE/PUT/HEAD on ``/`` method stubs;
    ``/_cluster/health`` and ``/_cat/health`` shape facades; wrong Content-Type;
    X-Elastic-Product header inconsistency vs claimed version
  · framing — GET ``/`` is not a parseable Elasticsearch root document

Ports 9200 / lab 19200 (HTTP). Transport port 9300 is out of scope.

See docs/tcp/ELASTICSEARCH.md and Elasticsearch HTTP API docs (root, cat, cluster, errors).
"""

from __future__ import annotations

import base64
import json
import re
import secrets
from typing import Any

from honeypot_auditor.config import effective_user_agent
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import (
    entropy_varied_creds,
    is_safe_mode,
    jittered_reconnect_pause,
    rtt_evidence,
    skip_suite,
)
from honeypot_auditor.settings import settings

_ES_SKIP = (
    (
        "elasticsearch.arbitrary_auth",
        "Elasticsearch accepts two entropy-varied Basic credentials on GET /",
        "arbitrary_auth",
    ),
    (
        "elasticsearch.state_nonpersist",
        "Elasticsearch root metadata mismatches /_nodes or /_cluster/health",
        "state_nonpersist",
    ),
    (
        "elasticsearch.root_framing",
        "Elasticsearch root response is not a valid cluster document",
        "static_signature",
    ),
    (
        "elasticsearch.stock_cluster",
        "Elasticsearch cluster metadata matches a stock honeypot lure",
        "static_signature",
    ),
    (
        "elasticsearch.missing_index_ok",
        "Elasticsearch returns success for a nonexistent index",
        "static_signature",
    ),
    (
        "elasticsearch.path_facade",
        "Elasticsearch answers unknown API paths with a root-shaped 200",
        "static_signature",
    ),
    (
        "elasticsearch.method_stub",
        "Elasticsearch ignores HTTP method on / (DELETE/PUT/HEAD stub)",
        "static_signature",
    ),
    (
        "elasticsearch.cluster_health_stub",
        "Elasticsearch /_cluster/health does not return a health document",
        "static_signature",
    ),
    (
        "elasticsearch.cat_stub",
        "Elasticsearch /_cat/health returns a root-shaped document",
        "static_signature",
    ),
    (
        "elasticsearch.content_type",
        "Elasticsearch JSON body is served with a non-JSON Content-Type",
        "static_signature",
    ),
    (
        "elasticsearch.content_negotiation",
        "Elasticsearch ignores an Accept: application/yaml request",
        "static_signature",
    ),
    (
        "elasticsearch.product_header",
        "Elasticsearch product header is missing or inconsistent with version",
        "static_signature",
    ),
)

# Decisive lure names — rare outside honeypots; score without corroboration.
_STOCK_CLUSTER_NAMES_DECISIVE = frozenset(
    {
        "elastichoney",
        "honeypot",
        "elastic-honeypot",
        "es-honeypot",
    }
)
# Generic / docker defaults — common on real clusters; corroboration-gated.
_STOCK_CLUSTER_NAMES_GENERIC = frozenset(
    {
        "elasticsearch",
        "docker-cluster",
        "test-cluster",
        "opensearch",
        "es-docker-cluster",
        "docker-compose",
    }
)
_STOCK_CLUSTER_NAMES = _STOCK_CLUSTER_NAMES_DECISIVE | _STOCK_CLUSTER_NAMES_GENERIC

_STOCK_NODE_NAMES_DECISIVE = frozenset(
    {
        "elastichoney",
        "honeypot",
        "es-honeypot",
    }
)
_STOCK_NODE_NAMES_GENERIC = frozenset(
    {
        "node-1",
        "elasticsearch",
        "es01",
        "es02",
        "docker-node",
    }
)
_STOCK_NODE_NAMES = _STOCK_NODE_NAMES_DECISIVE | _STOCK_NODE_NAMES_GENERIC

_STOCK_TAGLINES_DECISIVE = (
    "elastichoney",
    "fake elasticsearch",
    "honeypot search",
)
# OpenSearch default tagline appears on real OpenSearch deployments too.
_STOCK_TAGLINES_GENERIC = ("the open search project",)
_STOCK_TAGLINES = _STOCK_TAGLINES_DECISIVE + _STOCK_TAGLINES_GENERIC

# Long-EOL / frozen lure versions — decisive.
_STOCK_VERSIONS_FROZEN = frozenset(
    {
        "1.4.1",
        "1.4.2",
        "1.4.4",
        "1.7.6",
        "2.3.0",
        "2.4.6",
        "5.0.0",
        "5.6.16",
    }
)
# Still widely deployed release numbers — match but require corroboration alone.
_STOCK_VERSIONS_COMMON = frozenset(
    {
        "6.8.0",
        "7.0.0",
        "7.10.0",
        "7.10.2",
        "7.17.0",
        "8.0.0",
    }
)
_STOCK_VERSIONS = _STOCK_VERSIONS_FROZEN | _STOCK_VERSIONS_COMMON

_STOCK_CLUSTER_UUIDS = frozenset(
    {
        "deadbeef",
        "deadbeef-dead-beef-dead-beefdeadbeef",
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        "test",
        "abcd",
        "elasticsearch",
    }
)

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def _http_exchange(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    extra_headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> tuple[int, dict[str, str], bytes, str]:
    """Minimal HTTP/1.1 exchange over TCP. Returns (status, headers, body, error)."""
    hdrs = {
        "Host": f"{host}:{port}",
        "User-Agent": effective_user_agent(),
        "Accept": "application/json",
        "Connection": "close",
    }
    if extra_headers:
        hdrs.update(extra_headers)
    if body:
        hdrs.setdefault("Content-Type", "application/json")
        hdrs["Content-Length"] = str(len(body))
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        + "\r\n"
    ).encode("ascii", "replace") + body
    raw, err = tcp_transact(
        host, port, request, recv_first=False, timeout=settings.timeout_seconds
    )
    if err and not raw:
        return 0, {}, b"", closed_reason(err)
    if not raw:
        return 0, {}, b"", "empty HTTP response"
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return 0, {}, rest, "missing status line"
    status_line = lines[0].decode("latin-1", "replace")
    parts = status_line.split()
    status = 0
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        try:
            status = int(parts[1])
        except ValueError:
            status = 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.decode("latin-1", "replace").strip().lower()] = value.decode(
            "latin-1", "replace"
        ).strip()
    return status, headers, rest, ""


def _parse_json(body: bytes) -> dict[str, Any] | list[Any] | None:
    if not body:
        return None
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, (dict, list)):
        return data
    return None


def _as_dict(data: dict[str, Any] | list[Any] | None) -> dict[str, Any] | None:
    return data if isinstance(data, dict) else None


def _is_es_root(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    version = doc.get("version")
    has_version = isinstance(version, dict) and "number" in version
    has_tagline = isinstance(doc.get("tagline"), str)
    has_cluster = isinstance(doc.get("cluster_name"), str) or isinstance(doc.get("name"), str)
    return bool(has_version and (has_tagline or has_cluster))


def _is_cluster_health(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    status = str(doc.get("status") or "").lower()
    has_status = status in {"green", "yellow", "red"}
    has_nodes = "number_of_nodes" in doc or "number_of_data_nodes" in doc
    has_cluster = isinstance(doc.get("cluster_name"), str)
    # Must not look like the root document (version.number + tagline).
    if _is_es_root(doc):
        return False
    return bool(has_status and (has_nodes or has_cluster))


def _version_number(doc: dict[str, Any] | None) -> str:
    if not doc:
        return ""
    version = doc.get("version")
    if isinstance(version, dict):
        return str(version.get("number") or "")
    return ""


def _major_minor_patch(version: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.match(version or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _stock_cluster_assessment(doc: dict[str, Any]) -> tuple[str | None, bool]:
    """Return ``(detail, requires_corroboration)`` for stock lure metadata.

    Decisive tokens (honeypot names, frozen EOL versions, canned UUIDs in
    ``_STOCK_CLUSTER_UUIDS``) score alone. Generic docker/default names,
    still-deployed release numbers, and short/truncated UUIDs only contribute
    when another category hit corroborates them — or when mixed with a
    decisive token on the same root document.
    """
    cluster = str(doc.get("cluster_name") or "").strip().lower()
    name = str(doc.get("name") or "").strip().lower()
    tagline = str(doc.get("tagline") or "").strip().lower()
    version = _version_number(doc).strip()
    uuid = str(doc.get("cluster_uuid") or "").strip().lower()
    hits: list[str] = []
    decisive = False
    if cluster in _STOCK_CLUSTER_NAMES_DECISIVE:
        hits.append(f"cluster_name={cluster}")
        decisive = True
    elif cluster in _STOCK_CLUSTER_NAMES_GENERIC:
        hits.append(f"cluster_name={cluster}")
    if name in _STOCK_NODE_NAMES_DECISIVE:
        hits.append(f"name={name}")
        decisive = True
    elif name in _STOCK_NODE_NAMES_GENERIC:
        hits.append(f"name={name}")
    for tell in _STOCK_TAGLINES_DECISIVE:
        if tell in tagline:
            hits.append(f"tagline~{tell}")
            decisive = True
            break
    else:
        for tell in _STOCK_TAGLINES_GENERIC:
            if tell in tagline:
                hits.append(f"tagline~{tell}")
                break
    if version in _STOCK_VERSIONS_FROZEN:
        hits.append(f"version={version}")
        decisive = True
    elif version in _STOCK_VERSIONS_COMMON:
        hits.append(f"version={version}")
    if uuid in _STOCK_CLUSTER_UUIDS:
        hits.append(f"cluster_uuid={uuid}")
        decisive = True
    elif uuid and len(uuid) < 8:
        # Truncated/placeholder UUIDs are a weak tell alone (not decisive).
        hits.append(f"cluster_uuid={uuid}")
    if not hits:
        return None, False
    requires = not decisive
    return "; ".join(hits), requires


def _looks_like_index_missing(status: int, doc: dict[str, Any] | None) -> bool:
    if status == 404:
        return True
    if not doc:
        return False
    err = doc.get("error")
    if isinstance(err, dict):
        err_type = str(err.get("type") or "").lower()
        reason = str(err.get("reason") or "").lower()
        if "index_not_found" in err_type or "no such index" in reason:
            return True
    if str(doc.get("status") or "") == "404":
        return True
    return False


def _looks_like_api_not_found(status: int, doc: dict[str, Any] | None) -> bool:
    if status in {400, 404, 405}:
        return True
    if not doc:
        return status >= 400
    err = doc.get("error")
    if isinstance(err, dict):
        err_type = str(err.get("type") or "").lower()
        if any(
            token in err_type
            for token in ("invalid", "illegal", "not_found", "no_handler", "parse")
        ):
            return True
    return False


def _content_type_is_json(headers: dict[str, str]) -> bool:
    ctype = (headers.get("content-type") or "").lower()
    return "application/json" in ctype or "application/vnd.elasticsearch" in ctype


def _basic_auth_header(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _is_nodes_doc(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    nodes = doc.get("nodes")
    return isinstance(nodes, dict) and bool(nodes)


def _state_metadata_mismatch(
    root: dict[str, Any],
    *,
    nodes_doc: dict[str, Any] | None,
    nodes_status: int,
    health_doc: dict[str, Any] | None,
    health_status: int,
) -> tuple[bool, str]:
    """Return (hit, detail) for root vs nodes/health contradictions."""
    root_cluster = str(root.get("cluster_name") or "").strip()
    root_ver = _version_number(root).strip()
    notes: list[str] = []

    nodes_ok = nodes_status == 200 and _is_nodes_doc(nodes_doc)
    if nodes_status == 200 and not nodes_ok:
        notes.append(
            f"/_nodes empty/wrong shape while root looked real "
            f"(keys={sorted(nodes_doc)[:8] if nodes_doc else []})"
        )
    elif nodes_ok and nodes_doc is not None:
        node_cluster = str(nodes_doc.get("cluster_name") or "").strip()
        if root_cluster and node_cluster and root_cluster != node_cluster:
            notes.append(
                f"cluster_name root={root_cluster!r} vs /_nodes={node_cluster!r}"
            )
        nodes_map = nodes_doc.get("nodes")
        if isinstance(nodes_map, dict):
            for _nid, info in nodes_map.items():
                if not isinstance(info, dict):
                    continue
                nver = str(info.get("version") or "").strip()
                if root_ver and nver and nver != root_ver:
                    notes.append(f"version root={root_ver!r} vs node={nver!r}")
                    break

    health_ok = health_status == 200 and _is_cluster_health(health_doc)
    if health_status == 200 and not health_ok:
        notes.append(
            f"/_cluster/health empty/wrong shape while root looked real "
            f"(keys={sorted(health_doc)[:8] if health_doc else []})"
        )
    elif health_ok and health_doc is not None:
        h_cluster = str(health_doc.get("cluster_name") or "").strip()
        if root_cluster and h_cluster and root_cluster != h_cluster:
            notes.append(
                f"cluster_name root={root_cluster!r} vs health={h_cluster!r}"
            )

    if notes:
        return True, "; ".join(notes)
    return False, "root metadata consistent with /_nodes and /_cluster/health"


def probe_elasticsearch(host: str, port: int) -> list[Indicator]:
    status, headers, body, err = _http_exchange(host, port, "GET", "/")
    if err and not body and status == 0:
        return skip_suite(_ES_SKIP, err, protocol="elasticsearch", error=err)

    root = _as_dict(_parse_json(body))
    root_ok = _is_es_root(root)
    framing_hit = not root_ok
    auth_from_challenge = False
    auth_ok = 0
    auth_notes: list[str] = []
    auth_err = ""
    auth_skipped = False
    low_user = ""
    high_user = ""
    if root is not None and root_ok:
        framing_detail = (
            f"root ok cluster_name={root.get('cluster_name')!r} "
            f"version={_version_number(root)!r}"
        )
    else:
        framing_detail = (
            "GET / did not return an Elasticsearch root document "
            f"(status={status}, json_keys={sorted(root)[:8] if root else []})"
        )

    # Security-enabled clusters challenge GET /. A skin that then accepts any
    # Basic credential and returns the root is an auth bypass. An already-open
    # root (anonymous 200) is not: Basic is ignored because there is no gate.
    if framing_hit and status in (401, 403):
        anon_status = status
        (low_user, low_pass), (high_user, high_pass) = entropy_varied_creds()
        unlocked: tuple[int, dict[str, str], bytes] | None = None
        for label, user, password in (
            ("low-entropy", low_user, low_pass),
            ("high-entropy", high_user, high_pass),
        ):
            a_status, a_hdrs, a_body, a_err = _http_exchange(
                host,
                port,
                "GET",
                "/",
                extra_headers=_basic_auth_header(user, password),
            )
            if a_err and a_status == 0 and not a_body:
                auth_err = auth_err or a_err
                auth_notes.append(f"{label}: unanswered ({a_err})")
                continue
            a_doc = _as_dict(_parse_json(a_body))
            if a_status == 200 and _is_es_root(a_doc):
                auth_ok += 1
                unlocked = (a_status, a_hdrs, a_body)
                root = a_doc
                auth_notes.append(f"{label}: Basic unlocked ES root (status=200)")
            else:
                auth_notes.append(f"{label}: Basic status={a_status}")
        if auth_ok == 2 and unlocked is not None and root is not None and _is_es_root(root):
            status, headers, body = unlocked
            root_ok = True
            framing_hit = False
            auth_from_challenge = True
            framing_detail = (
                f"anonymous GET / was {anon_status}; root unlocked by arbitrary Basic "
                f"cluster_name={root.get('cluster_name')!r} version={_version_number(root)!r}"
            )

    if framing_hit:
        out: list[Indicator] = []
        for spec in _ES_SKIP:
            if spec[0] == "elasticsearch.root_framing":
                out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=bool(body) or status > 0,
                        skipped=not body and status == 0,
                        skip_reason=err if not body and status == 0 else "",
                        protocol="elasticsearch",
                        detail=framing_detail if (body or status) else err or "not an ES speaker",
                        evidence=(body[:400].decode("utf-8", "replace") if body else ""),
                        remediation="Return the Elasticsearch root JSON document on GET /",
                        fidelity="high" if (body or status) else "medium",
                    )
                )
            else:
                out.append(
                    skipped_indicator(
                        *spec,
                        "not an Elasticsearch HTTP speaker",
                        protocol="elasticsearch",
                        error=err,
                    )
                )
        return out

    if root is None:
        # `_is_es_root` already implies a dict; keep an explicit guard for type narrowing.
        return skip_suite(
            _ES_SKIP,
            "not an Elasticsearch HTTP speaker",
            protocol="elasticsearch",
            error=err,
        )

    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        safe_out: list[Indicator] = []
        for spec in _ES_SKIP:
            if spec[0] == "elasticsearch.root_framing":
                safe_out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=False,
                        protocol="elasticsearch",
                        detail=framing_detail,
                        evidence=body[:400].decode("utf-8", "replace"),
                        remediation="Return the Elasticsearch root JSON document on GET /",
                    )
                )
            else:
                safe_out.append(skipped_indicator(*spec, reason, protocol="elasticsearch"))
        return safe_out

    # --- stock cluster / version / tagline / uuid ---
    stock_detail, stock_requires = _stock_cluster_assessment(root)
    stock_hit = bool(stock_detail)

    # --- Content-Type should advertise JSON for a JSON root ---
    ctype = headers.get("content-type", "")
    ctype_hit = bool(body.strip()) and not _content_type_is_json(headers)
    ctype_detail = (
        f"GET / returned JSON-shaped body with Content-Type={ctype!r}"
        if ctype_hit
        else f"Content-Type={ctype!r}"
    )

    # --- nonexistent index must 404 / index_not_found ---
    idx = f"hpa-audit-{secrets.token_hex(4)}"
    idx_status, _idx_hdrs, idx_body, idx_err = _http_exchange(host, port, "GET", f"/{idx}")
    idx_doc = _as_dict(_parse_json(idx_body))
    idx_skipped = bool(idx_err) and idx_status == 0 and not idx_body
    missing_ok_hit = False
    missing_detail = "missing-index handling not evaluated"
    if not idx_skipped:
        if _looks_like_index_missing(idx_status, idx_doc):
            missing_detail = f"compliant missing-index response (status={idx_status})"
        elif idx_status == 200 and (_is_es_root(idx_doc) or idx_doc is not None):
            missing_ok_hit = True
            missing_detail = (
                f"GET /{idx} returned status={idx_status} with a JSON body "
                "(Elasticsearch should return index_not_found_exception / 404)"
            )
        else:
            missing_detail = f"non-success reply for missing index (status={idx_status})"

    # --- unknown API path facade ---
    mystery = f"/_hpa_nonexistent_{secrets.token_hex(3)}"
    path_status, _path_hdrs, path_body, path_err = _http_exchange(host, port, "GET", mystery)
    path_doc = _as_dict(_parse_json(path_body))
    path_skipped = bool(path_err) and path_status == 0 and not path_body
    path_hit = False
    path_detail = "unknown-path handling not evaluated"
    if not path_skipped:
        if _looks_like_api_not_found(path_status, path_doc):
            path_detail = f"compliant unknown-path handling (status={path_status})"
        elif path_status == 200 and (_is_es_root(path_doc) or path_doc == root):
            path_hit = True
            path_detail = (
                f"GET {mystery} returned status=200 root-shaped JSON "
                "(unknown API routes should not echo the cluster root document)"
            )
        else:
            path_detail = f"unknown-path reply status={path_status}"

    # --- method stubs: DELETE / PUT / HEAD on / ---
    method_notes: list[str] = []
    method_hit = False
    method_skipped = True
    method_err = ""
    for verb in ("DELETE", "PUT", "HEAD"):
        m_status, _m_hdrs, m_body, m_err = _http_exchange(host, port, verb, "/")
        if m_err and m_status == 0 and not m_body:
            method_notes.append(f"{verb}: unanswered ({m_err})")
            method_err = method_err or m_err
            continue
        method_skipped = False
        m_doc = _as_dict(_parse_json(m_body))
        if verb == "HEAD":
            # HEAD must not carry an entity body with the root document.
            if m_body.strip() and (_is_es_root(m_doc) or m_body.strip() == body.strip()):
                method_hit = True
                method_notes.append(f"HEAD / returned a root-shaped body ({len(m_body)} bytes)")
            elif m_status in {200, 405, 401, 403} and not m_body.strip():
                method_notes.append(f"HEAD / status={m_status} (no body)")
            else:
                method_notes.append(f"HEAD / status={m_status} body_len={len(m_body)}")
            continue
        if m_status == 200 and _is_es_root(m_doc) and m_body.strip() == body.strip():
            method_hit = True
            method_notes.append(f"{verb} / returned the identical root document as GET /")
        elif m_status == 200 and _is_es_root(m_doc):
            method_hit = True
            method_notes.append(f"{verb} / returned an Elasticsearch root document (status=200)")
        else:
            method_notes.append(f"{verb} / status={m_status}")
    method_detail = (
        "; ".join(method_notes) if method_notes else "method handling not evaluated"
    )

    # --- /_cluster/health must be a health document, not the root ---
    ch_status, _ch_hdrs, ch_body, ch_err = _http_exchange(host, port, "GET", "/_cluster/health")
    ch_doc = _as_dict(_parse_json(ch_body))
    health_skipped = bool(ch_err) and ch_status == 0 and not ch_body
    health_hit = False
    health_detail = "cluster health not evaluated"
    if not health_skipped:
        if ch_status == 200 and ch_doc is not None and _is_cluster_health(ch_doc):
            health_detail = (
                f"cluster health ok status={ch_doc.get('status')!r} "
                f"nodes={ch_doc.get('number_of_nodes')}"
            )
        elif ch_status == 200 and (_is_es_root(ch_doc) or ch_doc == root):
            health_hit = True
            health_detail = (
                "GET /_cluster/health returned the cluster root document "
                "(expected health fields: status, number_of_nodes, …)"
            )
        elif _looks_like_api_not_found(ch_status, ch_doc):
            # Some locked-down proxies deny _cluster/* — inconclusive.
            health_skipped = True
            health_detail = f"cluster health denied/unavailable (status={ch_status})"
        else:
            health_hit = ch_status == 200
            health_detail = (
                f"GET /_cluster/health status={ch_status} is not a health document "
                f"(keys={sorted(ch_doc)[:8] if ch_doc else []})"
            )

    # --- /_cat/health?format=json should be a list/rows, not the root object ---
    cat_status, _cat_hdrs, cat_body, cat_err = _http_exchange(
        host, port, "GET", "/_cat/health?format=json"
    )
    cat_parsed = _parse_json(cat_body)
    cat_doc = _as_dict(cat_parsed)
    cat_skipped = bool(cat_err) and cat_status == 0 and not cat_body
    cat_hit = False
    cat_detail = "cat health not evaluated"
    if not cat_skipped:
        if cat_status == 200 and isinstance(cat_parsed, list):
            cat_detail = f"_cat/health returned JSON array (len={len(cat_parsed)})"
        elif cat_status == 200 and (_is_es_root(cat_doc) or cat_doc == root):
            cat_hit = True
            cat_detail = (
                "GET /_cat/health?format=json returned the cluster root document "
                "(expected a JSON array of cat rows)"
            )
        elif _looks_like_api_not_found(cat_status, cat_doc):
            cat_skipped = True
            cat_detail = f"_cat/health denied/unavailable (status={cat_status})"
        elif cat_status == 200 and cat_body and not cat_parsed:
            # Plain-text cat table is also valid without format=json quirks.
            cat_detail = "_cat/health returned non-JSON body (acceptable cat text)"
        else:
            cat_detail = f"_cat/health status={cat_status}"

    # --- Accept: application/yaml content negotiation ---
    # Real Elasticsearch (and OpenSearch) natively serves YAML/SMILE/CBOR via
    # Accept; JSON-only replies to a YAML request are hand-rolled HTTP skins.
    # Gated: JSON-normalizing front proxies in front of real clusters exist.
    y_status, y_hdrs, y_body, y_err = _http_exchange(
        host, port, "GET", "/", extra_headers={"Accept": "application/yaml"}
    )
    yaml_skipped = bool(y_err) and y_status == 0 and not y_body
    yaml_hit = False
    yaml_detail = "yaml negotiation not evaluated"
    if not yaml_skipped:
        yct = y_hdrs.get("content-type", "")
        looks_yaml = "yaml" in yct.lower() or y_body.lstrip().startswith(b"---")
        looks_json = "json" in yct.lower() or _parse_json(y_body) is not None
        if y_status == 200 and looks_yaml and not looks_json:
            yaml_detail = f"yaml honored (Content-Type={yct!r})"
        elif y_status == 200 and looks_json:
            yaml_hit = True
            yaml_detail = (
                f"Accept: application/yaml answered with JSON "
                f"(Content-Type={yct!r}, {len(y_body)}B body)"
            )
        elif y_status == 406:
            yaml_skipped = True
            yaml_detail = "406 to yaml negotiation (strict gatekeeper; not scored)"
        else:
            yaml_skipped = True
            yaml_detail = f"yaml negotiation status={y_status} (not scored)"

    # --- X-Elastic-Product vs claimed version (7.14+) ---
    product = headers.get("x-elastic-product", "")
    ver = _major_minor_patch(_version_number(root))
    product_hit = False
    product_skipped = False
    product_detail = "product header not evaluated"
    if ver is None:
        product_skipped = True
        product_detail = "could not parse version.number for product-header check"
    elif ver >= (7, 14, 0):
        if product.lower() != "elasticsearch":
            product_hit = True
            product_detail = (
                f"version {_version_number(root)} claims modern Elasticsearch but "
                f"X-Elastic-Product={product!r} (expected 'Elasticsearch')"
            )
        else:
            product_detail = f"X-Elastic-Product={product!r} matches version {_version_number(root)}"
    else:
        product_skipped = True
        product_detail = (
            f"version {_version_number(root)} predates X-Elastic-Product requirement "
            f"(header={product!r})"
        )

    # --- arbitrary_auth ---
    # Reached only when GET / already returned a root document. If that was the
    # anonymous response, Basic cannot be a bypass. The 401-then-unlock path
    # sets auth_from_challenge before framing succeeds.
    if auth_from_challenge:
        auth_hit = auth_ok == 2
        auth_detail = (
            "anonymous GET / challenged; two entropy-varied Basic credentials "
            "both returned 200 ES root"
            if auth_hit
            else ("; ".join(auth_notes) if auth_notes else "Basic challenge not bypassed")
        )
    else:
        auth_hit = False
        auth_detail = (
            "anonymous GET / already returned the ES root; Basic is not a credential gate"
        )

    # --- state_nonpersist: root vs /_nodes + /_cluster/health after reconnect ---
    pause_s = jittered_reconnect_pause()
    n_status, _n_hdrs, n_body, n_err = _http_exchange(host, port, "GET", "/_nodes")
    n_doc = _as_dict(_parse_json(n_body))
    h2_status, _h2_hdrs, h2_body, h2_err = _http_exchange(
        host, port, "GET", "/_cluster/health"
    )
    h2_doc = _as_dict(_parse_json(h2_body))
    state_skipped = False
    state_err = ""
    if (n_err and n_status == 0 and not n_body) and (
        h2_err and h2_status == 0 and not h2_body
    ):
        state_skipped = True
        state_err = n_err or h2_err
        state_hit = False
        state_detail = closed_reason(state_err)
    elif (
        _looks_like_api_not_found(n_status, n_doc)
        and _looks_like_api_not_found(h2_status, h2_doc)
        and n_status != 200
        and h2_status != 200
    ):
        state_skipped = True
        state_detail = (
            f"/_nodes and /_cluster/health denied/unavailable "
            f"(status={n_status}/{h2_status})"
        )
        state_hit = False
    else:
        state_hit, state_detail = _state_metadata_mismatch(
            root,
            nodes_doc=n_doc,
            nodes_status=n_status,
            health_doc=h2_doc,
            health_status=h2_status,
        )
    rtt_note = rtt_evidence(pause_s * 1000.0)
    if rtt_note and state_hit:
        state_detail = f"{state_detail}; pause_{rtt_note}"

    return [
        Indicator(
            id="elasticsearch.arbitrary_auth",
            title="Elasticsearch accepts two entropy-varied Basic credentials on GET /",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason=closed_reason(auth_err) if auth_skipped else "",
            error=auth_err if auth_skipped else "",
            protocol="elasticsearch",
            detail=auth_detail,
            evidence=f"{low_user},{high_user}" if auth_hit else "",
            remediation="Reject unknown Basic credentials instead of always returning the root document",
            fidelity="decisive" if auth_hit else "medium",
        ),
        Indicator(
            id="elasticsearch.state_nonpersist",
            title="Elasticsearch root metadata mismatches /_nodes or /_cluster/health",
            category="state_nonpersist",
            triggered=state_hit,
            skipped=state_skipped,
            skip_reason=state_detail if state_skipped else "",
            error=state_err,
            protocol="elasticsearch",
            detail=state_detail,
            evidence=(
                (n_body[:200] + h2_body[:200]).decode("utf-8", "replace")
                if (n_body or h2_body)
                else ""
            ),
            remediation="Keep cluster_uuid/version coherent across /, /_nodes, and /_cluster/health",
            fidelity="high" if state_hit else "medium",
        ),
        Indicator(
            id="elasticsearch.root_framing",
            title="Elasticsearch root response is not a valid cluster document",
            category="static_signature",
            triggered=False,
            protocol="elasticsearch",
            detail=framing_detail,
            evidence=body[:500].decode("utf-8", "replace"),
            remediation="Return the Elasticsearch root JSON document on GET /",
        ),
        Indicator(
            id="elasticsearch.stock_cluster",
            title="Elasticsearch cluster metadata matches a stock honeypot lure",
            category="static_signature",
            triggered=stock_hit,
            protocol="elasticsearch",
            detail=stock_detail or "cluster metadata does not match stock lure tokens",
            evidence=body[:500].decode("utf-8", "replace"),
            remediation="Use unique cluster_name / node name / version / cluster_uuid",
            requires_corroboration=stock_requires,
            fidelity="medium",
        ),
        Indicator(
            id="elasticsearch.missing_index_ok",
            title="Elasticsearch returns success for a nonexistent index",
            category="static_signature",
            triggered=missing_ok_hit,
            skipped=idx_skipped,
            skip_reason=idx_err if idx_skipped else "",
            error=idx_err,
            protocol="elasticsearch",
            detail=missing_detail,
            evidence=(idx_body[:400].decode("utf-8", "replace") if idx_body else ""),
            remediation="Return HTTP 404 with index_not_found_exception for unknown indices",
            fidelity="high" if missing_ok_hit else "medium",
        ),
        Indicator(
            id="elasticsearch.path_facade",
            title="Elasticsearch answers unknown API paths with a root-shaped 200",
            category="static_signature",
            triggered=path_hit,
            skipped=path_skipped,
            skip_reason=path_err if path_skipped else "",
            error=path_err,
            protocol="elasticsearch",
            detail=path_detail,
            evidence=(path_body[:400].decode("utf-8", "replace") if path_body else ""),
            remediation="Return 400/404 errors for unknown HTTP API routes",
            fidelity="high" if path_hit else "medium",
        ),
        Indicator(
            id="elasticsearch.method_stub",
            title="Elasticsearch ignores HTTP method on / (DELETE/PUT/HEAD stub)",
            category="static_signature",
            triggered=method_hit,
            skipped=method_skipped,
            skip_reason=method_err if method_skipped else "",
            error=method_err,
            protocol="elasticsearch",
            detail=method_detail,
            evidence=method_detail[:400],
            remediation="Do not serve the cluster root document for DELETE/PUT/HEAD on /",
            fidelity="high" if method_hit else "medium",
        ),
        Indicator(
            id="elasticsearch.cluster_health_stub",
            title="Elasticsearch /_cluster/health does not return a health document",
            category="static_signature",
            triggered=health_hit,
            skipped=health_skipped,
            skip_reason=health_detail if health_skipped else "",
            error=ch_err,
            protocol="elasticsearch",
            detail=health_detail,
            evidence=(ch_body[:400].decode("utf-8", "replace") if ch_body else ""),
            remediation="Implement GET /_cluster/health with status and node counts",
            fidelity="high" if health_hit else "medium",
        ),
        Indicator(
            id="elasticsearch.cat_stub",
            title="Elasticsearch /_cat/health returns a root-shaped document",
            category="static_signature",
            triggered=cat_hit,
            skipped=cat_skipped,
            skip_reason=cat_detail if cat_skipped else "",
            error=cat_err,
            protocol="elasticsearch",
            detail=cat_detail,
            evidence=(cat_body[:400].decode("utf-8", "replace") if cat_body else ""),
            remediation="Implement _cat/health (JSON array with format=json), not a root echo",
            fidelity="high" if cat_hit else "medium",
        ),
        Indicator(
            id="elasticsearch.content_type",
            title="Elasticsearch JSON body is served with a non-JSON Content-Type",
            category="static_signature",
            triggered=ctype_hit,
            protocol="elasticsearch",
            detail=ctype_detail,
            evidence=f"Content-Type={ctype}",
            remediation="Serve application/json (or ES vendor JSON) for API responses",
            fidelity="medium",
        ),
        Indicator(
            id="elasticsearch.content_negotiation",
            title="Elasticsearch ignores an Accept: application/yaml request",
            category="static_signature",
            triggered=yaml_hit,
            skipped=yaml_skipped,
            skip_reason=yaml_detail if yaml_skipped else "",
            error=y_err if yaml_skipped else "",
            protocol="elasticsearch",
            detail=yaml_detail,
            evidence=y_body[:200].decode("utf-8", "replace") if y_body else "",
            requires_corroboration=True if yaml_hit else False,
            fidelity="high",
            remediation=(
                "Honor Accept: application/yaml (and SMILE/CBOR) content "
                "negotiation on API endpoints"
            ),
        ),
        Indicator(
            id="elasticsearch.product_header",
            title="Elasticsearch product header is missing or inconsistent with version",
            category="static_signature",
            triggered=product_hit,
            skipped=product_skipped,
            skip_reason=product_detail if product_skipped else "",
            protocol="elasticsearch",
            detail=product_detail,
            evidence=f"X-Elastic-Product={product}; version={_version_number(root)}",
            remediation="Send X-Elastic-Product: Elasticsearch on HTTP responses (7.14+)",
            fidelity="medium",
        ),
    ]


__all__ = ["probe_elasticsearch"]
