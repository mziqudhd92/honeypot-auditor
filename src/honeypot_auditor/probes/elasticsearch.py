"""Elasticsearch HTTP API fingerprint engine.

Protocol non-compliance strategies (read-only — never index/delete/bulk write):
  · static_signature — stock cluster/version/tagline lures; missing-index returns 200;
    unknown API path returns root-shaped 200; DELETE on ``/`` echoes GET root;
    X-Elastic-Product header inconsistency vs claimed version
  · framing — GET ``/`` is not a parseable Elasticsearch root document

Ports 9200 / lab 19200 (HTTP). Transport port 9300 is out of scope.

See docs/ELASTICSEARCH.md and Elasticsearch HTTP API docs (root, index APIs, errors).
"""

from __future__ import annotations

import json
import re
import secrets
from typing import Any

from honeypot_auditor.config import effective_user_agent
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import is_safe_mode, skip_suite
from honeypot_auditor.settings import settings

_ES_SKIP = (
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
        "Elasticsearch DELETE/PUT on / returns the same root document as GET",
        "static_signature",
    ),
    (
        "elasticsearch.product_header",
        "Elasticsearch product header is missing or inconsistent with version",
        "static_signature",
    ),
)

_STOCK_CLUSTER_NAMES = frozenset(
    {
        "elasticsearch",
        "docker-cluster",
        "elastichoney",
        "honeypot",
        "elastic-honeypot",
        "es-honeypot",
        "test-cluster",
        "opensearch",  # often mis-labeled lure; corroboration-gated below
    }
)

_STOCK_TAGLINES = (
    "the open search project",  # OpenSearch lure mislabeled as ES
    "elastichoney",
    "fake elasticsearch",
)

_STOCK_VERSIONS = frozenset(
    {
        "1.4.1",
        "1.4.2",
        "1.4.4",
        "1.7.6",
        "2.3.0",
        "2.4.6",
        "5.0.0",
        "5.6.16",
        "6.8.0",
        "7.0.0",
        "7.10.0",
        "7.10.2",
        "7.17.0",
        "8.0.0",
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
    try:
        head, _, rest = raw.partition(b"\r\n\r\n")
    except Exception:
        return 0, {}, raw, "malformed HTTP framing"
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


def _parse_json(body: bytes) -> dict[str, Any] | None:
    if not body:
        return None
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _is_es_root(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    version = doc.get("version")
    has_version = isinstance(version, dict) and "number" in version
    has_tagline = isinstance(doc.get("tagline"), str)
    has_cluster = isinstance(doc.get("cluster_name"), str) or isinstance(doc.get("name"), str)
    return bool(has_version and (has_tagline or has_cluster))


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


def _stock_cluster_hit(doc: dict[str, Any]) -> str | None:
    cluster = str(doc.get("cluster_name") or "").strip().lower()
    name = str(doc.get("name") or "").strip().lower()
    tagline = str(doc.get("tagline") or "").strip().lower()
    version = _version_number(doc).strip()
    hits: list[str] = []
    if cluster in _STOCK_CLUSTER_NAMES:
        hits.append(f"cluster_name={cluster}")
    if name in {"elastichoney", "honeypot", "es-honeypot", "node-1", "elasticsearch"}:
        hits.append(f"name={name}")
    for tell in _STOCK_TAGLINES:
        if tell in tagline:
            hits.append(f"tagline~{tell}")
            break
    if version in _STOCK_VERSIONS:
        hits.append(f"version={version}")
    return "; ".join(hits) if hits else None


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


def probe_elasticsearch(host: str, port: int) -> list[Indicator]:
    status, headers, body, err = _http_exchange(host, port, "GET", "/")
    if err and not body and status == 0:
        return skip_suite(_ES_SKIP, err, protocol="elasticsearch", error=err)

    root = _parse_json(body)
    root_ok = _is_es_root(root)
    framing_hit = not root_ok
    if framing_hit:
        framing_detail = (
            "GET / did not return an Elasticsearch root document "
            f"(status={status}, json_keys={sorted(root)[:8] if root else []})"
        )
    else:
        assert root is not None
        framing_detail = (
            f"root ok cluster_name={root.get('cluster_name')!r} "
            f"version={_version_number(root)!r}"
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

    assert root is not None  # for type-checkers; root_ok guarantees shape

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

    # --- stock cluster / version / tagline ---
    stock_detail = _stock_cluster_hit(root)
    stock_hit = bool(stock_detail)
    cluster_l = str(root.get("cluster_name") or "").strip().lower()
    stock_requires = cluster_l in {"elasticsearch", "opensearch", "docker-cluster", "test-cluster"}

    # --- nonexistent index must 404 / index_not_found ---
    idx = f"hpa-audit-{secrets.token_hex(4)}"
    idx_status, _idx_hdrs, idx_body, idx_err = _http_exchange(host, port, "GET", f"/{idx}")
    idx_doc = _parse_json(idx_body)
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
    path_doc = _parse_json(path_body)
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

    # --- method stub: DELETE / should not return the same root 200 as GET / ---
    del_status, _del_hdrs, del_body, del_err = _http_exchange(host, port, "DELETE", "/")
    del_doc = _parse_json(del_body)
    method_skipped = bool(del_err) and del_status == 0 and not del_body
    method_hit = False
    method_detail = "method handling not evaluated"
    if not method_skipped:
        if del_status == 200 and _is_es_root(del_doc) and del_body.strip() == body.strip():
            method_hit = True
            method_detail = (
                "DELETE / returned the identical root document as GET / "
                "(method stub / ignore-method lure)"
            )
        elif del_status == 200 and _is_es_root(del_doc):
            method_hit = True
            method_detail = "DELETE / returned an Elasticsearch root document (status=200)"
        else:
            method_detail = f"DELETE / status={del_status} (not an echoed root document)"

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
        # Older versions often omit the header — inconclusive, not a tell.
        product_skipped = True
        product_detail = (
            f"version {_version_number(root)} predates X-Elastic-Product requirement "
            f"(header={product!r})"
        )

    return [
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
            remediation="Use unique cluster_name / node name / version for real deployments",
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
            title="Elasticsearch DELETE/PUT on / returns the same root document as GET",
            category="static_signature",
            triggered=method_hit,
            skipped=method_skipped,
            skip_reason=del_err if method_skipped else "",
            error=del_err,
            protocol="elasticsearch",
            detail=method_detail,
            evidence=(del_body[:400].decode("utf-8", "replace") if del_body else ""),
            remediation="Do not serve the cluster root document for DELETE/PUT on /",
            fidelity="high" if method_hit else "medium",
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
