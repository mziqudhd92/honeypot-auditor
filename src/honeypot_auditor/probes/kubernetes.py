"""Kubernetes API server fingerprint engine.

Protocol non-compliance strategies (read-only — never create/exec/proxy/delete
cluster objects):
  · static_signature — /livez|/healthz not ok; /version not parseable;
    /api not APIVersions-shaped; unknown path returns version-shaped 200;
    DELETE /version method stub; stock gitVersion/platform lures;
    unauthenticated /api/v1 returns pods/secrets-shaped lists

Ports 6443 / lab 16443. TLS is preferred on those ports (IMAPS-style).

See docs/KUBERNETES.md and Kubernetes API health/discovery docs.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from honeypot_auditor.config import effective_user_agent
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason
from honeypot_auditor.probes.common import is_safe_mode, skip_suite
from honeypot_auditor.proxy_transport import create_connection, create_tls_connection
from honeypot_auditor.settings import settings

_K8S_SKIP = (
    (
        "kubernetes.health_framing",
        "Kubernetes livez/healthz response is not ok",
        "static_signature",
    ),
    (
        "kubernetes.version_framing",
        "Kubernetes /version response is not a parseable version document",
        "static_signature",
    ),
    (
        "kubernetes.api_framing",
        "Kubernetes /api is not APIVersions-shaped",
        "static_signature",
    ),
    (
        "kubernetes.path_facade",
        "Kubernetes answers unknown API paths with a version-shaped 200",
        "static_signature",
    ),
    (
        "kubernetes.method_stub",
        "Kubernetes ignores DELETE on /version",
        "static_signature",
    ),
    (
        "kubernetes.stock_version",
        "Kubernetes version metadata matches a stock honeypot lure",
        "static_signature",
    ),
    (
        "kubernetes.unauthenticated_ok",
        "Kubernetes returns secrets/pods-shaped data without authentication",
        "static_signature",
    ),
)

_TLS_PORTS = frozenset({6443, 16443})

# Decisive lure tokens — rare outside honeypots; score without corroboration.
_STOCK_GITVERSION_DECISIVE = (
    "kube-honeypot",
    "honey-kube",
    "k8s-honeypot",
    "kubernetes-honeypot",
    "honeypot",
    "honeykube",
    "k8spot",
)
_STOCK_PLATFORM_DECISIVE = (
    "honeypot",
    "honey-kube",
    "fake",
)

# Frozen / demo release strings common on lure faces — corroboration-gated alone.
_STOCK_GITVERSIONS_GENERIC = frozenset(
    {
        "v1.16.0",
        "v1.17.0",
        "v1.18.0",
        "v1.18.3",
        "v1.19.0",
        "v0.0.0",
        "v1.0.0",
    }
)

_MAX_RECV = 65535


def _open_socket(host: str, port: int):
    timeout = settings.timeout_seconds
    if int(port) in _TLS_PORTS:
        return create_tls_connection(host, port, timeout)
    return create_connection(host, port, timeout)


def _recv_all(sock, timeout: float, max_bytes: int = _MAX_RECV) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    total = 0
    while total < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - total))
        except (OSError, TimeoutError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        data = b"".join(chunks)
        if b"\r\n\r\n" in data:
            head, _, rest = data.partition(b"\r\n\r\n")
            cl = 0
            for line in head.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    try:
                        cl = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        cl = 0
                    break
            if cl and len(rest) >= cl:
                break
            if not cl and len(rest) > 0 and len(chunk) < 4096:
                break
    return b"".join(chunks)


def _http_exchange(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    extra_headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> tuple[int, dict[str, str], bytes, str]:
    """Minimal HTTP/1.1 exchange (TLS on 6443/16443). Returns (status, headers, body, error)."""
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
    try:
        with _open_socket(host, port) as sock:
            sock.sendall(request)
            raw = _recv_all(sock, settings.timeout_seconds)
    except (OSError, ImportError) as exc:
        return 0, {}, b"", closed_reason(str(exc))
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


def _is_health_ok(status: int, body: bytes) -> bool:
    if status != 200:
        return False
    text = body.decode("utf-8", "replace").strip().lower()
    return text == "ok"


def _is_version_doc(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    return (
        isinstance(doc.get("major"), str)
        and isinstance(doc.get("minor"), str)
        and isinstance(doc.get("gitVersion"), str)
        and bool(doc.get("gitVersion"))
    )


def _is_api_versions(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    kind = str(doc.get("kind") or "")
    versions = doc.get("versions")
    return kind == "APIVersions" and isinstance(versions, list)


def _is_api_resource_list(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    kind = str(doc.get("kind") or "")
    return kind == "APIResourceList" and isinstance(doc.get("resources"), list)


def _looks_like_object_list(doc: dict[str, Any] | None) -> bool:
    """True for PodList/SecretList or items that look like pods/secrets."""
    if not doc:
        return False
    kind = str(doc.get("kind") or "")
    if kind in {"PodList", "SecretList", "List"}:
        return True
    items = doc.get("items")
    if not isinstance(items, list) or not items:
        return False
    for item in items[:5]:
        if not isinstance(item, dict):
            continue
        if kind == "Secret" or str(item.get("kind") or "") == "Secret":
            return True
        if "data" in item and ("type" in item or "metadata" in item):
            return True
        status = item.get("status")
        if isinstance(status, dict) and ("phase" in status or "containerStatuses" in status):
            return True
        spec = item.get("spec")
        if isinstance(spec, dict) and "containers" in spec:
            return True
    return False


def _looks_like_api_not_found(status: int, doc: dict[str, Any] | None) -> bool:
    if status in {400, 404, 405, 401, 403}:
        return True
    if not doc:
        return status >= 400
    kind = str(doc.get("kind") or "")
    if kind == "Status":
        code = doc.get("code")
        if code in {400, 404, 405, 401, 403} or str(doc.get("status") or "").lower() == "failure":
            return True
    return False


def _stock_version_assessment(doc: dict[str, Any]) -> tuple[str | None, bool]:
    """Return ``(detail, requires_corroboration)`` for stock lure version metadata."""
    git_version = str(doc.get("gitVersion") or "").strip()
    platform = str(doc.get("platform") or "").strip()
    git_low = git_version.lower()
    plat_low = platform.lower()
    hits: list[str] = []
    decisive = False
    for token in _STOCK_GITVERSION_DECISIVE:
        if token in git_low:
            hits.append(f"gitVersion~{token}")
            decisive = True
            break
    if not any(h.startswith("gitVersion") for h in hits) and git_version in _STOCK_GITVERSIONS_GENERIC:
        hits.append(f"gitVersion={git_version}")
    for token in _STOCK_PLATFORM_DECISIVE:
        if token in plat_low:
            hits.append(f"platform~{token}")
            decisive = True
            break
    if not hits:
        return None, False
    requires = not decisive
    return "; ".join(hits), requires


def _probe_health(host: str, port: int) -> tuple[int, bytes, str, str]:
    """Try /livez then /healthz. Returns (status, body, path_used, error)."""
    for path in ("/livez", "/healthz"):
        status, _hdrs, body, err = _http_exchange(host, port, "GET", path)
        if err and status == 0 and not body:
            if path == "/livez":
                continue
            return 0, b"", path, err
        return status, body, path, err
    return 0, b"", "/healthz", "empty HTTP response"


def probe_kubernetes(host: str, port: int) -> list[Indicator]:
    health_status, health_body, health_path, health_err = _probe_health(host, port)
    ver_status, _ver_hdrs, ver_body, ver_err = _http_exchange(host, port, "GET", "/version")

    if (
        health_err
        and health_status == 0
        and not health_body
        and ver_err
        and ver_status == 0
        and not ver_body
    ):
        return skip_suite(
            _K8S_SKIP,
            health_err or ver_err,
            protocol="kubernetes",
            error=health_err or ver_err,
        )

    health_ok = _is_health_ok(health_status, health_body)
    version_doc = _as_dict(_parse_json(ver_body))
    version_ok = _is_version_doc(version_doc)

    health_framing_hit = not health_ok and bool(health_body or health_status > 0)
    health_skipped = bool(health_err) and health_status == 0 and not health_body
    if health_skipped:
        health_framing_hit = False

    version_framing_hit = not version_ok and bool(ver_body or ver_status > 0)
    version_skipped = bool(ver_err) and ver_status == 0 and not ver_body
    if version_skipped:
        version_framing_hit = False

    if health_ok:
        health_detail = f"{health_path} ok"
    elif health_skipped:
        health_detail = health_err or "health endpoints unreachable"
    else:
        health_detail = (
            f"{health_path} not ok (status={health_status}, "
            f"body={health_body[:80]!r})"
        )

    if version_ok and version_doc is not None:
        version_detail = (
            f"version ok gitVersion={version_doc.get('gitVersion')!r} "
            f"platform={version_doc.get('platform')!r}"
        )
    elif version_skipped:
        version_detail = ver_err or "/version unreachable"
    else:
        version_detail = (
            "GET /version did not return major/minor/gitVersion "
            f"(status={ver_status}, json_keys={sorted(version_doc)[:8] if version_doc else []})"
        )

    speaker = health_ok or version_ok
    if not speaker:
        out: list[Indicator] = []
        for spec in _K8S_SKIP:
            if spec[0] == "kubernetes.health_framing":
                out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=health_framing_hit,
                        skipped=health_skipped and not health_framing_hit,
                        skip_reason=health_err if health_skipped else "",
                        protocol="kubernetes",
                        detail=health_detail if (health_body or health_status) else health_err,
                        evidence=(health_body[:400].decode("utf-8", "replace") if health_body else ""),
                        remediation="Return HTTP 200 with body 'ok' on /livez and /healthz",
                        fidelity="high" if health_framing_hit else "medium",
                    )
                )
            elif spec[0] == "kubernetes.version_framing":
                out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=version_framing_hit,
                        skipped=version_skipped and not version_framing_hit,
                        skip_reason=ver_err if version_skipped else "",
                        protocol="kubernetes",
                        detail=version_detail if (ver_body or ver_status) else ver_err,
                        evidence=(ver_body[:400].decode("utf-8", "replace") if ver_body else ""),
                        remediation="Return a version JSON document with major, minor, gitVersion",
                        fidelity="high" if version_framing_hit else "medium",
                    )
                )
            else:
                out.append(
                    skipped_indicator(
                        *spec,
                        "not a Kubernetes API speaker",
                        protocol="kubernetes",
                        error=health_err or ver_err,
                    )
                )
        return out

    if is_safe_mode():
        reason = "safe-mode: health/version framing only"
        safe_out: list[Indicator] = []
        for spec in _K8S_SKIP:
            if spec[0] == "kubernetes.health_framing":
                safe_out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=health_framing_hit,
                        skipped=health_skipped,
                        skip_reason=health_err if health_skipped else "",
                        protocol="kubernetes",
                        detail=health_detail,
                        evidence=(health_body[:400].decode("utf-8", "replace") if health_body else ""),
                        remediation="Return HTTP 200 with body 'ok' on /livez and /healthz",
                    )
                )
            elif spec[0] == "kubernetes.version_framing":
                safe_out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=version_framing_hit,
                        skipped=version_skipped,
                        skip_reason=ver_err if version_skipped else "",
                        protocol="kubernetes",
                        detail=version_detail,
                        evidence=(ver_body[:400].decode("utf-8", "replace") if ver_body else ""),
                        remediation="Return a version JSON document with major, minor, gitVersion",
                    )
                )
            else:
                safe_out.append(skipped_indicator(*spec, reason, protocol="kubernetes"))
        return safe_out

    stock_detail: str | None = None
    stock_requires = False
    if version_doc is not None and version_ok:
        stock_detail, stock_requires = _stock_version_assessment(version_doc)
    stock_hit = bool(stock_detail)

    api_status, _api_hdrs, api_body, api_err = _http_exchange(host, port, "GET", "/api")
    api_doc = _as_dict(_parse_json(api_body))
    api_skipped = bool(api_err) and api_status == 0 and not api_body
    api_hit = False
    api_detail = "API discovery not evaluated"
    if not api_skipped:
        if api_status == 200 and _is_api_versions(api_doc):
            api_detail = f"/api ok versions={api_doc.get('versions')!r}"
        elif _looks_like_api_not_found(api_status, api_doc) and api_status in {401, 403}:
            api_skipped = True
            api_detail = f"/api denied (status={api_status})"
        else:
            api_hit = True
            api_detail = (
                f"GET /api status={api_status} is not APIVersions-shaped "
                f"(keys={sorted(api_doc)[:8] if api_doc else []})"
            )

    mystery = f"/_hpa_nonexistent_{secrets.token_hex(3)}"
    path_status, _path_hdrs, path_body, path_err = _http_exchange(host, port, "GET", mystery)
    path_doc = _as_dict(_parse_json(path_body))
    path_skipped = bool(path_err) and path_status == 0 and not path_body
    path_hit = False
    path_detail = "unknown-path handling not evaluated"
    if not path_skipped:
        if _looks_like_api_not_found(path_status, path_doc):
            path_detail = f"compliant unknown-path handling (status={path_status})"
        elif path_status == 200 and (_is_version_doc(path_doc) or path_doc == version_doc):
            path_hit = True
            path_detail = (
                f"GET {mystery} returned status=200 version-shaped JSON "
                "(unknown API routes should not echo /version)"
            )
        else:
            path_detail = f"unknown-path reply status={path_status}"

    m_status, _m_hdrs, m_body, m_err = _http_exchange(host, port, "DELETE", "/version")
    method_skipped = bool(m_err) and m_status == 0 and not m_body
    method_hit = False
    method_detail = "method handling not evaluated"
    if not method_skipped:
        m_doc = _as_dict(_parse_json(m_body))
        if m_status == 200 and _is_version_doc(m_doc):
            method_hit = True
            method_detail = (
                "DELETE /version returned a version document (status=200); "
                "apiserver should reject or Status-fail mutating /version"
            )
        else:
            method_detail = f"DELETE /version status={m_status}"

    v1_status, _v1_hdrs, v1_body, v1_err = _http_exchange(host, port, "GET", "/api/v1")
    v1_doc = _as_dict(_parse_json(v1_body))
    unauth_skipped = bool(v1_err) and v1_status == 0 and not v1_body
    unauth_hit = False
    unauth_detail = "/api/v1 not evaluated"
    if not unauth_skipped:
        if v1_status in {401, 403}:
            unauth_detail = f"/api/v1 correctly denied (status={v1_status})"
        elif v1_status == 200 and _is_api_resource_list(v1_doc):
            unauth_detail = "/api/v1 returned APIResourceList (expected discovery shape)"
        elif v1_status == 200 and _looks_like_object_list(v1_doc):
            unauth_hit = True
            unauth_detail = (
                f"GET /api/v1 returned status=200 kind={v1_doc.get('kind')!r} "
                "object list without auth (expected APIResourceList or 401/403)"
            )
        elif v1_status == 200 and _is_version_doc(v1_doc):
            unauth_hit = True
            unauth_detail = (
                "GET /api/v1 returned a version-shaped document "
                "(expected APIResourceList or 401/403)"
            )
        else:
            unauth_detail = (
                f"/api/v1 status={v1_status} "
                f"keys={sorted(v1_doc)[:8] if v1_doc else []}"
            )

    return [
        Indicator(
            id="kubernetes.health_framing",
            title="Kubernetes livez/healthz response is not ok",
            category="static_signature",
            triggered=health_framing_hit,
            skipped=health_skipped,
            skip_reason=health_err if health_skipped else "",
            error=health_err,
            protocol="kubernetes",
            detail=health_detail,
            evidence=(health_body[:500].decode("utf-8", "replace") if health_body else ""),
            remediation="Return HTTP 200 with body 'ok' on /livez and /healthz",
            fidelity="high" if health_framing_hit else "medium",
        ),
        Indicator(
            id="kubernetes.version_framing",
            title="Kubernetes /version response is not a parseable version document",
            category="static_signature",
            triggered=version_framing_hit,
            skipped=version_skipped,
            skip_reason=ver_err if version_skipped else "",
            error=ver_err,
            protocol="kubernetes",
            detail=version_detail,
            evidence=(ver_body[:500].decode("utf-8", "replace") if ver_body else ""),
            remediation="Return a version JSON document with major, minor, gitVersion",
            fidelity="high" if version_framing_hit else "medium",
        ),
        Indicator(
            id="kubernetes.api_framing",
            title="Kubernetes /api is not APIVersions-shaped",
            category="static_signature",
            triggered=api_hit,
            skipped=api_skipped,
            skip_reason=api_detail if api_skipped else "",
            error=api_err,
            protocol="kubernetes",
            detail=api_detail,
            evidence=(api_body[:400].decode("utf-8", "replace") if api_body else ""),
            remediation="Return kind=APIVersions with a versions list on GET /api",
            fidelity="high" if api_hit else "medium",
        ),
        Indicator(
            id="kubernetes.path_facade",
            title="Kubernetes answers unknown API paths with a version-shaped 200",
            category="static_signature",
            triggered=path_hit,
            skipped=path_skipped,
            skip_reason=path_err if path_skipped else "",
            error=path_err,
            protocol="kubernetes",
            detail=path_detail,
            evidence=(path_body[:400].decode("utf-8", "replace") if path_body else ""),
            remediation="Return 404 Status for unknown HTTP API routes",
            fidelity="high" if path_hit else "medium",
        ),
        Indicator(
            id="kubernetes.method_stub",
            title="Kubernetes ignores DELETE on /version",
            category="static_signature",
            triggered=method_hit,
            skipped=method_skipped,
            skip_reason=m_err if method_skipped else "",
            error=m_err,
            protocol="kubernetes",
            detail=method_detail,
            evidence=(m_body[:400].decode("utf-8", "replace") if m_body else ""),
            remediation="Do not serve the version document for DELETE /version",
            fidelity="high" if method_hit else "medium",
        ),
        Indicator(
            id="kubernetes.stock_version",
            title="Kubernetes version metadata matches a stock honeypot lure",
            category="static_signature",
            triggered=stock_hit,
            protocol="kubernetes",
            detail=stock_detail or "version metadata does not match stock lure tokens",
            evidence=(ver_body[:500].decode("utf-8", "replace") if ver_body else ""),
            remediation="Use unique gitVersion / platform strings, not honeypot lure tokens",
            requires_corroboration=stock_requires,
            fidelity="medium",
        ),
        Indicator(
            id="kubernetes.unauthenticated_ok",
            title="Kubernetes returns secrets/pods-shaped data without authentication",
            category="static_signature",
            triggered=unauth_hit,
            skipped=unauth_skipped,
            skip_reason=v1_err if unauth_skipped else "",
            error=v1_err,
            protocol="kubernetes",
            detail=unauth_detail,
            evidence=(v1_body[:400].decode("utf-8", "replace") if v1_body else ""),
            remediation=(
                "Serve APIResourceList (or 401/403) on GET /api/v1; "
                "never dump pods/secrets without auth"
            ),
            fidelity="high" if unauth_hit else "medium",
        ),
    ]


__all__ = ["probe_kubernetes"]
