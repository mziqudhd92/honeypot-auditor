"""HTTP fingerprint engine.

Strategies: static signature (empty PUT 405, GET / → index.html login skin,
407 Via localhost, framework 404+session cookie, silent TCP accept/tarpit).
When GET / returns an empty 404, up to five common admin paths are probed once
each for a stock login skin (phpMyAdmin /admin /login). Arbitrary auth and state
non-persistence are not on the basic path. Server banner strings are
operator-configurable; login skin and empty 405 are the source-hardcoded tells.
"""

from __future__ import annotations

import logging
import warnings

from honeypot_auditor.config import (
    HTTP_DYNAMIC_HEADERS,
    HTTP_HEADER_LURE_ORDERS,
    HTTP_SERVER_TELLS,
    WILDCARD_HOST,
    effective_user_agent,
    match_http_proxy_lure,
)
from honeypot_auditor.httpwire import parse_header_map as _parse_headers
from honeypot_auditor.httpwire import parse_header_names
from honeypot_auditor.models import Indicator, optional_import
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import is_safe_mode, skip_suite
from honeypot_auditor.proxy_detect import detect_proxy_from_headers
from honeypot_auditor.proxy_transport import configure_requests_proxy, create_connection
from honeypot_auditor.settings import settings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

_log = logging.getLogger(__name__)

_HTTP_SKIP = (
    ("http.malformed_200", "HTTP static 200 OK on malformed POST", "static_signature"),
    ("http.dynamic_headers", "HTTP missing dynamic Date header", "static_signature"),
    ("http.method_stub", "HTTP PUT/DELETE returns empty 405", "static_signature"),
    ("http.login_skin", "HTTP / redirects to a stock login form", "static_signature"),
    ("http.proxy_lure", "HTTP 407 looks like a stock proxy lure", "static_signature"),
    ("http.header_order", "HTTP response header order matches lure profile", "static_signature"),
    ("http.wildcard_host", "HTTP accepts invalid Host header", "proto_conformance"),
    ("http.framework_404_session", "HTTP 404 serves framework session cookie", "static_signature"),
    ("http.silent_accept", "HTTP TCP accepts then returns no response", "static_signature"),
)

# Follow-up paths when GET / is a bare 404 (common low-interaction HTTP faces).
_ADMIN_LOGIN_PATHS = ("/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/admin/", "/login")


def _dynamic_header_detail(
    server_val: str, missing_dynamic: bool, header_map: dict[str, str]
) -> str:
    date_note = "missing Date" if missing_dynamic else "Date present"
    return (f"server={server_val or '?'}; {date_note}; headers: " + ", ".join(sorted(header_map)))[
        :240
    ]


def _looks_like_admin_login_skin(status: int, body: bytes) -> bool:
    if status not in (200, 301, 302):
        return False
    low = body[:2048].lower()
    return (
        b"phpmyadmin" in low
        or (b'name="username"' in low and b'name="password"' in low)
        or b'name="pma_username"' in low
    )


def _probe_admin_login_skin(requests_mod, base: str) -> bool:
    """One GET per admin path; stop on first stock login skin. Failures are soft."""
    for path in _ADMIN_LOGIN_PATHS:
        try:
            admin = requests_mod.get(
                f"{base}{path}",
                timeout=settings.timeout_seconds,
                allow_redirects=False,
                headers={"User-Agent": effective_user_agent()},
                verify=False,
                proxies=configure_requests_proxy() or None,
            )
        except Exception as exc:
            _log.debug("admin path probe %s failed: %s", path, exc)
            continue
        if _looks_like_admin_login_skin(int(admin.status_code), admin.content or b""):
            return True
    return False


_TLS_PORTS = frozenset({443, 8443})


def _scheme(port: int) -> str:
    return "https" if port in _TLS_PORTS else "http"


def _tcp_accepts(host: str, port: int) -> bool:
    try:
        with create_connection(host, port, settings.timeout_seconds):
            return True
    except (OSError, ImportError, TimeoutError):
        return False


def _silent_accept_suite(detail: str) -> list[Indicator]:
    """TCP connected but application never returned an HTTP response (tarpit / silent face)."""
    out: list[Indicator] = []
    for i, title, cat in _HTTP_SKIP:
        if i == "http.silent_accept":
            out.append(
                Indicator(
                    id=i,
                    title=title,
                    category=cat,
                    triggered=True,
                    protocol="http",
                    detail=detail[:240],
                    remediation="Speak HTTP or refuse the TCP connection; silent accepts look like tarpits",
                )
            )
        else:
            out.append(
                Indicator(
                    id=i,
                    title=title,
                    category=cat,
                    triggered=False,
                    protocol="http",
                    detail="no HTTP response (silent TCP accept)",
                )
            )
    return out


def probe_http(host: str, port: int) -> list[Indicator]:
    if is_safe_mode():
        return _probe_http_safe(host, port)
    requests = optional_import("requests")
    tls = port in _TLS_PORTS
    malformed = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host.encode("ascii", "replace") + b"\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 8\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"\x00{{{}}"
    )
    raw, err = (b"", "") if tls else tcp_transact(host, port, malformed, recv_first=False)
    if err and not raw and not tls:
        return skip_suite(_HTTP_SKIP, closed_reason(err), protocol="http", error=err)
    if not tls and not err and not raw:
        return _silent_accept_suite("TCP accept; request sent; no HTTP bytes before timeout")
    if tls and requests is None:
        return skip_suite(_HTTP_SKIP, "HTTPS probe needs the requests package", protocol="http")

    text = raw.decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0] if text else ""
    static_200 = first.startswith("HTTP/") and " 200 " in first
    header_map = _parse_headers(text)
    missing_dynamic = "date" in [h for h in HTTP_DYNAMIC_HEADERS if h not in header_map]
    server_val = header_map.get("server", "")
    server_hit = any(tell in server_val.lower() for tell in HTTP_SERVER_TELLS if server_val)
    login_skin = False
    proxy_hit = match_http_proxy_lure(text)
    method_stub = False
    put_first = ""
    put_text = ""
    fetched = False
    get_status = 0
    get_headers: dict[str, str] = {}

    if requests is not None:
        base = f"{_scheme(port)}://{host}:{port}"
        try:
            # Certificate validity is evidence, so untrusted target certificates must remain observable.
            resp = requests.get(  # nosec B501  # nosemgrep: python.requests.security.disabled-cert-validation.disabled-cert-validation
                f"{base}/",
                timeout=settings.timeout_seconds,
                allow_redirects=False,
                headers={"User-Agent": effective_user_agent()},
                verify=False,
                proxies=configure_requests_proxy() or None,
            )
            fetched = True
            get_status = int(resp.status_code)
            get_headers = {k.lower(): v for k, v in resp.headers.items()}
            header_map = {**header_map, **get_headers}
            missing_dynamic = "date" not in get_headers
            server_val = get_headers.get("server", server_val)
            server_hit = server_hit or any(
                tell in server_val.lower() for tell in HTTP_SERVER_TELLS if server_val
            )
            body = resp.content[:2048]
            loc = get_headers.get("location", "")
            if resp.status_code in (301, 302, 303, 307) and "index.html" in loc.lower():
                login_skin = True
            low_body = body.lower()
            if b'name="username"' in low_body and b'name="password"' in low_body:
                login_skin = True
            wire = f"HTTP/1.1 {resp.status_code}\r\n" + "\r\n".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            )
            proxy_hit = proxy_hit or match_http_proxy_lure(wire)
            if not login_skin and resp.status_code == 404:
                login_skin = _probe_admin_login_skin(requests, base)
        except Exception as exc:
            _log.debug("HTTP GET / probe failed: %s", exc)
        if tls and not fetched:
            if _tcp_accepts(host, port):
                return _silent_accept_suite("TCP accept; no HTTPS/HTTP response before timeout")
            return skip_suite(_HTTP_SKIP, "HTTPS handshake failed", protocol="http")
        if not login_skin:
            try:
                # Certificate validity is evidence, so untrusted target certificates must remain observable.
                form = requests.get(  # nosec B501  # nosemgrep: python.requests.security.disabled-cert-validation.disabled-cert-validation
                    f"{base}/index.html",
                    timeout=settings.timeout_seconds,
                    allow_redirects=False,
                    headers={"User-Agent": effective_user_agent()},
                    verify=False,
                    proxies=configure_requests_proxy() or None,
                )
                low_form = form.content[:2048].lower()
                if b'name="username"' in low_form and b'name="password"' in low_form:
                    login_skin = True
            except Exception as exc:
                _log.debug("HTTP login-form probe failed: %s", exc)
        try:
            # Certificate validity is evidence, so untrusted target certificates must remain observable.
            put = requests.put(  # nosec B501  # nosemgrep: python.requests.security.disabled-cert-validation.disabled-cert-validation
                f"{base}/index.html",
                timeout=settings.timeout_seconds,
                headers={"User-Agent": effective_user_agent(), "Content-Length": "0"},
                data=b"",
                verify=False,
                proxies=configure_requests_proxy() or None,
            )
            put_first = f"HTTP/1.1 {put.status_code}"
            put_text = put.content[:400].decode("latin-1", "replace")
            method_stub = put.status_code == 405 and len(put.content.strip()) == 0
        except Exception as exc:
            _log.debug("HTTP PUT conformance probe failed: %s", exc)

    if not login_skin and not tls:
        get_req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: " + host.encode("ascii", "replace") + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        get_raw, _ = tcp_transact(host, port, get_req, recv_first=False)
        get_text = get_raw.decode("latin-1", "replace")
        get_first = get_text.split("\r\n", 1)[0] if get_text else ""
        loc = _parse_headers(get_text).get("location", "")
        if (
            any(code in get_first for code in (" 301 ", " 302 ", " 303 ", " 307 "))
            and "index.html" in loc.lower()
        ):
            login_skin = True
        proxy_hit = proxy_hit or match_http_proxy_lure(get_text)

    if not method_stub and not tls:
        for path in (b"/", b"/index.html"):
            put_req = (
                b"PUT " + path + b" HTTP/1.1\r\n"
                b"Host: " + host.encode("ascii", "replace") + b"\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            put_raw, _ = tcp_transact(host, port, put_req, recv_first=False)
            put_text = put_raw.decode("latin-1", "replace")
            put_first = put_text.split("\r\n", 1)[0] if put_text else ""
            put_body = put_text.split("\r\n\r\n", 1)[-1] if put_text else ""
            if " 405 " in put_first and len(put_body.strip()) == 0:
                method_stub = True
                break

    static_http_face = missing_dynamic or (server_hit and static_200)

    header_order_hit = False
    header_order_names: list[str] = []
    proxy_result = detect_proxy_from_headers(header_map)
    if text:
        header_order_names = parse_header_names(text)
        for lure_order in HTTP_HEADER_LURE_ORDERS:
            if _header_order_prefix_match(header_order_names, lure_order):
                header_order_hit = True
                break

    wildcard_host_hit = False
    wildcard_detail = ""
    if not tls:
        wh_req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: " + WILDCARD_HOST.encode("ascii") + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        wh_raw, _ = tcp_transact(host, port, wh_req, recv_first=False)
        wh_text = wh_raw.decode("latin-1", "replace")
        wh_first = wh_text.split("\r\n", 1)[0] if wh_text else ""
        wildcard_host_hit = bool(wh_text) and " 200 " in wh_first
        wildcard_detail = wh_first or "(no response)"

    corroborating_http = static_http_face or login_skin or method_stub or static_200
    header_order_trigger = header_order_hit and corroborating_http and not proxy_result.detected

    indicators = [
        Indicator(
            id="http.malformed_200",
            title="HTTP static 200 OK on malformed POST",
            category="static_signature",
            triggered=static_200,
            protocol="http",
            detail=first or "(no status line)",
            evidence=text[:600],
        ),
        Indicator(
            id="http.dynamic_headers",
            title="HTTP missing dynamic Date header",
            category="static_signature",
            triggered=static_http_face,
            protocol="http",
            detail=_dynamic_header_detail(server_val, missing_dynamic, header_map),
            evidence=text.split("\r\n\r\n", 1)[0][:600],
        ),
        Indicator(
            id="http.method_stub",
            title="HTTP PUT/DELETE returns empty 405",
            category="static_signature",
            triggered=method_stub,
            protocol="http",
            detail=put_first or "(no PUT status line)",
            evidence=put_text[:400],
        ),
        Indicator(
            id="http.login_skin",
            title="HTTP / redirects to a stock login form",
            category="static_signature",
            triggered=login_skin,
            protocol="http",
            detail="GET / looks like a canned login skin"
            if login_skin
            else "GET / is not a stock login skin",
        ),
        Indicator(
            id="http.proxy_lure",
            title="HTTP 407 looks like a stock proxy lure",
            category="static_signature",
            triggered=bool(proxy_hit),
            protocol="http",
            detail=proxy_hit or "no Via-localhost / squid-3.3.8 / ISA deny phrase",
        ),
        Indicator(
            id="http.header_order",
            title="HTTP response header order matches lure profile",
            category="static_signature",
            triggered=header_order_trigger,
            protocol="http",
            fingerprint_type="http_header_order",
            tell_tier="edge",
            detail=(
                f"order={header_order_names[:6]}"
                if header_order_hit
                else "header order does not match lure profile"
            ),
            remediation="Match production nginx/apache header ordering",
            suppressed=header_order_hit and proxy_result.detected,
            suppression_reason=(
                "reverse_proxy_detected" if header_order_hit and proxy_result.detected else ""
            ),
        ),
        Indicator(
            id="http.wildcard_host",
            title="HTTP accepts invalid Host header",
            category="proto_conformance",
            triggered=wildcard_host_hit,
            protocol="http",
            tell_tier="origin",
            detail=wildcard_detail,
            remediation="Reject unknown Host values with 400/421/444",
        ),
        Indicator(
            id="http.framework_404_session",
            title="HTTP 404 serves framework session cookie",
            category="static_signature",
            triggered=_framework_404_session(get_status, server_val, get_headers or header_map),
            protocol="http",
            detail=_framework_404_detail(get_status, server_val, get_headers or header_map),
            remediation="Avoid issuing session cookies on 404 error pages for decoy HTTP faces",
        ),
        Indicator(
            id="http.silent_accept",
            title="HTTP TCP accepts then returns no response",
            category="static_signature",
            triggered=False,
            protocol="http",
            detail="HTTP status received",
        ),
    ]
    return indicators


def _framework_404_session(status: int, server_val: str, headers: dict[str, str]) -> bool:
    if status != 404:
        return False
    server = (server_val or headers.get("server", "")).lower()
    if "werkzeug" not in server and "gunicorn" not in server and "uvicorn" not in server:
        return False
    return "set-cookie" in {k.lower() for k in headers}


def _framework_404_detail(status: int, server_val: str, headers: dict[str, str]) -> str:
    if _framework_404_session(status, server_val, headers):
        return f"HTTP {status} with {server_val or 'framework'} Set-Cookie"
    return f"HTTP {status or '?'} without framework session-on-404 pattern"


def _header_order_prefix_match(names: list[str], lure: tuple[str, ...]) -> bool:
    if len(names) < len(lure):
        return False
    return tuple(names[: len(lure)]) == lure


def _probe_http_safe(host: str, port: int) -> list[Indicator]:
    """Safe mode: GET / and HEAD only — no PUT, wildcard Host, or malformed POST."""
    requests = optional_import("requests")
    tls = port in _TLS_PORTS
    skipped = [
        Indicator(
            id=i,
            title=title,
            category=cat,
            skipped=True,
            skip_reason="safe-mode: GET/HEAD only",
            protocol="http",
            detail="safe-mode: GET/HEAD only",
        )
        for i, title, cat in _HTTP_SKIP
        if i not in ("http.dynamic_headers", "http.silent_accept")
    ]
    if requests is None and tls:
        return skip_suite(_HTTP_SKIP, "HTTPS probe needs the requests package", protocol="http")
    text = ""
    header_map: dict[str, str] = {}
    if not tls:
        get_req = (
            b"GET / HTTP/1.1\r\n"
            b"Host: " + host.encode("ascii", "replace") + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        raw, err = tcp_transact(host, port, get_req, recv_first=False)
        if err and not raw:
            return skip_suite(_HTTP_SKIP, closed_reason(err), protocol="http", error=err)
        if not err and not raw:
            return _silent_accept_suite("TCP accept; request sent; no HTTP bytes before timeout")
        text = raw.decode("latin-1", "replace")
        header_map = _parse_headers(text)
    else:
        base = f"{_scheme(port)}://{host}:{port}"
        try:
            # Certificate validity is evidence, so untrusted target certificates must remain observable.
            resp = requests.get(  # nosec B501  # nosemgrep: python.requests.security.disabled-cert-validation.disabled-cert-validation
                f"{base}/",
                timeout=settings.timeout_seconds,
                allow_redirects=False,
                headers={"User-Agent": effective_user_agent()},
                verify=False,
                proxies=configure_requests_proxy() or None,
            )
            text = f"HTTP/1.1 {resp.status_code}\r\n" + "\r\n".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            )
            header_map = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            if _tcp_accepts(host, port):
                return _silent_accept_suite("TCP accept; no HTTPS/HTTP response before timeout")
            return skip_suite(_HTTP_SKIP, str(exc), protocol="http", error=str(exc))
    missing_dynamic = "date" not in header_map
    server_val = header_map.get("server", "")
    return [
        Indicator(
            id="http.dynamic_headers",
            title="HTTP missing dynamic Date header",
            category="static_signature",
            triggered=missing_dynamic,
            protocol="http",
            detail=_dynamic_header_detail(server_val, missing_dynamic, header_map),
            evidence=text.split("\r\n\r\n", 1)[0][:600] if text else "",
        ),
        Indicator(
            id="http.silent_accept",
            title="HTTP TCP accepts then returns no response",
            category="static_signature",
            triggered=False,
            protocol="http",
            detail="HTTP status received",
        ),
        *skipped,
    ]
