"""IPP/CUPS HTTP + light IPP fingerprint engine.

Protocol non-compliance strategies (read-only — never print, pause, or
reconfigure queues):
  · arbitrary_auth — anonymous /admin challenged 401/403, then two entropy-varied
    Basic credentials both return 200
  · state_nonpersist — unsupported IPP opcode still successful-ok and/or ghost
    printer identity drifts across reconnect
  · static_signature — CUPS root framing; stock Server header lures; unknown-path
    facade; DELETE method stub; /printers stub; open /admin; frozen Date;
    IPP Content-Type framing; ghost-printer successful-ok; request-id echo;
    bitwise-identical canned IPP replies; illegal operation façade; stock HTML
    body lures
  · framing — GET ``/`` is not a CUPS/HTTP print-service speaker

Transport: cleartext HTTP first; TLS fallback when the peer returns a TLS record
layer or cleartext yields no HTTP response (CUPS often serves HTTPS on 631).

See docs/tcp/IPP.md, RFC 8010/8011 (IPP), and CUPS HTTP admin surface.
"""

from __future__ import annotations

import base64
import re
import secrets
import struct
from contextlib import closing
from dataclasses import dataclass

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
from honeypot_auditor.proxy_transport import create_tls_connection
from honeypot_auditor.settings import settings

_IPP_SKIP = (
    (
        "ipp.arbitrary_auth",
        "IPP/CUPS accepts two entropy-varied Basic credentials on /admin",
        "arbitrary_auth",
    ),
    (
        "ipp.state_nonpersist",
        "IPP state drifts across reconnect (illegal-op ok / ghost identity)",
        "state_nonpersist",
    ),
    (
        "ipp.root_framing",
        "IPP/CUPS root response is not a print-service HTTP face",
        "static_signature",
    ),
    (
        "ipp.server_header",
        "IPP/CUPS Server header matches a stock honeypot lure",
        "static_signature",
    ),
    (
        "ipp.path_facade",
        "IPP/CUPS answers unknown paths with a root-shaped 200",
        "static_signature",
    ),
    (
        "ipp.method_stub",
        "IPP/CUPS ignores DELETE on / (method stub)",
        "static_signature",
    ),
    (
        "ipp.printers_stub",
        "IPP/CUPS /printers is a stub or root echo",
        "static_signature",
    ),
    (
        "ipp.admin_open",
        "IPP/CUPS /admin is open without authentication",
        "static_signature",
    ),
    (
        "ipp.frozen_date",
        "IPP/CUPS Date header is missing or frozen across GETs",
        "static_signature",
    ),
    (
        "ipp.ipp_framing",
        "IPP POST does not return an application/ipp body",
        "static_signature",
    ),
    (
        "ipp.ghost_printer",
        "IPP Get-Printer-Attributes succeeds for a nonexistent printer",
        "static_signature",
    ),
    (
        "ipp.request_id",
        "IPP response request-id does not echo the request",
        "static_signature",
    ),
    (
        "ipp.ipp_clone",
        "IPP replies are bitwise-identical across distinct request-ids",
        "static_signature",
    ),
    (
        "ipp.illegal_op",
        "IPP accepts an illegal operation-id",
        "static_signature",
    ),
    (
        "ipp.stock_body",
        "IPP/CUPS HTML body matches a stock honeypot lure",
        "static_signature",
    ),
)

# Decisive Server tokens — rare outside decoys.
_STOCK_SERVER_DECISIVE = (
    "honeypot",
    "fake-cups",
    "cups-honeypot",
    "printer-honeypot",
)
# Frozen / generic / product-named — corroboration-gated alone.
_STOCK_SERVER_GENERIC = (
    "cups/1.1",
    "cups/1.2",
    "cups/1.3",
    "cups/1.4.2",
    "cups/1.4.3",
    "cups/1.4.4",
    "cups/1.4.6",
    "opencanary",
)

_STOCK_BODY_DECISIVE = (
    "honeypot printer",
    "fake cups",
    "cups honeypot",
    "this is not a real printer",
)
_STOCK_BODY_GENERIC = (
    "welcome to cups",
    "web interface is currently disabled",
    "no printers found",
    "opencanary",
)

# Strong CUPS HTML / URI markers — not bare "printer" marketing copy.
_CUPS_HINT_RE = re.compile(
    rb"(cups\s+\d|home\s*-\s*cups|cups\s+[\d.]+|/admin|/printers|ipp://|application/ipp)",
    re.IGNORECASE,
)
_CUPS_ADMIN_RE = re.compile(
    rb"(cups|administration|printers|classes|jobs|/admin)",
    re.IGNORECASE,
)

_IPP_SUCCESSFUL_OK = 0x0000
_IPP_CLIENT_ERROR_NOT_FOUND = 0x0406
_IPP_CLIENT_ERROR_NOT_POSSIBLE = 0x0404
_IPP_CLIENT_ERROR_BAD_REQUEST = 0x0400
_IPP_SERVER_ERROR_OPERATION_NOT_SUPPORTED = 0x0501
_IPP_ILLEGAL_OPERATION = 0x7FFF

_MIN_FACADE_BODY = 32


@dataclass(frozen=True)
class _IppHeader:
    version_major: int
    version_minor: int
    status: int
    request_id: int


def _looks_like_tls(raw: bytes) -> bool:
    """TLS record layer ContentType: handshake(0x16) or alert(0x15)."""
    return bool(raw) and raw[0] in {0x15, 0x16}


def _recv_all(sock, timeout: float, max_bytes: int = 65535) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    try:
        while sum(len(c) for c in chunks) < max_bytes:
            buf = sock.recv(4096)
            if not buf:
                break
            chunks.append(buf)
            sock.settimeout(min(0.4, timeout))
    except TimeoutError:
        pass
    return b"".join(chunks)


def _transact(host: str, port: int, payload: bytes, *, tls: bool) -> tuple[bytes, str]:
    if not tls:
        return tcp_transact(
            host, port, payload, recv_first=False, timeout=settings.timeout_seconds
        )
    try:
        with closing(
            create_tls_connection(host, port, settings.timeout_seconds)
        ) as sock:
            if payload:
                sock.sendall(payload)
            return _recv_all(sock, settings.timeout_seconds), ""
    except (OSError, ImportError) as exc:
        return b"", str(exc)


def _parse_http_response(raw: bytes) -> tuple[int, dict[str, str], bytes, str]:
    if not raw:
        return 0, {}, b"", "empty HTTP response"
    if _looks_like_tls(raw):
        return 0, {}, b"", "tls-record-layer"
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return 0, {}, rest, "missing status line"
    status_line = lines[0].decode("latin-1", "replace")
    parts = status_line.split()
    if not parts or not parts[0].startswith("HTTP/"):
        return 0, {}, rest, "non-HTTP response"
    status = 0
    if len(parts) >= 2:
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


def _http_exchange(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    tls: bool = False,
    extra_headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> tuple[int, dict[str, str], bytes, str]:
    """Minimal HTTP/1.1 exchange. Returns (status, headers, body, error)."""
    hdrs = {
        "Host": f"{host}:{port}",
        "User-Agent": effective_user_agent(),
        "Accept": "*/*",
        "Connection": "close",
    }
    if extra_headers:
        hdrs.update(extra_headers)
    if body:
        hdrs.setdefault("Content-Type", "application/ipp")
        hdrs["Content-Length"] = str(len(body))
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        + "\r\n"
    ).encode("ascii", "replace") + body
    raw, err = _transact(host, port, request, tls=tls)
    if err and not raw:
        return 0, {}, b"", closed_reason(err)
    return _parse_http_response(raw)


def _is_cups_root(status: int, headers: dict[str, str], body: bytes) -> bool:
    """True when the peer looks like a CUPS/IPP HTTP face."""
    if status == 0:
        return False
    server = (headers.get("server") or "").lower()
    if "cups" in server or "ipp" in server:
        return True
    if status in {200, 301, 302, 401, 403} and _CUPS_HINT_RE.search(body[:4096] or b""):
        return True
    location = (headers.get("location") or "").lower()
    return status in {301, 302} and any(
        token in location for token in ("/admin", "/printers", "/ipp")
    )


def _server_stock_assessment(server: str) -> tuple[str | None, bool]:
    """Return ``(detail, requires_corroboration)`` for Server header lures."""
    low = (server or "").strip().lower()
    if not low:
        return None, False
    for token in _STOCK_SERVER_DECISIVE:
        if token in low:
            return f"decisive Server lure {server!r}", False
    for token in _STOCK_SERVER_GENERIC:
        if token in low:
            return f"generic/frozen Server {server!r}", True
    return None, False


def _body_stock_assessment(body: bytes) -> tuple[str | None, bool]:
    low = body[:4096].decode("utf-8", "replace").lower()
    if not low.strip():
        return None, False
    for token in _STOCK_BODY_DECISIVE:
        if token in low:
            return f"decisive body lure {token!r}", False
    for token in _STOCK_BODY_GENERIC:
        if token in low:
            return f"generic body lure {token!r}", True
    return None, False


def _is_ipp_content_type(headers: dict[str, str]) -> bool:
    ctype = (headers.get("content-type") or "").lower()
    return "application/ipp" in ctype


def _parse_ipp_header(body: bytes) -> _IppHeader | None:
    if len(body) < 8:
        return None
    major, minor, status, request_id = struct.unpack(">BBHI", body[:8])
    if major != 0x01 or minor not in {0x00, 0x01}:
        return None
    return _IppHeader(major, minor, status, request_id)


def _is_ipp_binary(body: bytes) -> bool:
    return _parse_ipp_header(body) is not None


def _body_complete(headers: dict[str, str], body: bytes) -> bool:
    """False when Content-Length claims more bytes than we received (truncated)."""
    cl = headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > len(body):
        return False
    return True


def _bodies_equal_facade(
    a: bytes,
    b: bytes,
    a_hdrs: dict[str, str],
    b_hdrs: dict[str, str],
) -> bool:
    if not a or not b or a != b:
        return False
    if len(a) < _MIN_FACADE_BODY:
        return False
    if not _body_complete(a_hdrs, a) or not _body_complete(b_hdrs, b):
        return False
    return True


def _build_get_printer_attributes(request_id: int, printer_uri: str) -> bytes:
    """Minimal IPP 1.1 Get-Printer-Attributes (RFC 8010/8011)."""
    out = bytearray(struct.pack(">BBHI", 0x01, 0x01, 0x000B, request_id & 0xFFFFFFFF))
    out.append(0x01)  # operation-attributes-tag

    def _write_attr(tag: int, name: str, value: str) -> None:
        nb = name.encode("utf-8")
        vb = value.encode("utf-8")
        out.append(tag)
        out.extend(struct.pack(">H", len(nb)))
        out.extend(nb)
        out.extend(struct.pack(">H", len(vb)))
        out.extend(vb)

    _write_attr(0x47, "attributes-charset", "utf-8")
    _write_attr(0x48, "attributes-natural-language", "en")
    _write_attr(0x45, "printer-uri", printer_uri)
    _write_attr(0x44, "requested-attributes", "all")
    out.append(0x03)  # end-of-attributes
    return bytes(out)


def _build_illegal_operation(request_id: int) -> bytes:
    """IPP PDU with reserved/illegal operation-id 0x7FFF."""
    out = bytearray(
        struct.pack(">BBHI", 0x01, 0x01, _IPP_ILLEGAL_OPERATION, request_id & 0xFFFFFFFF)
    )
    out.append(0x01)
    for tag, name, value in (
        (0x47, "attributes-charset", "utf-8"),
        (0x48, "attributes-natural-language", "en"),
    ):
        nb = name.encode("utf-8")
        vb = value.encode("utf-8")
        out.append(tag)
        out.extend(struct.pack(">H", len(nb)))
        out.extend(nb)
        out.extend(struct.pack(">H", len(vb)))
        out.extend(vb)
    out.append(0x03)
    return bytes(out)


def _printers_is_stub(status: int, body: bytes, root_body: bytes) -> bool:
    if status == 200 and body and root_body and body == root_body and len(body) >= _MIN_FACADE_BODY:
        return True
    low = body[:4096].lower()
    if status == 200 and (
        (b"no printers" in low and b"honeypot" in low)
        or b"fake printer" in low
        or b"printer honeypot" in low
    ):
        return True
    return False


def _ipp_error_expected(status_code: int) -> bool:
    return status_code in {
        _IPP_CLIENT_ERROR_BAD_REQUEST,
        _IPP_CLIENT_ERROR_NOT_FOUND,
        _IPP_CLIENT_ERROR_NOT_POSSIBLE,
        _IPP_SERVER_ERROR_OPERATION_NOT_SUPPORTED,
    } or (0x0400 <= status_code <= 0x04FF) or (0x0500 <= status_code <= 0x05FF)


def probe_ipp(host: str, port: int) -> list[Indicator]:
    use_tls = False
    root_status, root_hdrs, root_body, root_err = _http_exchange(
        host, port, "GET", "/", tls=False
    )

    # TLS fallback: record-layer response, or cleartext produced no HTTP.
    if root_err == "tls-record-layer" or (
        root_status == 0 and not root_body and root_err not in {"", "tls-record-layer"}
    ):
        t_status, t_hdrs, t_body, t_err = _http_exchange(host, port, "GET", "/", tls=True)
        if t_status > 0 or t_body:
            use_tls = True
            root_status, root_hdrs, root_body, root_err = t_status, t_hdrs, t_body, t_err
        elif root_err == "tls-record-layer":
            root_err = t_err or root_err

    if root_err == "tls-record-layer":
        root_err = "TLS required but handshake/exchange failed"

    if root_err and not root_body and root_status == 0:
        return skip_suite(_IPP_SKIP, root_err, protocol="ipp", error=root_err)

    framing_hit = not _is_cups_root(root_status, root_hdrs, root_body)
    framing_detail = (
        f"GET / status={root_status} is not a CUPS/IPP HTTP face "
        f"(server={root_hdrs.get('server', '')!r}, tls={use_tls})"
        if framing_hit
        else (
            f"CUPS/IPP HTTP face status={root_status} "
            f"server={root_hdrs.get('server', '')!r} tls={use_tls}"
        )
    )

    if framing_hit:
        out: list[Indicator] = []
        reason = "not an IPP/CUPS speaker"
        for spec in _IPP_SKIP:
            if spec[0] == "ipp.root_framing":
                out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=True,
                        protocol="ipp",
                        detail=framing_detail,
                        evidence=root_body[:256].hex(),
                        remediation="Serve a real CUPS/IPP HTTP face on the print port",
                        fidelity="high",
                    )
                )
            else:
                out.append(skipped_indicator(*spec, reason, protocol="ipp"))
        return out

    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        safe_out: list[Indicator] = []
        for spec in _IPP_SKIP:
            if spec[0] == "ipp.root_framing":
                safe_out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=False,
                        protocol="ipp",
                        detail=framing_detail,
                        evidence=(root_hdrs.get("server") or "")[:120],
                        remediation="",
                        fidelity="high",
                    )
                )
            else:
                safe_out.append(skipped_indicator(*spec, reason, protocol="ipp"))
        return safe_out

    server_val = root_hdrs.get("server") or ""
    server_detail, server_requires = _server_stock_assessment(server_val)
    server_hit = bool(server_detail)

    body_detail, body_requires = _body_stock_assessment(root_body)
    body_hit = bool(body_detail)

    mystery = f"/_hpa_nonexistent_{secrets.token_hex(3)}"
    path_status, path_hdrs, path_body, path_err = _http_exchange(
        host, port, "GET", mystery, tls=use_tls
    )
    path_skipped = bool(path_err) and path_status == 0 and not path_body
    path_hit = False
    path_detail = "unknown-path handling not evaluated"
    if not path_skipped:
        if path_status in {404, 401, 403, 405, 501}:
            path_detail = f"compliant unknown-path handling (status={path_status})"
        elif path_status == 200 and _bodies_equal_facade(
            path_body, root_body, path_hdrs, root_hdrs
        ):
            path_hit = True
            path_detail = (
                f"GET {mystery} returned status=200 root-shaped body "
                "(unknown paths should not echo /)"
            )
        else:
            path_detail = f"GET {mystery} status={path_status}"

    del_status, del_hdrs, del_body, del_err = _http_exchange(
        host, port, "DELETE", "/", tls=use_tls
    )
    method_skipped = bool(del_err) and del_status == 0 and not del_body
    method_hit = False
    method_detail = "DELETE / not evaluated"
    if not method_skipped:
        if del_status in {401, 403, 405, 501}:
            method_detail = f"DELETE / correctly rejected (status={del_status})"
        elif del_status == 200 and _bodies_equal_facade(
            del_body, root_body, del_hdrs, root_hdrs
        ):
            method_hit = True
            method_detail = (
                "DELETE / returned status=200 with GET / body "
                "(print faces should not ignore DELETE)"
            )
        else:
            method_detail = f"DELETE / status={del_status}"

    pr_status, pr_hdrs, pr_body, pr_err = _http_exchange(
        host, port, "GET", "/printers", tls=use_tls
    )
    printers_skipped = bool(pr_err) and pr_status == 0 and not pr_body
    printers_hit = False
    printers_detail = "/printers not evaluated"
    if not printers_skipped:
        if _printers_is_stub(pr_status, pr_body, root_body):
            printers_hit = True
            printers_detail = (
                f"GET /printers status={pr_status} looks like a stub/root echo "
                f"({len(pr_body)} bytes)"
            )
        elif pr_status in {200, 401, 403}:
            printers_detail = f"GET /printers status={pr_status} ({len(pr_body)} bytes)"
        else:
            printers_detail = f"GET /printers status={pr_status}"

    ad_status, ad_hdrs, ad_body, ad_err = _http_exchange(
        host, port, "GET", "/admin", tls=use_tls
    )
    admin_skipped = bool(ad_err) and ad_status == 0 and not ad_body
    admin_hit = False
    admin_requires = False
    admin_detail = "/admin not evaluated"
    if not admin_skipped:
        www = (ad_hdrs.get("www-authenticate") or "").strip()
        if ad_status in {401, 403}:
            admin_detail = f"GET /admin correctly challenged (status={ad_status})"
        elif ad_status == 200 and not www:
            cups_admin = bool(_CUPS_ADMIN_RE.search(ad_body[:4096] or b"")) or (
                "cups" in (ad_hdrs.get("server") or "").lower()
            )
            if cups_admin and ad_body.strip():
                admin_hit = True
                admin_detail = (
                    f"GET /admin status=200 without WWW-Authenticate "
                    f"({len(ad_body)} bytes)"
                )
            elif ad_status == 200:
                admin_hit = True
                admin_requires = True
                admin_detail = (
                    f"GET /admin status=200 empty/generic without auth "
                    f"({len(ad_body)} bytes)"
                )
            else:
                admin_detail = f"GET /admin status={ad_status}"
        else:
            admin_detail = f"GET /admin status={ad_status}"

    # Frozen / missing Date across two successful GETs (root + path or printers).
    date1 = (root_hdrs.get("date") or "").strip()
    date2 = ""
    date2_src = ""
    if not path_skipped and path_status > 0:
        date2 = (path_hdrs.get("date") or "").strip()
        date2_src = "path"
    if not date2 and not printers_skipped and pr_status > 0:
        date2 = (pr_hdrs.get("date") or "").strip()
        date2_src = "printers"
    if not date2 and not admin_skipped and ad_status > 0:
        date2 = (ad_hdrs.get("date") or "").strip()
        date2_src = "admin"
    frozen_hit = False
    frozen_requires = False
    frozen_skipped = False
    frozen_detail = "Date header not evaluated"
    if not date2_src:
        frozen_skipped = True
        frozen_detail = "no second GET response for Date comparison"
    elif date1 and date2 and date1 == date2:
        frozen_hit = True
        frozen_detail = f"identical Date across GET / and GET {date2_src}: {date1!r}"
    elif not date1 and not date2:
        frozen_hit = True
        frozen_requires = True
        frozen_detail = f"missing Date on GET / and GET {date2_src}"
    else:
        frozen_detail = f"Date differs or present on one side (root={date1!r}, {date2_src}={date2!r})"

    # IPP Get-Printer-Attributes with distinct request-ids + illegal op.
    uri = f"ipp://{host}:{port}/printers/hpaudit-{secrets.token_hex(2)}"
    rid1 = (secrets.randbelow(0x7FFFFFFF) + 1) & 0xFFFFFFFF
    rid2 = (rid1 + 1) % 0x100000000 or 1
    rid3 = (rid2 + 1) % 0x100000000 or 1
    ipp1 = _build_get_printer_attributes(rid1, uri)
    ipp2 = _build_get_printer_attributes(rid2, uri)
    illegal = _build_illegal_operation(rid3)

    i1_status, i1_hdrs, i1_body, i1_err = _http_exchange(
        host,
        port,
        "POST",
        "/ipp/print",
        tls=use_tls,
        extra_headers={"Content-Type": "application/ipp"},
        body=ipp1,
    )
    ipp_path = "/ipp/print"
    if i1_status in {0, 404} and not i1_body:
        i1_status, i1_hdrs, i1_body, i1_err = _http_exchange(
            host,
            port,
            "POST",
            "/",
            tls=use_tls,
            extra_headers={"Content-Type": "application/ipp"},
            body=ipp1,
        )
        ipp_path = "/"

    ipp_skipped = bool(i1_err) and i1_status == 0 and not i1_body
    ipp_hit = False
    ipp_detail = "IPP POST not evaluated"
    parsed1 = _parse_ipp_header(i1_body) if i1_body else None
    if not ipp_skipped:
        if i1_status == 200 and (
            _is_ipp_content_type(i1_hdrs) or parsed1 is not None
        ):
            ipp_detail = (
                f"POST {ipp_path} returned IPP "
                f"(content-type={i1_hdrs.get('content-type', '')!r}, {len(i1_body)} bytes)"
            )
        elif i1_status == 200 and root_body and i1_body == root_body:
            ipp_hit = True
            ipp_detail = (
                f"POST {ipp_path} application/ipp echoed the HTML root "
                "(expected application/ipp)"
            )
        elif i1_status in {401, 403, 426, 505}:
            ipp_skipped = True
            ipp_detail = f"IPP POST denied/unsupported (status={i1_status})"
        else:
            ipp_hit = True
            ipp_detail = (
                f"POST {ipp_path} status={i1_status} "
                f"content-type={i1_hdrs.get('content-type', '')!r} "
                "is not an IPP response"
            )

    ghost_hit = False
    ghost_skipped = ipp_skipped
    ghost_detail = "ghost printer not evaluated"
    if not ipp_skipped and parsed1 is not None:
        if parsed1.status == _IPP_SUCCESSFUL_OK:
            ghost_hit = True
            ghost_detail = (
                f"Get-Printer-Attributes for nonexistent {uri!r} returned "
                f"successful-ok (status-code=0x{parsed1.status:04x})"
            )
        elif _ipp_error_expected(parsed1.status):
            ghost_detail = (
                f"missing printer correctly rejected "
                f"(status-code=0x{parsed1.status:04x})"
            )
        else:
            ghost_detail = f"IPP status-code=0x{parsed1.status:04x} for missing printer"
    elif not ipp_skipped:
        ghost_skipped = True
        ghost_detail = "no parseable IPP header for ghost-printer check"

    rid_hit = False
    rid_skipped = ipp_skipped
    rid_detail = "request-id echo not evaluated"
    if not ipp_skipped and parsed1 is not None:
        if parsed1.request_id != rid1:
            rid_hit = True
            rid_detail = (
                f"response request-id={parsed1.request_id} != request {rid1}"
            )
        else:
            rid_detail = f"request-id echoed correctly ({rid1})"
    elif not ipp_skipped:
        rid_skipped = True
        rid_detail = "no parseable IPP header for request-id check"

    clone_hit = False
    clone_detail = "IPP clone not evaluated"
    clone_skipped = ipp_skipped
    i2_body = b""
    if not ipp_skipped and i1_body:
        i2_status, _i2_hdrs, i2_body, i2_err = _http_exchange(
            host,
            port,
            "POST",
            ipp_path,
            tls=use_tls,
            extra_headers={"Content-Type": "application/ipp"},
            body=ipp2,
        )
        if i2_err and not i2_body:
            clone_skipped = True
            clone_detail = closed_reason(i2_err)
        elif i1_body and i2_body and i1_body == i2_body and rid1 != rid2:
            clone_hit = True
            clone_detail = (
                f"distinct IPP request-ids {rid1}/{rid2} returned bitwise-identical "
                f"{len(i1_body)}-byte payloads (status={i1_status}/{i2_status})"
            )
        else:
            clone_detail = (
                f"IPP replies differ across request-ids "
                f"({len(i1_body)} vs {len(i2_body)} bytes)"
            )
        # Also flag frozen request-id across both replies when bodies differ.
        parsed2 = _parse_ipp_header(i2_body) if i2_body else None
        if (
            not rid_hit
            and parsed1 is not None
            and parsed2 is not None
            and parsed1.request_id == parsed2.request_id
            and rid1 != rid2
        ):
            rid_hit = True
            rid_detail = (
                f"both IPP replies froze request-id={parsed1.request_id} "
                f"despite distinct requests {rid1}/{rid2}"
            )

    illegal_hit = False
    illegal_skipped = ipp_skipped
    illegal_detail = "illegal operation not evaluated"
    if not ipp_skipped:
        ill_status, ill_hdrs, ill_body, ill_err = _http_exchange(
            host,
            port,
            "POST",
            ipp_path,
            tls=use_tls,
            extra_headers={"Content-Type": "application/ipp"},
            body=illegal,
        )
        if ill_err and not ill_body:
            illegal_skipped = True
            illegal_detail = closed_reason(ill_err)
        elif ill_status in {401, 403, 426}:
            illegal_skipped = True
            illegal_detail = f"illegal-op POST denied (status={ill_status})"
        else:
            parsed_ill = _parse_ipp_header(ill_body) if ill_body else None
            if root_body and ill_body == root_body:
                illegal_hit = True
                illegal_detail = (
                    f"illegal operation-id echoed HTML root on POST {ipp_path}"
                )
            elif parsed_ill is not None and parsed_ill.status == _IPP_SUCCESSFUL_OK:
                illegal_hit = True
                illegal_detail = (
                    f"illegal operation-id 0x{_IPP_ILLEGAL_OPERATION:04x} returned "
                    f"successful-ok"
                )
            elif parsed_ill is not None and _ipp_error_expected(parsed_ill.status):
                illegal_detail = (
                    f"illegal operation correctly rejected "
                    f"(status-code=0x{parsed_ill.status:04x})"
                )
            elif parsed_ill is None:
                illegal_hit = True
                illegal_detail = (
                    f"illegal-op POST status={ill_status} "
                    f"content-type={ill_hdrs.get('content-type', '')!r} "
                    "is not an IPP error response"
                )
            else:
                illegal_detail = (
                    f"illegal-op IPP status-code=0x{parsed_ill.status:04x}"
                )

    # --- arbitrary_auth: dual entropy-varied Basic on /admin ---
    (low_user, low_pass), (high_user, high_pass) = entropy_varied_creds()
    auth_ok = 0
    auth_notes: list[str] = []
    auth_err = ""
    for label, user, password in (
        ("low-entropy", low_user, low_pass),
        ("high-entropy", high_user, high_pass),
    ):
        token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        ba_status, _ba_hdrs, ba_body, ba_err = _http_exchange(
            host,
            port,
            "GET",
            "/admin",
            tls=use_tls,
            extra_headers={"Authorization": f"Basic {token}"},
        )
        if ba_err and ba_status == 0 and not ba_body:
            auth_err = auth_err or ba_err
            auth_notes.append(f"{label}: unanswered ({ba_err})")
            continue
        if ba_status == 200:
            auth_ok += 1
            auth_notes.append(f"{label}: Basic unlocked /admin (status=200)")
        else:
            auth_notes.append(f"{label}: Basic status={ba_status}")
    auth_skipped = auth_ok == 0 and bool(auth_err) and all(
        "unanswered" in n for n in auth_notes
    )
    # A public /admin already returns 200. Both Basic attempts getting 200 is
    # the same page, not a credential bypass. Require the anonymous challenge.
    challenged = ad_status in {401, 403}
    auth_hit = auth_ok == 2 and challenged
    if auth_hit:
        auth_detail = (
            f"anon /admin was {ad_status}; two entropy-varied Basic credentials "
            f"both unlocked /admin (status=200)"
        )
    elif auth_ok == 2 and not challenged:
        auth_detail = (
            f"anon /admin was {ad_status}; both Basic requests were also 200 "
            f"(path is public, not a credential bypass)"
        )
    else:
        auth_detail = (
            f"anon /admin was {ad_status}; "
            + ("; ".join(auth_notes) if auth_notes else "Basic /admin not evaluated")
        )

    # --- state_nonpersist: illegal-op successful-ok and/or ghost drift ---
    state_notes: list[str] = []
    state_skipped = False
    state_err = ""
    if illegal_hit and (
        "successful-ok" in illegal_detail or "echoed HTML root" in illegal_detail
    ):
        state_notes.append(illegal_detail)

    pause_s = jittered_reconnect_pause()
    rid4 = (rid3 + 1) % 0x100000000 or 1
    ipp_reconnect = _build_get_printer_attributes(rid4, uri)
    if not ipp_skipped:
        r_status, _r_hdrs, r_body, r_err = _http_exchange(
            host,
            port,
            "POST",
            ipp_path,
            tls=use_tls,
            extra_headers={"Content-Type": "application/ipp"},
            body=ipp_reconnect,
        )
        if r_err and not r_body:
            if not state_notes:
                state_skipped = True
                state_err = r_err
        else:
            parsed_r = _parse_ipp_header(r_body) if r_body else None
            if parsed1 is not None and parsed_r is not None:
                if parsed1.status != parsed_r.status:
                    state_notes.append(
                        f"ghost printer status drifted "
                        f"0x{parsed1.status:04x}→0x{parsed_r.status:04x} across reconnect"
                    )
                elif (
                    ghost_hit
                    and parsed_r.status == _IPP_SUCCESSFUL_OK
                    and i1_body
                    and r_body
                    and i1_body != r_body
                ):
                    state_notes.append(
                        "ghost printer identity/attributes changed across reconnect"
                    )
            elif parsed1 is not None and parsed_r is None and r_body:
                state_notes.append(
                    "ghost printer reply lost IPP framing across reconnect"
                )
    elif not state_notes:
        state_skipped = True

    state_hit = bool(state_notes)
    state_detail = (
        "; ".join(state_notes)
        if state_notes
        else (
            closed_reason(state_err)
            if state_skipped and state_err
            else "IPP state stable across reconnect / illegal-op rejected"
        )
    )
    rtt_note = rtt_evidence(pause_s * 1000.0)
    if rtt_note and state_hit:
        state_detail = f"{state_detail}; pause_{rtt_note}"

    return [
        Indicator(
            id="ipp.arbitrary_auth",
            title="IPP/CUPS accepts two entropy-varied Basic credentials on /admin",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason=closed_reason(auth_err) if auth_skipped else "",
            error=auth_err if auth_skipped else "",
            protocol="ipp",
            detail=auth_detail,
            evidence=f"{low_user},{high_user}" if auth_hit else "",
            remediation="Reject unknown Basic credentials on /admin",
            fidelity="decisive" if auth_hit else "medium",
        ),
        Indicator(
            id="ipp.state_nonpersist",
            title="IPP state drifts across reconnect (illegal-op ok / ghost identity)",
            category="state_nonpersist",
            triggered=state_hit,
            skipped=state_skipped and not state_hit,
            skip_reason=state_detail if state_skipped and not state_hit else "",
            error=state_err,
            protocol="ipp",
            detail=state_detail,
            evidence="",
            remediation="Reject illegal IPP opcodes; keep ghost-printer errors stable across sessions",
            fidelity="high" if state_hit else "medium",
        ),
        Indicator(
            id="ipp.root_framing",
            title="IPP/CUPS root response is not a print-service HTTP face",
            category="static_signature",
            triggered=False,
            protocol="ipp",
            detail=framing_detail,
            evidence=(server_val or "")[:120],
            remediation="",
            fidelity="high",
        ),
        Indicator(
            id="ipp.server_header",
            title="IPP/CUPS Server header matches a stock honeypot lure",
            category="static_signature",
            triggered=server_hit,
            protocol="ipp",
            detail=server_detail or f"Server={server_val!r}",
            evidence=server_val[:160],
            remediation="Advertise a real CUPS Server version string",
            fidelity="medium",
            requires_corroboration=server_requires if server_hit else False,
        ),
        Indicator(
            id="ipp.path_facade",
            title="IPP/CUPS answers unknown paths with a root-shaped 200",
            category="static_signature",
            triggered=path_hit,
            skipped=path_skipped,
            skip_reason=path_err if path_skipped else "",
            protocol="ipp",
            detail=path_detail,
            evidence=path_body[:128].hex() if path_body else "",
            remediation="Return 404/401 for unknown admin paths",
            fidelity="high",
            error=path_err,
        ),
        Indicator(
            id="ipp.method_stub",
            title="IPP/CUPS ignores DELETE on / (method stub)",
            category="static_signature",
            triggered=method_hit,
            skipped=method_skipped,
            skip_reason=del_err if method_skipped else "",
            protocol="ipp",
            detail=method_detail,
            evidence=del_body[:128].hex() if del_body else "",
            remediation="Reject unsupported HTTP methods on the CUPS root",
            fidelity="high",
            error=del_err,
        ),
        Indicator(
            id="ipp.printers_stub",
            title="IPP/CUPS /printers is a stub or root echo",
            category="static_signature",
            triggered=printers_hit,
            skipped=printers_skipped,
            skip_reason=pr_err if printers_skipped else "",
            protocol="ipp",
            detail=printers_detail,
            evidence=pr_body[:128].hex() if pr_body else "",
            remediation="Serve a real /printers listing or auth challenge",
            fidelity="medium",
            error=pr_err,
        ),
        Indicator(
            id="ipp.admin_open",
            title="IPP/CUPS /admin is open without authentication",
            category="static_signature",
            triggered=admin_hit,
            skipped=admin_skipped,
            skip_reason=ad_err if admin_skipped else "",
            protocol="ipp",
            detail=admin_detail,
            evidence=ad_body[:128].hex() if ad_body else "",
            remediation="Require authentication on /admin",
            fidelity="medium",
            requires_corroboration=admin_requires if admin_hit else False,
            error=ad_err,
        ),
        Indicator(
            id="ipp.frozen_date",
            title="IPP/CUPS Date header is missing or frozen across GETs",
            category="static_signature",
            triggered=frozen_hit,
            skipped=frozen_skipped,
            skip_reason=frozen_detail if frozen_skipped else "",
            protocol="ipp",
            detail=frozen_detail,
            evidence=f"{date1}|{date2}",
            remediation="Emit a fresh Date header on each HTTP response",
            fidelity="medium",
            requires_corroboration=frozen_requires if frozen_hit else False,
        ),
        Indicator(
            id="ipp.ipp_framing",
            title="IPP POST does not return an application/ipp body",
            category="static_signature",
            triggered=ipp_hit,
            skipped=ipp_skipped,
            skip_reason=i1_err if ipp_skipped else "",
            protocol="ipp",
            detail=ipp_detail,
            evidence=i1_body[:128].hex() if i1_body else "",
            remediation="Answer Get-Printer-Attributes with application/ipp",
            fidelity="high",
            error=i1_err,
        ),
        Indicator(
            id="ipp.ghost_printer",
            title="IPP Get-Printer-Attributes succeeds for a nonexistent printer",
            category="static_signature",
            triggered=ghost_hit,
            skipped=ghost_skipped,
            skip_reason=ghost_detail if ghost_skipped else "",
            protocol="ipp",
            detail=ghost_detail,
            evidence=i1_body[:16].hex() if i1_body else "",
            remediation="Return client-error-not-found for unknown printer-uri",
            fidelity="high",
        ),
        Indicator(
            id="ipp.request_id",
            title="IPP response request-id does not echo the request",
            category="static_signature",
            triggered=rid_hit,
            skipped=rid_skipped,
            skip_reason=rid_detail if rid_skipped else "",
            protocol="ipp",
            detail=rid_detail,
            evidence="",
            remediation="Echo the request-id from each IPP request in the response",
            fidelity="high",
        ),
        Indicator(
            id="ipp.ipp_clone",
            title="IPP replies are bitwise-identical across distinct request-ids",
            category="static_signature",
            triggered=clone_hit,
            skipped=clone_skipped,
            skip_reason=clone_detail if clone_skipped and not clone_hit else "",
            protocol="ipp",
            detail=clone_detail,
            evidence="",
            remediation="Echo distinct request-ids and attribute sets per IPP request",
            fidelity="decisive",
        ),
        Indicator(
            id="ipp.illegal_op",
            title="IPP accepts an illegal operation-id",
            category="static_signature",
            triggered=illegal_hit,
            skipped=illegal_skipped,
            skip_reason=illegal_detail if illegal_skipped else "",
            protocol="ipp",
            detail=illegal_detail,
            evidence="",
            remediation="Reject unknown IPP operation-ids with a client/server error status",
            fidelity="high",
        ),
        Indicator(
            id="ipp.stock_body",
            title="IPP/CUPS HTML body matches a stock honeypot lure",
            category="static_signature",
            triggered=body_hit,
            protocol="ipp",
            detail=body_detail or "no stock body lure",
            evidence=root_body[:160].hex(),
            remediation="Avoid canned honeypot phrases in the CUPS web UI",
            fidelity="medium",
            requires_corroboration=body_requires if body_hit else False,
        ),
    ]
