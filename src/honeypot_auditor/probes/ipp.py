"""IPP/CUPS HTTP + light IPP fingerprint engine.

Protocol non-compliance strategies (read-only — never print, pause, or
reconfigure queues):
  · static_signature — CUPS root framing; stock Server header lures; unknown-path
    facade; DELETE method stub; /printers stub; IPP Content-Type framing;
    bitwise-identical canned IPP replies; stock HTML/body lures
  · framing — GET ``/`` is not a CUPS/HTTP print-service speaker

Ports 631 / lab 1631 (HTTP to CUPS). IPP-over-HTTPS (631 TLS-only) uses the same
HTTP exchange path when the peer speaks cleartext HTTP on the probed port.

See docs/IPP.md, RFC 8010/8011 (IPP), and CUPS HTTP admin surface.
"""

from __future__ import annotations

import re
import secrets
import struct

from honeypot_auditor.config import effective_user_agent
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import is_safe_mode, skip_suite
from honeypot_auditor.settings import settings

_IPP_SKIP = (
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
        "ipp.ipp_framing",
        "IPP POST does not return an application/ipp body",
        "static_signature",
    ),
    (
        "ipp.ipp_clone",
        "IPP replies are bitwise-identical across distinct request-ids",
        "static_signature",
    ),
    (
        "ipp.stock_body",
        "IPP/CUPS HTML body matches a stock honeypot lure",
        "static_signature",
    ),
)

_SAFE_ONLY = frozenset({"ipp.root_framing"})

# Decisive Server tokens — rare outside decoys.
_STOCK_SERVER_DECISIVE = (
    "honeypot",
    "fake-cups",
    "cups-honeypot",
    "printer-honeypot",
    "opencanary",
)
# Frozen / generic CUPS versions — corroboration-gated alone.
_STOCK_SERVER_GENERIC = (
    "cups/1.1",
    "cups/1.2",
    "cups/1.3",
    "cups/1.4.2",
    "cups/1.4.3",
    "cups/1.4.4",
    "cups/1.4.6",
)

_STOCK_BODY_DECISIVE = (
    "honeypot printer",
    "fake cups",
    "cups honeypot",
    "opencanary",
    "this is not a real printer",
)
_STOCK_BODY_GENERIC = (
    "welcome to cups",
    "web interface is currently disabled",
    "no printers found",
)

_CUPS_HINT_RE = re.compile(
    rb"(cups|ipp|printer|print.?job|/admin|/printers)",
    re.IGNORECASE,
)


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


def _is_cups_root(status: int, headers: dict[str, str], body: bytes) -> bool:
    """True when the peer looks like a CUPS/IPP HTTP face."""
    if status == 0:
        return False
    server = (headers.get("server") or "").lower()
    if "cups" in server or "ipp" in server:
        return True
    if status in {200, 301, 302, 401, 403} and _CUPS_HINT_RE.search(body[:4096] or b""):
        return True
    # Some CUPS builds redirect / to /admin with empty body.
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


def _is_ipp_binary(body: bytes) -> bool:
    """IPP/1.x responses start with version (0x01xx) then status-code."""
    return len(body) >= 8 and body[0] == 0x01 and body[1] in {0x00, 0x01}


def _build_get_printer_attributes(request_id: int, printer_uri: str) -> bytes:
    """Minimal IPP 1.1 Get-Printer-Attributes (RFC 8010/8011)."""
    # version 1.1, operation 0x000B, request-id
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

    _write_attr(0x47, "attributes-charset", "utf-8")  # charset
    _write_attr(0x48, "attributes-natural-language", "en")  # naturalLanguage
    _write_attr(0x45, "printer-uri", printer_uri)  # uri
    _write_attr(0x44, "requested-attributes", "all")  # keyword
    out.append(0x03)  # end-of-attributes
    return bytes(out)


def _printers_is_stub(status: int, body: bytes, root_body: bytes) -> bool:
    if status == 200 and body and root_body and body == root_body:
        return True
    if status == 200 and not body.strip():
        return True
    low = body[:4096].lower()
    # Empty queue pages that claim printers exist via a single canned row are weak;
    # treat decisive empty-queue honeypot phrases as stubs.
    if status == 200 and (
        (b"no printers" in low and b"honeypot" in low)
        or b"fake printer" in low
        or b"printer honeypot" in low
    ):
        return True
    return False


def probe_ipp(host: str, port: int) -> list[Indicator]:
    root_status, root_hdrs, root_body, root_err = _http_exchange(host, port, "GET", "/")
    if root_err and not root_body and root_status == 0:
        return skip_suite(_IPP_SKIP, root_err, protocol="ipp", error=root_err)

    framing_hit = not _is_cups_root(root_status, root_hdrs, root_body)
    framing_detail = (
        f"GET / status={root_status} is not a CUPS/IPP HTTP face "
        f"(server={root_hdrs.get('server', '')!r})"
        if framing_hit
        else (
            f"CUPS/IPP HTTP face status={root_status} "
            f"server={root_hdrs.get('server', '')!r}"
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
    path_status, _path_hdrs, path_body, path_err = _http_exchange(host, port, "GET", mystery)
    path_skipped = bool(path_err) and path_status == 0 and not path_body
    path_hit = False
    path_detail = "unknown-path handling not evaluated"
    if not path_skipped:
        if path_status in {404, 401, 403, 405, 501}:
            path_detail = f"compliant unknown-path handling (status={path_status})"
        elif path_status == 200 and path_body and root_body and path_body == root_body:
            path_hit = True
            path_detail = (
                f"GET {mystery} returned status=200 root-shaped body "
                "(unknown paths should not echo /)"
            )
        else:
            path_detail = f"GET {mystery} status={path_status}"

    del_status, _del_hdrs, del_body, del_err = _http_exchange(host, port, "DELETE", "/")
    method_skipped = bool(del_err) and del_status == 0 and not del_body
    method_hit = False
    method_detail = "DELETE / not evaluated"
    if not method_skipped:
        if del_status in {401, 403, 405, 501}:
            method_detail = f"DELETE / correctly rejected (status={del_status})"
        elif del_status == 200 and (
            (del_body and root_body and del_body == root_body) or del_status == root_status
        ):
            method_hit = True
            method_detail = (
                f"DELETE / returned status={del_status} like GET / "
                "(print faces should not ignore DELETE)"
            )
        else:
            method_detail = f"DELETE / status={del_status}"

    pr_status, _pr_hdrs, pr_body, pr_err = _http_exchange(host, port, "GET", "/printers")
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

    # Two IPP Get-Printer-Attributes with distinct request-ids.
    uri = f"ipp://{host}:{port}/printers/hpaudit-{secrets.token_hex(2)}"
    rid1 = (secrets.randbelow(0x7FFFFFFF) + 1) & 0xFFFFFFFF
    rid2 = (rid1 + 1) % 0x100000000 or 1
    ipp1 = _build_get_printer_attributes(rid1, uri)
    ipp2 = _build_get_printer_attributes(rid2, uri)
    i1_status, i1_hdrs, i1_body, i1_err = _http_exchange(
        host,
        port,
        "POST",
        "/ipp/print",
        extra_headers={"Content-Type": "application/ipp"},
        body=ipp1,
    )
    # Fallback path used by some CUPS builds.
    if i1_status in {0, 404} and not i1_body:
        i1_status, i1_hdrs, i1_body, i1_err = _http_exchange(
            host,
            port,
            "POST",
            "/",
            extra_headers={"Content-Type": "application/ipp"},
            body=ipp1,
        )
        ipp_path = "/"
    else:
        ipp_path = "/ipp/print"

    ipp_skipped = bool(i1_err) and i1_status == 0 and not i1_body
    ipp_hit = False
    ipp_detail = "IPP POST not evaluated"
    if not ipp_skipped:
        if i1_status == 200 and (_is_ipp_content_type(i1_hdrs) or _is_ipp_binary(i1_body)):
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

    clone_hit = False
    clone_detail = "IPP clone not evaluated"
    clone_skipped = ipp_skipped
    if not ipp_skipped and i1_body:
        i2_status, _i2_hdrs, i2_body, i2_err = _http_exchange(
            host,
            port,
            "POST",
            ipp_path,
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

    return [
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
