"""SSDP / UPnP discovery fingerprint engine.

UPnP Device Architecture discovery strategies (non-destructive unicast M-SEARCH
only — never NOTIFY spam, multicast floods, or LOCATION HTTP fetch in v1):
  · static_signature — framing, header facade, ST echo, response clone,
    stock SERVER lure tokens (gated), LOCATION loopback, method stub

UDP/1900 (lab 11900). See docs/udp/SSDP.md.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urlparse

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, udp_exchange
from honeypot_auditor.probes.common import is_safe_mode
from honeypot_auditor.probes.udp._engine import UDPEngine

_SSDP_SKIP = (
    (
        "ssdp.framing",
        "SSDP response framing is invalid",
        "static_signature",
    ),
    (
        "ssdp.header_facade",
        "SSDP 200 OK is missing required discovery headers",
        "static_signature",
    ),
    (
        "ssdp.st_echo",
        "SSDP response ST does not echo the search target",
        "static_signature",
    ),
    (
        "ssdp.response_clone",
        "SSDP returns identical payloads for distinct M-SEARCH requests",
        "static_signature",
    ),
    (
        "ssdp.stock_server",
        "SSDP SERVER header matches a stock honeypot lure",
        "static_signature",
    ),
    (
        "ssdp.location_loopback",
        "SSDP LOCATION points at loopback / localhost",
        "static_signature",
    ),
    (
        "ssdp.method_stub",
        "SSDP answers non-M-SEARCH garbage with 200 OK",
        "static_signature",
    ),
)

_REQUIRED_200_HEADERS = ("server", "st", "usn", "location")

_STOCK_TOKENS = (
    "honeypot",
    "upnp honeypot",
    "fake upnp",
    "ssdp stub",
    "fake ssdp",
    "dionaea",
    "opencanary",
    "conpot",
    "honeytrap",
)

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


@dataclass(frozen=True)
class SsdpMessage:
    """Parsed SSDP / HTTP-like discovery datagram."""

    raw: bytes
    start_line: str
    headers: dict[str, str]  # lower-cased keys
    is_response: bool
    status_code: int | None


def build_msearch(host: str, port: int, *, st: str, mx: int = 1) -> bytes:
    """Build a unicast M-SEARCH discovery request."""
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {host}:{port}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {int(mx)}\r\n"
        f"ST: {st}\r\n"
        "\r\n"
    ).encode("ascii")


def build_ssdp_response(*, status: str = "HTTP/1.1 200 OK", headers: dict[str, str]) -> bytes:
    """Build an SSDP-shaped HTTP response (tests + helpers)."""
    lines = [status]
    for key, value in headers.items():
        if value == "":
            lines.append(f"{key}:")
        else:
            lines.append(f"{key}: {value}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("utf-8")


def parse_ssdp_message(data: bytes) -> SsdpMessage | None:
    """Parse an HTTP/1.x-shaped SSDP datagram; ``None`` if not SSDP-framed."""
    if not data:
        return None
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return None
    # Normalize rare LF-only stacks for header splitting; keep raw for clone checks.
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if "\n" not in normalized:
        return None
    start, rest = normalized.split("\n", 1)
    start = start.strip()
    if not start.upper().startswith("HTTP/"):
        # Requests are not scored as responses; still not a valid SSDP reply shape.
        if start.upper().startswith("M-SEARCH") or start.upper().startswith("NOTIFY"):
            return None
        return None
    headers: dict[str, str] = {}
    for line in rest.split("\n"):
        if line == "":
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    status_code: int | None = None
    parts = start.split()
    if len(parts) >= 2 and parts[1].isdigit():
        status_code = int(parts[1])
    return SsdpMessage(
        raw=data,
        start_line=start,
        headers=headers,
        is_response=True,
        status_code=status_code,
    )


def _stock_hit(text: str) -> str:
    lowered = text.lower()
    for token in _STOCK_TOKENS:
        if token in lowered:
            return token
    return ""


def _location_is_loopback(location: str) -> bool:
    if not location:
        return False
    try:
        parsed = urlparse(location)
    except Exception:
        return False
    host = (parsed.hostname or "").lower().strip("[]")
    return host in _LOOPBACK_HOSTS


def _ind(
    spec: tuple[str, str, str],
    *,
    triggered: bool,
    detail: str,
    evidence: str = "",
    fidelity: str = "high",
    requires_corroboration: bool = False,
) -> Indicator:
    ind_id, title, category = spec
    return Indicator(
        id=ind_id,
        title=title,
        category=category,
        triggered=triggered,
        protocol="ssdp",
        detail=detail,
        evidence=evidence,
        fidelity=fidelity,
        requires_corroboration=requires_corroboration,
        remediation=(
            "Speak UPnP discovery honestly: echo ST, advertise a reachable LOCATION, "
            "and ignore non-M-SEARCH datagrams"
        ),
    )


def _spec(ind_id: str) -> tuple[str, str, str]:
    for row in _SSDP_SKIP:
        if row[0] == ind_id:
            return row
    raise KeyError(ind_id)


def _framing_fail_suite(data: bytes, detail: str) -> list[Indicator]:
    out: list[Indicator] = []
    reason = "not an SSDP speaker"
    for spec in _SSDP_SKIP:
        if spec[0] == "ssdp.framing":
            out.append(
                _ind(
                    spec,
                    triggered=True,
                    detail=detail,
                    evidence=data[:256].hex(),
                    fidelity="high",
                )
            )
        else:
            out.append(skipped_indicator(*spec, reason, protocol="ssdp"))
    return out


def probe_ssdp(host: str, port: int) -> list[Indicator]:
    nonce = secrets.token_hex(4)
    st_primary = "upnp:rootdevice"
    st_secondary = f"urn:schemas-upnp-org:device:Hpaudit-{nonce}:1"

    # 1) Baseline M-SEARCH — speakership + header/ST/stock/location.
    baseline = udp_exchange(
        host,
        port,
        build_msearch(host, port, st=st_primary, mx=1),
        connected=False,
    )
    if baseline.error and not baseline.data:
        return [
            skipped_indicator(*spec, closed_reason(baseline.error), protocol="ssdp", error=baseline.error)
            for spec in _SSDP_SKIP
        ]

    base_msg = parse_ssdp_message(baseline.data)
    if base_msg is None or not base_msg.is_response:
        return _framing_fail_suite(
            baseline.data,
            f"UDP reply was not an HTTP/1.x SSDP response ({len(baseline.data)} bytes)",
        )

    framing_detail = f"SSDP {base_msg.start_line} peer_port={baseline.peer_port}"

    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        safe_out: list[Indicator] = []
        for spec in _SSDP_SKIP:
            if spec[0] == "ssdp.framing":
                safe_out.append(
                    _ind(
                        spec,
                        triggered=False,
                        detail=framing_detail,
                        evidence=baseline.data[:256].decode("latin-1", "replace"),
                    )
                )
            else:
                safe_out.append(skipped_indicator(*spec, reason, protocol="ssdp"))
        return safe_out

    # --- header_facade: 200 OK must carry SERVER/ST/USN/LOCATION ---
    missing = [name for name in _REQUIRED_200_HEADERS if name not in base_msg.headers]
    is_200 = base_msg.status_code == 200
    header_hit = is_200 and bool(missing)
    header_detail = (
        f"200 OK missing headers: {', '.join(missing)}"
        if header_hit
        else (
            f"status={base_msg.status_code} headers_present="
            f"{sorted(h for h in _REQUIRED_200_HEADERS if h in base_msg.headers)}"
        )
    )

    # --- st_echo on baseline ---
    resp_st = base_msg.headers.get("st", "")
    st_hit = False
    st_detail = f"request ST={st_primary!r} response ST={resp_st!r}"
    if is_200:
        if not resp_st:
            st_hit = True
            st_detail = f"200 OK missing ST (requested {st_primary!r})"
        elif resp_st.lower() != st_primary.lower():
            st_hit = True
            st_detail = f"ST mismatch: requested {st_primary!r}, got {resp_st!r}"

    # --- stock SERVER + LOCATION loopback (baseline) ---
    server = base_msg.headers.get("server", "")
    stock_token = _stock_hit(server)
    stock_hit = bool(stock_token)
    stock_detail = (
        f"stock lure token {stock_token!r} in SERVER"
        if stock_hit
        else f"SERVER={server!r}" if server else "no SERVER header"
    )

    location = base_msg.headers.get("location", "")
    loop_hit = _location_is_loopback(location)
    loop_detail = (
        f"LOCATION host is loopback ({location!r})"
        if loop_hit
        else f"LOCATION={location!r}" if location else "no LOCATION header"
    )

    # 2) Distinct M-SEARCH — clone + additional ST check.
    second = udp_exchange(
        host,
        port,
        build_msearch(host, port, st=st_secondary, mx=1),
        connected=False,
    )
    clone_hit = False
    clone_detail = "second M-SEARCH not compared"
    if second.data and not second.error:
        if second.data == baseline.data:
            clone_hit = True
            clone_detail = "bitwise-identical SSDP body for two distinct ST values"
        else:
            clone_detail = (
                f"distinct replies ({len(baseline.data)} vs {len(second.data)} bytes)"
            )
        second_msg = parse_ssdp_message(second.data)
        if second_msg is not None and second_msg.status_code == 200:
            second_st = second_msg.headers.get("st", "")
            if second_st.lower() != st_secondary.lower():
                st_hit = True
                st_detail = (
                    f"ST mismatch on secondary search: requested {st_secondary!r}, "
                    f"got {second_st!r}"
                )
            # Refresh stock/location from second reply if baseline was thin.
            if not stock_hit:
                stock_token = _stock_hit(second_msg.headers.get("server", ""))
                stock_hit = bool(stock_token)
                if stock_hit:
                    stock_detail = f"stock lure token {stock_token!r} in SERVER"
            if not loop_hit:
                loc2 = second_msg.headers.get("location", "")
                if _location_is_loopback(loc2):
                    loop_hit = True
                    loop_detail = f"LOCATION host is loopback ({loc2!r})"
                    location = loc2
    elif second.error and not second.data:
        clone_detail = f"no reply to secondary ST ({closed_reason(second.error)}; ok)"

    # 3) Method stub — garbage non-M-SEARCH must not earn 200 OK SSDP.
    garbage = (
        f"HPAUDIT * HTTP/1.1\r\nHOST: {host}:{port}\r\nContent-Length: 0\r\n\r\n"
    ).encode("ascii")
    stub_ex = udp_exchange(host, port, garbage, connected=False)
    stub_hit = False
    stub_detail = "non-M-SEARCH unanswered (ok)"
    if stub_ex.data and not stub_ex.error:
        stub_msg = parse_ssdp_message(stub_ex.data)
        if stub_msg is not None and stub_msg.status_code == 200:
            stub_hit = True
            stub_detail = f"garbage method answered with {stub_msg.start_line}"
        else:
            stub_detail = (
                f"non-SSDP reply to garbage ({len(stub_ex.data)} bytes)"
                if stub_msg is None
                else f"garbage reply {stub_msg.start_line}"
            )
    elif stub_ex.error:
        stub_detail = f"non-M-SEARCH unanswered ({closed_reason(stub_ex.error)}; ok)"

    evidence = baseline.data[:600].decode("latin-1", "replace")

    return [
        _ind(
            _spec("ssdp.framing"),
            triggered=False,
            detail=framing_detail,
            evidence=evidence,
            fidelity="high",
        ),
        _ind(
            _spec("ssdp.header_facade"),
            triggered=header_hit,
            detail=header_detail,
            evidence=evidence,
            fidelity="high",
        ),
        _ind(
            _spec("ssdp.st_echo"),
            triggered=st_hit,
            detail=st_detail,
            evidence=evidence,
            fidelity="high",
        ),
        _ind(
            _spec("ssdp.response_clone"),
            triggered=clone_hit,
            detail=clone_detail,
            evidence=evidence,
            fidelity="high",
        ),
        _ind(
            _spec("ssdp.stock_server"),
            triggered=stock_hit,
            detail=stock_detail,
            evidence=server[:200],
            fidelity="medium",
            requires_corroboration=True,
        ),
        _ind(
            _spec("ssdp.location_loopback"),
            triggered=loop_hit,
            detail=loop_detail,
            evidence=location[:200],
            fidelity="high",
        ),
        _ind(
            _spec("ssdp.method_stub"),
            triggered=stub_hit,
            detail=stub_detail,
            evidence=(stub_ex.data[:200].decode("latin-1", "replace") if stub_ex.data else ""),
            fidelity="high",
        ),
    ]


UDP_ENGINE = UDPEngine(name="ssdp", probe=probe_ssdp)

__all__ = [
    "UDP_ENGINE",
    "SsdpMessage",
    "build_msearch",
    "build_ssdp_response",
    "parse_ssdp_message",
    "probe_ssdp",
    "_SSDP_SKIP",
]
