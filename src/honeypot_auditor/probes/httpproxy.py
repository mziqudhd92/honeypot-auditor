"""HTTP proxy fingerprint engine.

Strategies: arbitrary auth (Proxy-Authorization Basic façade), state
non-persistence (canned 407 / lost tunnel), static signature (407 lure /
silent TCP accept).
"""

from __future__ import annotations

import base64
import re

from honeypot_auditor.config import match_http_proxy_lure
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import (
    entropy_varied_creds,
    is_safe_mode,
    jittered_reconnect_pause,
    skip_suite,
)

_PROXY_SKIP = (
    (
        "httpproxy.arbitrary_auth",
        "HTTP proxy accepts two entropy-varied Proxy-Authorization Basic pairs",
        "arbitrary_auth",
    ),
    (
        "httpproxy.state_nonpersist",
        "HTTP proxy prior success becomes identical canned 407 on reconnect",
        "state_nonpersist",
    ),
    ("httpproxy.signature", "HTTP proxy 407 looks like a stock lure", "static_signature"),
    (
        "httpproxy.silent_accept",
        "HTTP proxy port TCP accepts then returns no response",
        "static_signature",
    ),
)

_STATUS_RE = re.compile(rb"^HTTP/\d\.\d\s+(\d{3})", re.IGNORECASE)


def _status(raw: bytes) -> int:
    m = _STATUS_RE.match(raw or b"")
    return int(m.group(1)) if m else 0


def _basic_header(user: str, password: str) -> bytes:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n".encode("ascii")


def _proxy_get(*, auth: bytes = b"") -> bytes:
    return (
        b"GET http://example.invalid/ HTTP/1.1\r\n"
        b"Host: example.invalid\r\n"
        + auth
        + b"Connection: close\r\n"
        b"\r\n"
    )


def _is_proxy_success(code: int) -> bool:
    """Proxy accepted the request (forwarded / served). 401/403/407 are denials."""
    return 200 <= code < 400


def probe_httpproxy(host: str, port: int) -> list[Indicator]:
    req = _proxy_get()
    raw, err = tcp_transact(host, port, req)
    if err and not raw:
        return skip_suite(_PROXY_SKIP, closed_reason(err), protocol="httpproxy", error=err)
    if not err and not raw:
        return [
            Indicator(
                id="httpproxy.arbitrary_auth",
                title="HTTP proxy accepts two entropy-varied Proxy-Authorization Basic pairs",
                category="arbitrary_auth",
                triggered=False,
                protocol="httpproxy",
                detail="no HTTP response (silent TCP accept)",
            ),
            Indicator(
                id="httpproxy.state_nonpersist",
                title="HTTP proxy prior success becomes identical canned 407 on reconnect",
                category="state_nonpersist",
                triggered=False,
                protocol="httpproxy",
                detail="no HTTP response (silent TCP accept)",
            ),
            Indicator(
                id="httpproxy.signature",
                title="HTTP proxy 407 looks like a stock lure",
                category="static_signature",
                triggered=False,
                protocol="httpproxy",
                detail="no HTTP response (silent TCP accept)",
            ),
            Indicator(
                id="httpproxy.silent_accept",
                title="HTTP proxy port TCP accepts then returns no response",
                category="static_signature",
                triggered=True,
                protocol="httpproxy",
                detail="TCP accept; proxy request sent; no HTTP bytes before timeout",
                remediation="Speak HTTP proxy or refuse the TCP connection; silent accepts look like tarpits",
            ),
        ]

    text = raw.decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0] if text else ""
    if not first.startswith("HTTP/"):
        return skip_suite(_PROXY_SKIP, "not an HTTP proxy speaker", protocol="httpproxy")

    if is_safe_mode():
        hit = match_http_proxy_lure(text)
        out: list[Indicator] = []
        for iid, title, cat in _PROXY_SKIP:
            if iid == "httpproxy.signature":
                out.append(
                    Indicator(
                        id=iid,
                        title=title,
                        category=cat,
                        triggered=bool(hit),
                        protocol="httpproxy",
                        detail=hit or (first[:160] or "(no status line)"),
                        evidence=text.split("\r\n\r\n", 1)[0][:600],
                    )
                )
            elif iid == "httpproxy.silent_accept":
                out.append(
                    Indicator(
                        id=iid,
                        title=title,
                        category=cat,
                        triggered=False,
                        protocol="httpproxy",
                        detail="HTTP status received",
                    )
                )
            else:
                out.extend(
                    skip_suite(
                        ((iid, title, cat),),
                        "safe-mode: handshake-only probe",
                        protocol="httpproxy",
                    )
                )
        return out

    baseline_code = _status(raw)
    low, high = entropy_varied_creds()
    successes = 0
    auth_notes: list[str] = []
    success_raw = b""
    for user, password in (low, high):
        a_raw, _ = tcp_transact(host, port, _proxy_get(auth=_basic_header(user, password)))
        code = _status(a_raw)
        if _is_proxy_success(code):
            successes += 1
            success_raw = a_raw
            auth_notes.append(f"{user}: {code}")
        else:
            auth_notes.append(f"{user}: {code or 'no-status'}")
    auth_hit = successes >= 2
    auth_detail = (
        "two entropy-varied Proxy-Authorization Basic pairs both allowed absolute-URI GET"
        if auth_hit
        else "; ".join(auth_notes) or "Proxy-Authorization rejected"
    )

    # --- state ---
    state_hit = False
    state_detail = "proxy auth/tunnel state looks consistent across reconnect"
    jittered_reconnect_pause()
    re_raw, _ = tcp_transact(host, port, _proxy_get())
    re_code = _status(re_raw)
    if auth_hit and re_code == 407:
        # Prior success becomes 407 façade.
        state_hit = True
        state_detail = "prior Proxy-Authorization success became 407 on reconnect"
    elif baseline_code == 407 and re_code == 407 and raw and re_raw and raw == re_raw:
        state_hit = True
        state_detail = "identical canned 407 across reconnects"
    elif _is_proxy_success(baseline_code) and re_code == 407:
        state_hit = True
        state_detail = "baseline proxy success became 407 façade after reconnect"
    elif auth_hit and success_raw and re_code == 407:
        state_hit = True
        state_detail = "tunnel/auth state gone inconsistently (success → 407)"

    hit = match_http_proxy_lure(text)
    return [
        Indicator(
            id="httpproxy.arbitrary_auth",
            title="HTTP proxy accepts two entropy-varied Proxy-Authorization Basic pairs",
            category="arbitrary_auth",
            triggered=auth_hit,
            protocol="httpproxy",
            detail=auth_detail,
            evidence="; ".join(auth_notes),
            fidelity="decisive" if auth_hit else "medium",
            remediation="Reject unknown Proxy-Authorization credentials with 407",
        ),
        Indicator(
            id="httpproxy.state_nonpersist",
            title="HTTP proxy prior success becomes identical canned 407 on reconnect",
            category="state_nonpersist",
            triggered=state_hit,
            protocol="httpproxy",
            detail=state_detail,
            evidence=f"baseline={baseline_code} reconnect={re_code}",
            fidelity="high" if state_hit else "medium",
            remediation="Keep proxy challenge/nonce state consistent; avoid bitwise-identical 407 templates",
        ),
        Indicator(
            id="httpproxy.signature",
            title="HTTP proxy 407 looks like a stock lure",
            category="static_signature",
            triggered=bool(hit),
            protocol="httpproxy",
            detail=hit or (first[:160] or "(no status line)"),
            evidence=text.split("\r\n\r\n", 1)[0][:600],
        ),
        Indicator(
            id="httpproxy.silent_accept",
            title="HTTP proxy port TCP accepts then returns no response",
            category="static_signature",
            triggered=False,
            protocol="httpproxy",
            detail="HTTP status received",
        ),
    ]
