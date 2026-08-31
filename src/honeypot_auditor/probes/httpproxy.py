"""HTTP proxy fingerprint engine.

Strategies: static signature (407 Via localhost / frozen squid / ISA deny).
Arbitrary auth and state non-persistence are not on the basic path
(deny-all 407 is also a real proxy requiring credentials).
"""

from __future__ import annotations

from honeypot_auditor.config import match_http_proxy_lure
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import skip_suite

_PROXY_SKIP = (
    ("httpproxy.signature", "HTTP proxy 407 looks like a stock lure", "static_signature"),
)


def probe_httpproxy(host: str, port: int) -> list[Indicator]:
    req = (
        b"GET http://example.invalid/ HTTP/1.1\r\n"
        b"Host: example.invalid\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    raw, err = tcp_transact(host, port, req)
    if err and not raw:
        return skip_suite(_PROXY_SKIP, closed_reason(err), protocol="httpproxy", error=err)
    text = raw.decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0] if text else ""
    if not first.startswith("HTTP/"):
        return skip_suite(_PROXY_SKIP, "not an HTTP proxy speaker", protocol="httpproxy")
    hit = match_http_proxy_lure(text)
    return [
        Indicator(
            id="httpproxy.signature",
            title="HTTP proxy 407 looks like a stock lure",
            category="static_signature",
            triggered=bool(hit),
            protocol="httpproxy",
            detail=hit or (first[:160] or "(no status line)"),
            evidence=text.split("\r\n\r\n", 1)[0][:600],
        )
    ]
