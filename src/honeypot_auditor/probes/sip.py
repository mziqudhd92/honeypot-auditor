"""SIP fingerprint engine.

Strategies: static signature (default User-Agent template). Arbitrary auth and state non-persistence are not on the basic path.
"""

from __future__ import annotations

import secrets

from honeypot_auditor.config import SIP_UA_TELLS, USER_AGENT
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact, udp_transact


def probe_sip(host: str, port: int) -> list[Indicator]:
    call_id = secrets.token_hex(6)
    probe = (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bKhpaudit;rport\r\n"
        f"From: <sip:auditor@invalid>;tag=hpaudit\r\n"
        f"To: <sip:{host}>\r\n"
        f"Call-ID: hpaudit-{call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Contact: <sip:auditor@0.0.0.0:5060>\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode()
    raw, err = udp_transact(host, port, probe)
    if err and not raw:
        raw, err = tcp_transact(host, port, probe)
    if err and not raw:
        return [
            skipped_indicator(
                "sip.user_agent",
                "SIP User-Agent matches a default template",
                "static_signature",
                closed_reason(err),
                protocol="sip",
                error=err,
            )
        ]
    text = raw.decode("latin-1", "replace")
    ua = ""
    for line in text.split("\r\n"):
        if line.lower().startswith("user-agent:"):
            ua = line.split(":", 1)[1].strip()
            break
    hit = bool(ua) and any(tell in ua.lower() for tell in SIP_UA_TELLS)
    return [
        Indicator(
            id="sip.user_agent",
            title="SIP User-Agent matches a default template",
            category="static_signature",
            triggered=hit,
            protocol="sip",
            detail=f"User-Agent: {ua or '(missing)'}",
            evidence=text[:600],
        )
    ]
