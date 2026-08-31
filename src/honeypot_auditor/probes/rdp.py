"""RDP fingerprint engine.

Strategies: static signature (canned NLA cookie) · state non-persistence
(second packet is canned negotiation failure). Arbitrary auth is not on the
basic path (deny-all is also a real NLA server with the wrong password).
"""

from __future__ import annotations

from honeypot_auditor.config import match_rdp_canned_nla, match_rdp_neg_fail
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_roundtrips
from honeypot_auditor.probes.common import skip_suite

_RDP_SKIP = (
    ("rdp.signature", "RDP first reply is a canned NLA template", "static_signature"),
    ("rdp.persist", "RDP second packet is a canned negotiation failure", "state_nonpersist"),
)

# Minimal TPKT + X.224 Connection Request (any first write is enough for the lure).
_RDP_CR = bytes.fromhex("030000130ee000000000000100080000000000")


def probe_rdp(host: str, port: int) -> list[Indicator]:
    replies, err = tcp_roundtrips(host, port, [_RDP_CR, b"\x00"])
    if err and not replies:
        return skip_suite(_RDP_SKIP, closed_reason(err), protocol="rdp", error=err)
    first = replies[0] if replies else b""
    second = replies[1] if len(replies) > 1 else b""
    if not first:
        return skip_suite(_RDP_SKIP, closed_reason(err) if err else "not an RDP speaker", protocol="rdp", error=err)
    nla_hit = match_rdp_canned_nla(first)
    fail_hit = match_rdp_neg_fail(second)
    return [
        Indicator(
            id="rdp.signature",
            title="RDP first reply is a canned NLA template",
            category="static_signature",
            triggered=bool(nla_hit),
            protocol="rdp",
            detail=nla_hit or f"{len(first)} byte RDP reply",
            evidence=first[:80].hex(),
        ),
        Indicator(
            id="rdp.persist",
            title="RDP second packet is a canned negotiation failure",
            category="state_nonpersist",
            triggered=bool(fail_hit),
            protocol="rdp",
            detail=fail_hit or (f"{len(second)} byte follow-up" if second else "no second RDP reply"),
            evidence=(second[:80].hex() if second else ""),
        ),
    ]
