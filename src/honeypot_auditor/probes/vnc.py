"""VNC fingerprint engine.

Strategies: static signature (RFB 3.8 VNC-auth only, canned Authentication failure,
generic desktop name) · state non-persistence (RFB auth always canned failure, no
desktop). Arbitrary auth is not on the basic path (deny-all is also a real VNC
with the wrong password).
"""

from __future__ import annotations

from honeypot_auditor.config import (
    match_vnc_auth_fail,
    match_vnc_invalid_security_challenge,
    match_vnc_vncauth_only,
)
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_roundtrips
from honeypot_auditor.probes.common import skip_suite

VNC_DESKTOP_TELLS = ("qemu", "raspberrypi", "localhost.localdomain")

_VNC_SKIP = (
    ("vnc.handshake", "VNC RFB handshake is a canned auth-fail lure", "static_signature"),
    ("vnc.persist", "VNC RFB auth always canned failure (no desktop)", "state_nonpersist"),
    ("vnc.security", "VNC accepts invalid security type 0", "static_signature"),
)


def probe_vnc(host: str, port: int) -> list[Indicator]:
    replies, err = tcp_roundtrips(
        host,
        port,
        [b"RFB 003.008\n", b"\x02", b"\x00" * 16],
        recv_first=True,
    )
    greeting = replies[0] if replies else b""
    if err and not greeting:
        return skip_suite(_VNC_SKIP, closed_reason(err), protocol="vnc", error=err)

    banner = greeting.decode("latin-1", "replace").split("\n", 1)[0].strip()
    if not banner.startswith("RFB "):
        return skip_suite(_VNC_SKIP, banner or "(no RFB banner)", protocol="vnc")

    security = replies[1] if len(replies) > 1 else b""
    fail = replies[3] if len(replies) > 3 else b""
    blob = greeting.decode("latin-1", "replace").lower()
    desktop_hit = any(tok in blob for tok in VNC_DESKTOP_TELLS)
    auth_only = match_vnc_vncauth_only(security)
    canned_fail = match_vnc_auth_fail(fail)
    type0_replies, _type0_err = tcp_roundtrips(
        host,
        port,
        [b"RFB 003.008\n", b"\x00"],
        recv_first=True,
    )
    after_type0 = type0_replies[2] if len(type0_replies) > 2 else b""
    type0_hit = match_vnc_invalid_security_challenge(after_type0)
    static_hits = [
        h
        for h in (
            auth_only,
            canned_fail,
            type0_hit,
            "generic desktop name" if desktop_hit else None,
        )
        if h
    ]
    return [
        Indicator(
            id="vnc.handshake",
            title="VNC RFB handshake is a canned auth-fail lure",
            category="static_signature",
            triggered=bool(static_hits),
            protocol="vnc",
            detail="; ".join(static_hits) if static_hits else banner[:120],
            evidence=(greeting + security + fail)[:400].decode("utf-8", "replace"),
        ),
        Indicator(
            id="vnc.persist",
            title="VNC RFB auth always canned failure (no desktop)",
            category="state_nonpersist",
            triggered=bool(canned_fail),
            protocol="vnc",
            detail=canned_fail or "RFB auth was not a canned Authentication failure",
            evidence=fail[:200].decode("utf-8", "replace"),
        ),
        Indicator(
            id="vnc.security",
            title="VNC accepts invalid security type 0",
            category="static_signature",
            triggered=bool(type0_hit),
            protocol="vnc",
            detail=type0_hit or "security type 0 did not produce a VNC-auth challenge",
            evidence=after_type0[:80].decode("utf-8", "replace"),
        ),
    ]
