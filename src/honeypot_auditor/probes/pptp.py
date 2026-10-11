"""PPTP control-channel fingerprint engine (RFC 2637).

Five detection checks across the three basic strategies (non-destructive —
control plane on TCP/1723 only; never GRE / PPP / CHAP):

  · static_signature  — framing, protocol-version facade, unknown-control stub
  · state_nonpersist  — Echo-Request Identifier must be echoed in Echo-Reply
  · arbitrary_auth    — dual entropy-varied Outgoing-Call-Requests answered
    Result=1 without the Peer's Call-ID echo (or with a hollow server Call ID).
    Pre-auth call establishment alone is RFC 2637-honest — real concentrators
    accept OCRQ before PPP authentication runs inside the GRE tunnel.

TCP/1723 (lab 11723). See docs/strategies/pptp/.
"""

from __future__ import annotations

import secrets
import struct
from typing import cast

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_roundtrips, tcp_transact
from honeypot_auditor.probes.common import is_safe_mode, jittered_reconnect_pause

PPTP_MAGIC = 0x1A2B3C4D
PPTP_MSG_CONTROL = 1
PPTP_VERSION = 0x0100

CTRL_SCCRQ = 1
CTRL_SCCRP = 2
CTRL_ECHO_REQ = 5
CTRL_ECHO_REP = 6
CTRL_OCRQ = 7
CTRL_OCRP = 8
CTRL_GARBAGE = 0x0077  # reserved / unused — real stacks should not SCCRP this

_PPTP_SKIP = (
    (
        "pptp.framing",
        "PPTP Start-Control-Connection-Reply framing is invalid",
        "static_signature",
    ),
    (
        "pptp.version_facade",
        "PPTP protocol version is not RFC 2637 0x0100",
        "static_signature",
    ),
    (
        "pptp.echo_id",
        "PPTP Echo-Reply Identifier does not echo the request",
        "state_nonpersist",
    ),
    (
        "pptp.call_facade",
        "PPTP accepts dual entropy-varied Outgoing-Call-Requests",
        "arbitrary_auth",
    ),
    (
        "pptp.control_stub",
        "PPTP answers unknown control types like a successful SCCRP",
        "static_signature",
    ),
)

_STOCK_VENDOR_TOKENS = (
    "honeypot",
    "pptp honeypot",
    "fake pptp",
    "dionaea",
    "opencanary",
    "conpot",
    "honeytrap",
    "softether honeypot",
)


def _pad64(text: str) -> bytes:
    raw = text.encode("ascii", "replace")[:64]
    return raw.ljust(64, b"\x00")


def build_sccrq(
    *,
    hostname: str = "hpaudit",
    vendor: str = "honeypot-auditor",
    framing: int = 1,
    bearer: int = 1,
) -> bytes:
    """Start-Control-Connection-Request (156 bytes)."""
    return struct.pack(
        "!HHIHHHHIIHH64s64s",
        156,
        PPTP_MSG_CONTROL,
        PPTP_MAGIC,
        CTRL_SCCRQ,
        0,
        PPTP_VERSION,
        0,
        framing,
        bearer,
        0,
        1,
        _pad64(hostname),
        _pad64(vendor),
    )


def build_echo_request(identifier: int) -> bytes:
    """Echo-Request (16 bytes)."""
    return struct.pack(
        "!HHIHHI",
        16,
        PPTP_MSG_CONTROL,
        PPTP_MAGIC,
        CTRL_ECHO_REQ,
        0,
        identifier & 0xFFFFFFFF,
    )


def build_ocrq(*, call_id: int, phone: str) -> bytes:
    """Outgoing-Call-Request (168 bytes) with entropy-varied phone number."""
    phone_b = phone.encode("ascii", "replace")[:64]
    phone_len = min(len(phone_b), 64)
    phone_field = phone_b.ljust(64, b"\x00")
    subaddr = b"\x00" * 64
    return struct.pack(
        "!HHIHHHHIIIIHHHH64s64s",
        168,
        PPTP_MSG_CONTROL,
        PPTP_MAGIC,
        CTRL_OCRQ,
        0,
        call_id & 0xFFFF,
        secrets.randbelow(0xFFFF) + 1,
        2400,  # min BPS
        1_000_000,  # max BPS
        1,  # bearer analog
        1,  # framing async
        10,  # recv window
        0,  # processing delay
        phone_len,
        0,
        phone_field,
        subaddr,
    )


def build_unknown_control() -> bytes:
    """Minimal control datagram with an unused Control Message Type."""
    return struct.pack(
        "!HHIHH",
        12,
        PPTP_MSG_CONTROL,
        PPTP_MAGIC,
        CTRL_GARBAGE,
        0,
    )


def parse_control_header(data: bytes) -> dict[str, int] | None:
    """Parse the common 12-byte PPTP control header; ``None`` if not PPTP."""
    if len(data) < 12:
        return None
    length, msg_type, magic, ctrl, _reserved = struct.unpack_from("!HHIHH", data, 0)
    if magic != PPTP_MAGIC or msg_type != PPTP_MSG_CONTROL:
        return None
    if length < 12 or length > 2048:
        return None
    return {
        "length": length,
        "msg_type": msg_type,
        "magic": magic,
        "control": ctrl,
    }


def parse_sccrp(data: bytes) -> dict[str, object] | None:
    """Parse Start-Control-Connection-Reply fields used by the probe."""
    hdr = parse_control_header(data)
    if hdr is None or hdr["control"] != CTRL_SCCRP:
        return None
    if len(data) < 28:
        return None
    version = struct.unpack_from("!H", data, 12)[0]
    result, error = struct.unpack_from("!BB", data, 14)
    hostname = data[28:92].split(b"\x00", 1)[0].decode("latin-1", "replace") if len(data) >= 92 else ""
    vendor = data[92:156].split(b"\x00", 1)[0].decode("latin-1", "replace") if len(data) >= 156 else ""
    return {
        **hdr,
        "version": version,
        "result": result,
        "error": error,
        "hostname": hostname,
        "vendor": vendor,
    }


def parse_echo_reply(data: bytes) -> dict[str, int] | None:
    hdr = parse_control_header(data)
    if hdr is None or hdr["control"] != CTRL_ECHO_REP:
        return None
    if len(data) < 16:
        return None
    identifier = struct.unpack_from("!I", data, 12)[0]
    result = data[16] if len(data) > 16 else -1
    return {**hdr, "identifier": identifier, "result": result}


def parse_ocrp(data: bytes) -> dict[str, int] | None:
    hdr = parse_control_header(data)
    if hdr is None or hdr["control"] != CTRL_OCRP:
        return None
    if len(data) < 16:
        return None
    # Call ID (2) + Peer's Call ID (2) + Result (1) + Error (1) …
    call_id, peer_call_id = struct.unpack_from("!HH", data, 12)
    result = data[16] if len(data) > 16 else -1
    return {
        **hdr,
        "call_id": call_id,
        "peer_call_id": peer_call_id,
        "result": result,
    }


def _stock_hit(text: str) -> str:
    lowered = text.lower()
    for token in _STOCK_VENDOR_TOKENS:
        if token in lowered:
            return token
    return ""


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
        protocol="pptp",
        detail=detail,
        evidence=evidence,
        fidelity=fidelity,
        requires_corroboration=requires_corroboration,
        remediation=(
            "Speak RFC 2637 PPTP honestly: SCCRP version 0x0100, echo Echo "
            "Identifiers, reject unknown control types, and do not accept "
            "arbitrary Outgoing-Call-Requests"
        ),
    )


def _spec(ind_id: str) -> tuple[str, str, str]:
    for row in _PPTP_SKIP:
        if row[0] == ind_id:
            return row
    raise KeyError(ind_id)


def _framing_fail_suite(data: bytes, detail: str) -> list[Indicator]:
    out: list[Indicator] = []
    reason = "not a PPTP control speaker"
    for spec in _PPTP_SKIP:
        if spec[0] == "pptp.framing":
            out.append(
                _ind(
                    spec,
                    triggered=True,
                    detail=detail,
                    evidence=data[:64].hex(),
                    fidelity="high",
                )
            )
        else:
            out.append(skipped_indicator(*spec, reason, protocol="pptp"))
    return out


def _call_fabricated(data: bytes, *, our_call_id: int) -> tuple[bool, str]:
    """Classify an OCRP against RFC 2637 call semantics.

    Real concentrators establish calls pre-auth (Result=1 arrives before PPP
    authentication), but they echo our Call ID in Peer's Call ID and assign
    their own non-zero Call ID. Result=1 without the echo — or with a hollow
    zero Call ID — is the fabricated-acceptance tell; honest acceptance and
    denial both stay clean.
    """
    ocrp = parse_ocrp(data)
    if ocrp is None:
        return False, "no OCRP"
    if ocrp["result"] != 1:
        return False, f"denied (result={ocrp['result']})"
    if ocrp["peer_call_id"] != our_call_id:
        return True, (
            f"accepted without Peer's Call-ID echo "
            f"(peer={ocrp['peer_call_id']}, sent {our_call_id})"
        )
    if ocrp["call_id"] == 0:
        return True, "accepted with hollow server Call ID=0"
    return False, f"established (server Call ID={ocrp['call_id']}, peer echoed)"


def probe_pptp(host: str, port: int) -> list[Indicator]:
    # 1) Baseline SCCRQ — speakership / version / stock vendor strings.
    sccrq = build_sccrq()
    baseline, err = tcp_transact(host, port, sccrq)
    if err and not baseline:
        return [
            skipped_indicator(*spec, closed_reason(err), protocol="pptp", error=err)
            for spec in _PPTP_SKIP
        ]

    sccrp = parse_sccrp(baseline)
    if sccrp is None:
        hdr = parse_control_header(baseline)
        detail = (
            f"reply was not SCCRP (control={hdr['control'] if hdr else 'n/a'}, "
            f"{len(baseline)} bytes)"
        )
        return _framing_fail_suite(baseline, detail)

    framing_detail = (
        f"SCCRP result={sccrp['result']} error={sccrp['error']} "
        f"host={sccrp['hostname']!r} vendor={sccrp['vendor']!r}"
    )
    evidence = baseline[:80].hex()

    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        out: list[Indicator] = []
        for spec in _PPTP_SKIP:
            if spec[0] == "pptp.framing":
                out.append(
                    _ind(
                        spec,
                        triggered=False,
                        detail=framing_detail,
                        evidence=evidence,
                    )
                )
            else:
                out.append(skipped_indicator(*spec, reason, protocol="pptp"))
        return out

    version = cast(int, sccrp["version"])
    version_hit = version != PPTP_VERSION
    version_detail = (
        f"protocol version 0x{version:04x} (expected 0x{PPTP_VERSION:04x})"
        if version_hit
        else f"protocol version 0x{version:04x}"
    )
    stock = _stock_hit(f"{sccrp['hostname']} {sccrp['vendor']}")
    if stock:
        # Stock lure tokens corroborate version facade when version is also wrong;
        # alone they stay medium and corroboration-gated (version_requires below).
        if not version_hit:
            version_hit = True
            version_detail = f"stock lure token {stock!r} in hostname/vendor"
        else:
            version_detail = f"{version_detail}; stock lure token {stock!r}"

    # Prefer decisive version mismatch; stock-only needs corroboration.
    version_requires = bool(stock) and version == PPTP_VERSION

    # 2) Same session: Echo-Request + OCRQ #1 + unknown control.
    echo_id = secrets.randbelow(0x7FFFFFFF) + 1
    phone_a = f"+1555{secrets.token_hex(3)}"
    call_a = secrets.randbelow(0x7FFF) + 1
    replies, sess_err = tcp_roundtrips(
        host,
        port,
        [
            sccrq,
            build_echo_request(echo_id),
            build_ocrq(call_id=call_a, phone=phone_a),
            build_unknown_control(),
        ],
    )
    # replies: [SCCRP, Echo-Reply?, OCRP?, stub?]
    echo_raw = replies[1] if len(replies) > 1 else b""
    ocrp_a = replies[2] if len(replies) > 2 else b""
    stub_raw = replies[3] if len(replies) > 3 else b""

    echo_hit = False
    echo_detail = "no Echo-Reply"
    echo_rep = parse_echo_reply(echo_raw)
    if echo_rep is not None:
        got_id = int(echo_rep["identifier"])
        if got_id != echo_id:
            echo_hit = True
            echo_detail = f"Echo Identifier mismatch: sent {echo_id}, got {got_id}"
        else:
            echo_detail = f"Echo Identifier echoed ({echo_id})"
    elif echo_raw:
        # Wrong control type or framing on echo path — treat as state lie when
        # speaker already proved SCCRP (decoy that ignores echo semantics).
        echo_hit = True
        echo_detail = f"Echo-Request answered with non-Echo-Reply ({len(echo_raw)} bytes)"
    elif sess_err and not echo_raw:
        echo_detail = f"Echo-Request unanswered ({closed_reason(sess_err)}; ok)"

    call_a_fab, call_a_note = _call_fabricated(ocrp_a, our_call_id=call_a)

    stub_hit = False
    stub_detail = "unknown control unanswered (ok)"
    if stub_raw:
        stub_sccrp = parse_sccrp(stub_raw)
        stub_hdr = parse_control_header(stub_raw)
        if stub_sccrp is not None and cast(int, stub_sccrp["result"]) == 1:
            stub_hit = True
            stub_detail = "unknown control type answered with successful SCCRP"
        elif stub_hdr is not None and stub_hdr["control"] == CTRL_SCCRP:
            stub_hit = True
            stub_detail = "unknown control type answered with SCCRP framing"
        elif stub_hdr is not None and stub_hdr["control"] == CTRL_GARBAGE:
            # Echoing the illegal type back as "success" is also a stub tell.
            stub_hit = True
            stub_detail = "unknown control type echoed with PPTP magic cookie"
        else:
            stub_detail = (
                f"unknown control reply control="
                f"{stub_hdr['control'] if stub_hdr else 'n/a'} ({len(stub_raw)} bytes)"
            )

    # 3) Reconnect: second Outgoing-Call with distinct phone (arbitrary_auth).
    jittered_reconnect_pause()
    phone_b = f"+1555{secrets.token_hex(3)}"
    call_b = secrets.randbelow(0x7FFF) + 1
    while phone_b == phone_a:
        phone_b = f"+1555{secrets.token_hex(3)}"
    replies_b, _err_b = tcp_roundtrips(
        host,
        port,
        [build_sccrq(), build_ocrq(call_id=call_b, phone=phone_b)],
    )
    ocrp_b = replies_b[1] if len(replies_b) > 1 else b""
    call_b_fab, call_b_note = _call_fabricated(ocrp_b, our_call_id=call_b)

    # Both sessions must show fabricated acceptance; honest pre-auth
    # establishment (peer echo + non-zero server Call ID) stays clean.
    call_hit = bool(call_a_fab and call_b_fab)
    call_detail = (
        (
            f"Outgoing-Call-Requests for {phone_a!r} and {phone_b!r} both accepted "
            f"with fabricated call semantics ({call_a_note}; {call_b_note})"
        )
        if call_hit
        else f"call_a: {call_a_note}; call_b: {call_b_note}"
    )

    return [
        _ind(
            _spec("pptp.framing"),
            triggered=False,
            detail=framing_detail,
            evidence=evidence,
            fidelity="high",
        ),
        _ind(
            _spec("pptp.version_facade"),
            triggered=version_hit,
            detail=version_detail,
            evidence=evidence,
            fidelity="medium" if version_requires else "high",
            requires_corroboration=version_requires,
        ),
        _ind(
            _spec("pptp.echo_id"),
            triggered=echo_hit,
            detail=echo_detail,
            evidence=(echo_raw[:40].hex() if echo_raw else ""),
            fidelity="high",
        ),
        _ind(
            _spec("pptp.call_facade"),
            triggered=call_hit,
            detail=call_detail,
            evidence=(ocrp_a[:24] + ocrp_b[:24]).hex(),
            fidelity="high",
        ),
        _ind(
            _spec("pptp.control_stub"),
            triggered=stub_hit,
            detail=stub_detail,
            evidence=(stub_raw[:40].hex() if stub_raw else ""),
            fidelity="high",
        ),
    ]


__all__ = [
    "PPTP_MAGIC",
    "build_echo_request",
    "build_ocrq",
    "build_sccrq",
    "build_unknown_control",
    "parse_control_header",
    "parse_echo_reply",
    "parse_ocrp",
    "parse_sccrp",
    "probe_pptp",
    "_PPTP_SKIP",
]
