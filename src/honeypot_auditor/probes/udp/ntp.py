"""NTP fingerprint engine (RFC 5905 client/server modes).

RFC non-compliance strategies (non-destructive mode-3 only — never monlist / mode-7):
  · arbitrary_auth / kod_absent — mode-3 burst still served with uniform mode-4
    (missing KoD RATE/DENY)
  · state_nonpersist — transmit/receive/reference timestamps fail monotonicity
  · static_signature — framing, mode/VN facade, originate echo, stratum facade,
    canned bitwise-identical replies, zeroed clock metrics, epoch-zero timestamps,
    stock lure refids

UDP/123 (lab 1123). NTPv4 client mode 3 → server mode 4.

See docs/udp/NTP.md, RFC 5905 §7.3 / §7.5 / §7.4.
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass

from honeypot_auditor import netutil
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason
from honeypot_auditor.probes.common import (
    is_safe_mode,
    jittered_reconnect_pause,
    rtt_evidence,
    skip_suite,
)
from honeypot_auditor.probes.udp._engine import UDPEngine

_NTP_SKIP = (
    (
        "ntp.kod_absent",
        "NTP mode-3 burst is served without KoD RATE/DENY",
        "arbitrary_auth",
    ),
    (
        "ntp.state_nonpersist",
        "NTP timestamps fail monotonicity across exchanges",
        "state_nonpersist",
    ),
    (
        "ntp.framing",
        "NTP response framing is invalid",
        "static_signature",
    ),
    (
        "ntp.mode_facade",
        "NTP answers with wrong mode or serves an invalid version",
        "static_signature",
    ),
    (
        "ntp.org_echo",
        "NTP originate timestamp does not echo the client transmit timestamp",
        "static_signature",
    ),
    (
        "ntp.stratum_facade",
        "NTP stratum is invalid for a serving reply",
        "static_signature",
    ),
    (
        "ntp.response_clone",
        "NTP returns bitwise-identical replies for distinct requests",
        "static_signature",
    ),
    (
        "ntp.zeroed_clock_metrics",
        "NTP root delay, dispersion, and reference timestamp are all zero",
        "static_signature",
    ),
    (
        "ntp.epoch_zero",
        "NTP reference/receive/transmit timestamps are at NTP or Unix epoch",
        "static_signature",
    ),
    (
        "ntp.stock_refid",
        "NTP reference ID matches a stock honeypot lure token",
        "static_signature",
    ),
)

_NTP_PACKET_LEN = 48
_MODE_CLIENT = 3
_MODE_SERVER = 4
_VN_V4 = 4
_VN_INVALID = 0

# Seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
_UNIX_EPOCH_NTP_SECONDS = 2_208_988_800

# RFC 5905 kiss codes (stratum 0 + ASCII refid) — compliant, not a facade.
_KISS_CODES = frozenset(
    {
        b"ACST",
        b"AUTH",
        b"AUTO",
        b"BCST",
        b"CRYP",
        b"DENY",
        b"DROP",
        b"RSTR",
        b"INIT",
        b"MCST",
        b"NKEY",
        b"RATE",
        b"RMOT",
        b"STEP",
    }
)

# Generic lure tokens only — no product honeypot brand names.
_STOCK_REFIDS = frozenset(
    {
        b"FAKE",
        b"HONE",
        b"TEST",
        b"DECO",
        b"STUB",
        b"MOCK",
        b"NULL",
    }
)


@dataclass(frozen=True)
class NtpPacket:
    li: int
    vn: int
    mode: int
    stratum: int
    poll: int
    precision: int
    root_delay: int
    root_dispersion: int
    reference_id: bytes
    reference_timestamp: int
    originate_timestamp: int
    receive_timestamp: int
    transmit_timestamp: int
    raw: bytes


def _li_vn_mode(li: int, vn: int, mode: int) -> int:
    return ((li & 0x3) << 6) | ((vn & 0x7) << 3) | (mode & 0x7)


def build_ntp_packet(
    *,
    li: int = 0,
    vn: int = _VN_V4,
    mode: int = _MODE_CLIENT,
    stratum: int = 0,
    poll: int = 4,
    precision: int = -6,
    root_delay: int = 0,
    root_dispersion: int = 0,
    reference_id: bytes = b"\x00\x00\x00\x00",
    reference_timestamp: int = 0,
    originate_timestamp: int = 0,
    receive_timestamp: int = 0,
    transmit_timestamp: int = 0,
) -> bytes:
    """Build a 48-byte NTP packet (no extension fields)."""
    refid = (reference_id + b"\x00\x00\x00\x00")[:4]
    precision_u8 = precision & 0xFF
    header = struct.pack(
        "!BBbBII4s",
        _li_vn_mode(li, vn, mode),
        stratum & 0xFF,
        poll if poll >= 0 else poll & 0xFF,
        precision_u8,
        root_delay & 0xFFFFFFFF,
        root_dispersion & 0xFFFFFFFF,
        refid,
    )
    stamps = struct.pack(
        "!QQQQ",
        reference_timestamp & 0xFFFFFFFFFFFFFFFF,
        originate_timestamp & 0xFFFFFFFFFFFFFFFF,
        receive_timestamp & 0xFFFFFFFFFFFFFFFF,
        transmit_timestamp & 0xFFFFFFFFFFFFFFFF,
    )
    return header + stamps


def build_client_request(
    *,
    vn: int = _VN_V4,
    mode: int = _MODE_CLIENT,
    transmit_timestamp: int | None = None,
) -> bytes:
    """NTPv4 client mode-3 request with a random (or provided) transmit timestamp."""
    xmt = (
        secrets.randbits(64)
        if transmit_timestamp is None
        else int(transmit_timestamp) & 0xFFFFFFFFFFFFFFFF
    )
    return build_ntp_packet(vn=vn, mode=mode, transmit_timestamp=xmt)


def parse_ntp_packet(data: bytes) -> NtpPacket | None:
    """Parse a ≥48-byte NTP datagram; returns None if too short."""
    if not data or len(data) < _NTP_PACKET_LEN:
        return None
    raw = data[:_NTP_PACKET_LEN]
    b0, stratum, poll, precision_u8, root_delay, root_dispersion, refid = struct.unpack(
        "!BBbBII4s", raw[:16]
    )
    ref_ts, org_ts, rec_ts, xmt_ts = struct.unpack("!QQQQ", raw[16:48])
    precision = precision_u8 if precision_u8 < 128 else precision_u8 - 256
    return NtpPacket(
        li=(b0 >> 6) & 0x3,
        vn=(b0 >> 3) & 0x7,
        mode=b0 & 0x7,
        stratum=stratum,
        poll=poll,
        precision=precision,
        root_delay=root_delay,
        root_dispersion=root_dispersion,
        reference_id=refid,
        reference_timestamp=ref_ts,
        originate_timestamp=org_ts,
        receive_timestamp=rec_ts,
        transmit_timestamp=xmt_ts,
        raw=raw,
    )


def _ts_seconds(ts: int) -> int:
    return (ts >> 32) & 0xFFFFFFFF


def _is_epoch_zero_ts(ts: int) -> bool:
    sec = _ts_seconds(ts)
    return sec == 0 or sec == _UNIX_EPOCH_NTP_SECONDS


def _is_kiss_code(refid: bytes) -> bool:
    return refid in _KISS_CODES


def _stock_refid_token(refid: bytes) -> str | None:
    if refid in _STOCK_REFIDS:
        return refid.rstrip(b"\x00").decode("ascii", "replace")
    # Also match ASCII lure substrings case-insensitively in the 4-byte field.
    low = refid.upper()
    for token in _STOCK_REFIDS:
        if token in low:
            return token.decode("ascii")
    return None


def _exchange(host: str, port: int, payload: bytes):
    ex = netutil.udp_exchange(host, port, payload, connected=False)
    if ex.error and not ex.data:
        return ex, None, closed_reason(ex.error)
    if not ex.data:
        return ex, None, "empty UDP reply"
    parsed = parse_ntp_packet(ex.data)
    return ex, parsed, ""


def _is_rate_deny_kod(msg: NtpPacket) -> bool:
    return (
        msg.stratum == 0
        and msg.mode == _MODE_SERVER
        and msg.reference_id in (b"RATE", b"DENY")
    )


def _timestamps_non_monotonic(msgs: list[NtpPacket]) -> tuple[bool, str]:
    """Hit when transmit/receive/reference are frozen or go backwards across exchanges."""
    if len(msgs) < 2:
        return False, "insufficient exchanges for monotonicity check"
    for field, label in (
        ("transmit_timestamp", "transmit"),
        ("receive_timestamp", "receive"),
        ("reference_timestamp", "reference"),
    ):
        vals = [getattr(m, field) for m in msgs]
        if len(set(vals)) == 1 and vals[0] != 0:
            return True, f"{label} timestamp frozen across {len(msgs)} exchanges ({vals[0]:#x})"
        for i in range(1, len(vals)):
            if vals[i] and vals[i - 1] and vals[i] < vals[i - 1]:
                return True, (
                    f"{label} timestamp went backwards "
                    f"({vals[i - 1]:#x} -> {vals[i]:#x})"
                )
    return False, "timestamps advance across exchanges"


def probe_ntp(host: str, port: int) -> list[Indicator]:
    # 1) Baseline NTPv4 client mode-3
    base_req = build_client_request()
    base_xmt = parse_ntp_packet(base_req)
    if base_xmt is None:
        raise RuntimeError("build_client_request produced an unparseable NTP packet")
    client_xmt = base_xmt.transmit_timestamp

    base_ex, base_msg, base_err = _exchange(host, port, base_req)
    if base_err and not base_ex.data:
        return skip_suite(_NTP_SKIP, base_err, protocol="ntp", error=base_err)

    if base_msg is None:
        reason = "not an NTP speaker"
        out: list[Indicator] = []
        for spec in _NTP_SKIP:
            if spec[0] == "ntp.framing":
                out.append(
                    Indicator(
                        id="ntp.framing",
                        title="NTP response framing is invalid",
                        category="static_signature",
                        triggered=True,
                        protocol="ntp",
                        detail=(
                            f"UDP reply was not a parseable ≥48-byte NTP packet "
                            f"({len(base_ex.data)} bytes)"
                        ),
                        evidence=base_ex.data[:64].hex(),
                        remediation="Return a 48-byte NTPv4 mode-4 response (RFC 5905)",
                        fidelity="high",
                    )
                )
            else:
                out.append(skipped_indicator(*spec, reason, protocol="ntp", error=base_err))
        return out

    framing_hit = False
    framing_detail = (
        f"NTPv{base_msg.vn} mode={base_msg.mode} stratum={base_msg.stratum} "
        f"({len(base_ex.data)} bytes, rtt_ms={base_ex.rtt_ms:.2f})"
    )

    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        safe_out: list[Indicator] = []
        for spec in _NTP_SKIP:
            if spec[0] == "ntp.framing":
                safe_out.append(
                    Indicator(
                        id="ntp.framing",
                        title="NTP response framing is invalid",
                        category="static_signature",
                        triggered=framing_hit,
                        protocol="ntp",
                        detail=framing_detail,
                        evidence=base_ex.data[:64].hex(),
                        remediation="Return a 48-byte NTPv4 mode-4 response (RFC 5905)",
                    )
                )
            else:
                safe_out.append(skipped_indicator(*spec, reason, protocol="ntp"))
        return safe_out

    # --- mode / version facade ---
    mode_hit = base_msg.mode != _MODE_SERVER
    mode_detail = (
        f"response mode={base_msg.mode} (expected server mode {_MODE_SERVER})"
        if mode_hit
        else f"server mode {_MODE_SERVER} ok"
    )
    # Invalid VN=0 should be dropped; a serving reply is a facade tell.
    vn_req = build_client_request(vn=_VN_INVALID)
    vn_ex, vn_msg, _vn_err = _exchange(host, port, vn_req)
    if vn_msg is not None and vn_msg.mode == _MODE_SERVER:
        mode_hit = True
        mode_detail = "invalid VN=0 client request still received a mode-4 server reply"

    # --- originate timestamp echo (RFC 5905 §7.3) ---
    org_hit = base_msg.originate_timestamp != client_xmt
    org_detail = (
        f"originate {base_msg.originate_timestamp:#x} != client xmt {client_xmt:#x}"
        if org_hit
        else f"originate echoed client xmt ({client_xmt:#x})"
    )

    # --- stratum facade ---
    stratum_hit = False
    if base_msg.stratum == 0 and not _is_kiss_code(base_msg.reference_id):
        stratum_hit = True
        stratum_detail = (
            "stratum 0 without a kiss-o'-death ASCII refid "
            f"(refid={base_msg.reference_id!r})"
        )
    elif base_msg.stratum >= 16:
        stratum_hit = True
        stratum_detail = f"stratum {base_msg.stratum} ≥ 16 presented as a serving reply"
    else:
        stratum_detail = f"stratum {base_msg.stratum} ok"

    # --- response clone (second distinct xmt) ---
    clone_req = build_client_request()
    clone_ex, _clone_msg, clone_err = _exchange(host, port, clone_req)
    clone_hit = False
    clone_detail = "second exchange not evaluated"
    if clone_ex.data and not clone_err:
        clone_hit = clone_ex.data == base_ex.data
        clone_detail = (
            "bitwise-identical UDP payloads for distinct client transmit timestamps"
            if clone_hit
            else "distinct replies for distinct originate values"
        )
    elif clone_err:
        clone_detail = f"second exchange inconclusive ({clone_err})"

    # --- zeroed clock metrics (gated) ---
    zeroed_hit = (
        base_msg.root_delay == 0
        and base_msg.root_dispersion == 0
        and base_msg.reference_timestamp == 0
    )
    zeroed_detail = (
        "root_delay, root_dispersion, and reference_timestamp are all zero"
        if zeroed_hit
        else (
            f"root_delay={base_msg.root_delay:#x} "
            f"root_dispersion={base_msg.root_dispersion:#x} "
            f"ref_ts={base_msg.reference_timestamp:#x}"
        )
    )

    # --- epoch-zero timestamps (gated) ---
    epoch_fields = []
    if _is_epoch_zero_ts(base_msg.reference_timestamp):
        epoch_fields.append("reference")
    if _is_epoch_zero_ts(base_msg.receive_timestamp):
        epoch_fields.append("receive")
    if _is_epoch_zero_ts(base_msg.transmit_timestamp):
        epoch_fields.append("transmit")
    epoch_hit = bool(epoch_fields)
    epoch_detail = (
        f"epoch-zero timestamps in: {', '.join(epoch_fields)}"
        if epoch_hit
        else "reference/receive/transmit timestamps look dynamic"
    )

    # --- stock refid (gated) ---
    stock_token = _stock_refid_token(base_msg.reference_id)
    stock_hit = bool(stock_token)
    stock_detail = (
        f"refid lure token {stock_token!r}"
        if stock_hit
        else f"refid={base_msg.reference_id!r}"
    )

    # --- arbitrary auth / KoD absent: short mode-3 burst (2–3 extras) ---
    # Exchanges so far: base, vn, clone (=3). Burst adds 2 → total 5.
    burst_msgs: list[NtpPacket] = []
    burst_served = 0
    burst_kod = False
    burst_rtts: list[float] = []
    for _ in range(2):
        breq = build_client_request()
        bex, bmsg, _berr = _exchange(host, port, breq)
        burst_rtts.append(bex.rtt_ms)
        if bmsg is not None and bmsg.mode == _MODE_SERVER:
            burst_served += 1
            burst_msgs.append(bmsg)
            if _is_rate_deny_kod(bmsg):
                burst_kod = True
    kod_hit = False
    if burst_served >= 2 and not burst_kod:
        # "Uniform serve under load": every burst packet is mode-4 with no RATE/DENY
        # KoD, and replies are canned (identical) or freeze transmit timestamps.
        raws = {m.raw for m in burst_msgs}
        xmts = {m.transmit_timestamp for m in burst_msgs}
        kod_hit = len(raws) == 1 or len(xmts) == 1
    kod_detail = (
        f"mode-3 burst: {burst_served}/2 uniform mode-4 replies with no KoD RATE/DENY"
        if kod_hit
        else (
            "KoD RATE/DENY observed under burst"
            if burst_kod
            else f"burst served {burst_served}/2 mode-4 replies (clock advanced / not uniform)"
        )
    )

    # --- state: timestamp monotonicity across baseline/clone/burst ---
    jittered_reconnect_pause()
    mono_msgs: list[NtpPacket] = [base_msg]
    if _clone_msg is not None:
        mono_msgs.append(_clone_msg)
    mono_msgs.extend(burst_msgs)
    # One more exchange after jitter for a fresh sample.
    late_req = build_client_request()
    late_ex, late_msg, _late_err = _exchange(host, port, late_req)
    if late_msg is not None:
        mono_msgs.append(late_msg)
    state_hit, state_detail = _timestamps_non_monotonic(mono_msgs)
    rtt_note = rtt_evidence(base_ex.rtt_ms, *burst_rtts, late_ex.rtt_ms)

    return [
        Indicator(
            id="ntp.kod_absent",
            title="NTP mode-3 burst is served without KoD RATE/DENY",
            category="arbitrary_auth",
            triggered=kod_hit,
            protocol="ntp",
            detail=kod_detail,
            evidence=rtt_note,
            remediation="Emit stratum-0 KoD RATE/DENY under client burst load (RFC 5905 §7.4)",
            fidelity="high" if kod_hit else "medium",
        ),
        Indicator(
            id="ntp.state_nonpersist",
            title="NTP timestamps fail monotonicity across exchanges",
            category="state_nonpersist",
            triggered=state_hit,
            protocol="ntp",
            detail=state_detail,
            evidence=rtt_note,
            remediation="Advance transmit/receive/reference timestamps per exchange",
            fidelity="high" if state_hit else "medium",
        ),
        Indicator(
            id="ntp.framing",
            title="NTP response framing is invalid",
            category="static_signature",
            triggered=framing_hit,
            protocol="ntp",
            detail=framing_detail,
            evidence=base_ex.data[:64].hex(),
            remediation="Return a 48-byte NTPv4 mode-4 response (RFC 5905)",
            fidelity="high" if framing_hit else "medium",
        ),
        Indicator(
            id="ntp.mode_facade",
            title="NTP answers with wrong mode or serves an invalid version",
            category="static_signature",
            triggered=mode_hit,
            protocol="ntp",
            detail=mode_detail,
            evidence=base_ex.data[:64].hex(),
            remediation="Respond mode 4 to mode-3 clients; drop unsupported VN",
            fidelity="high" if mode_hit else "medium",
        ),
        Indicator(
            id="ntp.org_echo",
            title="NTP originate timestamp does not echo the client transmit timestamp",
            category="static_signature",
            triggered=org_hit,
            protocol="ntp",
            detail=org_detail,
            evidence=base_ex.data[24:32].hex(),
            remediation="Copy client transmit timestamp into originate (RFC 5905 §7.3)",
            fidelity="high" if org_hit else "medium",
        ),
        Indicator(
            id="ntp.stratum_facade",
            title="NTP stratum is invalid for a serving reply",
            category="static_signature",
            triggered=stratum_hit,
            protocol="ntp",
            detail=stratum_detail,
            evidence=f"stratum={base_msg.stratum} refid={base_msg.reference_id!r}",
            remediation="Use stratum 1–15 when synchronized; stratum 0 only with kiss codes",
            fidelity="high" if stratum_hit else "medium",
        ),
        Indicator(
            id="ntp.response_clone",
            title="NTP returns bitwise-identical replies for distinct requests",
            category="static_signature",
            triggered=clone_hit,
            protocol="ntp",
            detail=clone_detail,
            evidence=(
                f"base={base_ex.data[:48].hex()} clone={clone_ex.data[:48].hex()}"
                if clone_ex.data
                else base_ex.data[:48].hex()
            ),
            remediation="Vary originate echo and transmit timestamp per request",
            fidelity="decisive" if clone_hit else "medium",
        ),
        Indicator(
            id="ntp.zeroed_clock_metrics",
            title="NTP root delay, dispersion, and reference timestamp are all zero",
            category="static_signature",
            triggered=zeroed_hit,
            protocol="ntp",
            detail=zeroed_detail,
            evidence=(
                f"delay={base_msg.root_delay:#x} disp={base_msg.root_dispersion:#x} "
                f"ref={base_msg.reference_timestamp:#x}"
            ),
            remediation="Maintain non-zero dispersion metrics even when unsynchronized",
            requires_corroboration=True,
            fidelity="medium",
        ),
        Indicator(
            id="ntp.epoch_zero",
            title="NTP reference/receive/transmit timestamps are at NTP or Unix epoch",
            category="static_signature",
            triggered=epoch_hit,
            protocol="ntp",
            detail=epoch_detail,
            evidence=(
                f"ref={base_msg.reference_timestamp:#x} "
                f"rec={base_msg.receive_timestamp:#x} "
                f"xmt={base_msg.transmit_timestamp:#x}"
            ),
            remediation="Populate timestamps from a live system clock",
            requires_corroboration=True,
            fidelity="medium",
        ),
        Indicator(
            id="ntp.stock_refid",
            title="NTP reference ID matches a stock honeypot lure token",
            category="static_signature",
            triggered=stock_hit,
            protocol="ntp",
            detail=stock_detail,
            evidence=base_msg.reference_id.hex(),
            remediation="Use a real clock-source refid (IP or ASCII id)",
            requires_corroboration=True,
            fidelity="medium",
        ),
    ]


UDP_ENGINE = UDPEngine(name="ntp", probe=probe_ntp)
