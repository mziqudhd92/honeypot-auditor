"""SNMP fingerprint engine (RFC 1157 / RFC 3416 community-based).

RFC non-compliance strategies (non-destructive GetRequest only — never Set):
  · arbitrary_auth — two random community strings both receive successful GetResponses
  · static_signature — request-id echo, invalid version facade, noSuch* handling,
    BER/PDU framing, stock sysDescr lure banners

UDP/161 (lab 1161). SNMPv1 and SNMPv2c message wrappers only.

See docs/SNMP.md, RFC 1157 §4.1, RFC 3416 §4.2.1 / §4.2.3.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, udp_transact
from honeypot_auditor.probes.common import is_safe_mode, skip_suite

_SNMP_SKIP = (
    (
        "snmp.arbitrary_community",
        "SNMP accepts two random community strings",
        "arbitrary_auth",
    ),
    (
        "snmp.request_id",
        "SNMP GetResponse request-id does not echo the request",
        "static_signature",
    ),
    (
        "snmp.version_facade",
        "SNMP answers GetRequest with an invalid protocol version",
        "static_signature",
    ),
    (
        "snmp.nosuch_success",
        "SNMP returns success data for a nonexistent OID",
        "static_signature",
    ),
    (
        "snmp.ber_framing",
        "SNMP response BER/PDU framing is invalid",
        "static_signature",
    ),
    (
        "snmp.stock_sysdescr",
        "SNMP sysDescr matches a stock honeypot lure banner",
        "static_signature",
    ),
)

# SNMPv1 INTEGER version=0, SNMPv2c version=1 (RFC 3416 / RFC 1901).
_VERSION_V1 = 0
_VERSION_V2C = 1
_VERSION_INVALID = 99

_PDU_GET_REQUEST = 0xA0
_PDU_GET_RESPONSE = 0xA2

# RFC 1157 error-status
_ERR_NO_ERROR = 0
_ERR_NO_SUCH_NAME = 2

# SNMPv2 exception tags inside VarBind value (RFC 3416)
_EXC_NO_SUCH_OBJECT = 0x80
_EXC_NO_SUCH_INSTANCE = 0x81
_EXC_END_OF_MIB_VIEW = 0x82

_OID_SYSDESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
_OID_GARBAGE = (1, 3, 6, 1, 4, 1, 999999, 1, 0)  # enterprise OID that should not exist

_STOCK_SYSDESCR = (
    "linux #1 smp",
    "fake snmp",
    "snmp honeypot",
    "opencanary",
    "conpot",
    "honeytrap",
    "debian gnu/linux",
    "device description",
    "unknown",
)


@dataclass(frozen=True)
class SnmpMessage:
    version: int
    community: str
    pdu_type: int
    request_id: int
    error_status: int
    error_index: int
    varbinds: tuple[tuple[tuple[int, ...], bytes, int], ...]  # (oid, value_bytes, value_tag)


def _ber_length(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative BER length")
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _ber_encode(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(content)) + content


def _ber_integer(value: int, *, tag: int = 0x02) -> bytes:
    if value == 0:
        return _ber_encode(tag, b"\x00")
    length = max(1, (value.bit_length() + 8) // 8)
    raw = value.to_bytes(length, "big", signed=True)
    # Ensure sign bit is correct for positive values.
    if value > 0 and raw[0] & 0x80:
        raw = b"\x00" + raw
    elif value < 0 and not (raw[0] & 0x80):
        raw = b"\xff" + raw
    return _ber_encode(tag, raw)


def _ber_octet_string(data: bytes | str, *, tag: int = 0x04) -> bytes:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return _ber_encode(tag, raw)


def _ber_null() -> bytes:
    return b"\x05\x00"


def _ber_oid(oid: tuple[int, ...]) -> bytes:
    if len(oid) < 2 or oid[0] > 2:
        raise ValueError("invalid OID")
    first = 40 * oid[0] + oid[1]
    body = bytearray([first])
    for arc in oid[2:]:
        if arc < 0:
            raise ValueError("negative OID arc")
        if arc < 128:
            body.append(arc)
            continue
        stack: list[int] = []
        n = arc
        stack.append(n & 0x7F)
        n >>= 7
        while n:
            stack.append(0x80 | (n & 0x7F))
            n >>= 7
        body.extend(reversed(stack))
    return _ber_encode(0x06, bytes(body))


def _ber_sequence(items: bytes, *, tag: int = 0x30) -> bytes:
    return _ber_encode(tag, items)


def _decode_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        return -1, pos
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    nbytes = first & 0x7F
    if nbytes == 0 or pos + nbytes > len(data):
        return -1, pos
    value = int.from_bytes(data[pos : pos + nbytes], "big")
    return value, pos + nbytes


def _decode_tlv(data: bytes, pos: int = 0) -> tuple[int, bytes, int] | None:
    if pos >= len(data):
        return None
    tag = data[pos]
    length, next_pos = _decode_length(data, pos + 1)
    if length < 0 or next_pos + length > len(data):
        return None
    return tag, data[next_pos : next_pos + length], next_pos + length


def _decode_integer(content: bytes) -> int | None:
    if not content:
        return None
    return int.from_bytes(content, "big", signed=True)


def _decode_oid(content: bytes) -> tuple[int, ...] | None:
    if not content:
        return None
    first = content[0]
    arcs = [first // 40, first % 40]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if (byte & 0x80) == 0:
            arcs.append(value)
            value = 0
    if content[-1] & 0x80:
        return None
    return tuple(arcs)


def build_get_request(
    community: str,
    oid: tuple[int, ...],
    *,
    version: int = _VERSION_V2C,
    request_id: int | None = None,
) -> bytes:
    """Build a community-based SNMP GetRequest (v1 or v2c)."""
    rid = secrets.randbelow(0x7FFFFFFF) if request_id is None else int(request_id)
    varbind = _ber_sequence(_ber_oid(oid) + _ber_null())
    varbind_list = _ber_sequence(varbind)
    pdu = _ber_sequence(
        _ber_integer(rid)
        + _ber_integer(_ERR_NO_ERROR)
        + _ber_integer(0)
        + varbind_list,
        tag=_PDU_GET_REQUEST,
    )
    return _ber_sequence(_ber_integer(version) + _ber_octet_string(community) + pdu)


def build_get_response(
    community: str,
    oid: tuple[int, ...],
    value: bytes | str,
    *,
    version: int = _VERSION_V2C,
    request_id: int = 1,
    error_status: int = _ERR_NO_ERROR,
    error_index: int = 0,
    value_tag: int = 0x04,
    pdu_type: int = _PDU_GET_RESPONSE,
) -> bytes:
    """Build a community SNMP GetResponse (test / lab helper)."""
    if value_tag == 0x05:
        val = _ber_null()
    elif value_tag in {_EXC_NO_SUCH_OBJECT, _EXC_NO_SUCH_INSTANCE, _EXC_END_OF_MIB_VIEW}:
        val = _ber_encode(value_tag, b"")
    else:
        val = _ber_octet_string(value, tag=value_tag)
    varbind = _ber_sequence(_ber_oid(oid) + val)
    varbind_list = _ber_sequence(varbind)
    pdu = _ber_sequence(
        _ber_integer(request_id)
        + _ber_integer(error_status)
        + _ber_integer(error_index)
        + varbind_list,
        tag=pdu_type,
    )
    return _ber_sequence(_ber_integer(version) + _ber_octet_string(community) + pdu)


def parse_snmp_message(data: bytes) -> SnmpMessage | None:
    """Parse a community SNMP message; return None if BER/PDU framing is invalid."""
    outer = _decode_tlv(data, 0)
    if outer is None or outer[0] != 0x30:
        return None
    body = outer[1]
    pos = 0

    ver_tlv = _decode_tlv(body, pos)
    if ver_tlv is None or ver_tlv[0] != 0x02:
        return None
    version = _decode_integer(ver_tlv[1])
    if version is None:
        return None
    pos = ver_tlv[2]

    com_tlv = _decode_tlv(body, pos)
    if com_tlv is None or com_tlv[0] != 0x04:
        return None
    community = com_tlv[1].decode("latin-1", "replace")
    pos = com_tlv[2]

    pdu_tlv = _decode_tlv(body, pos)
    if pdu_tlv is None:
        return None
    pdu_type, pdu_body, _ = pdu_tlv
    ppos = 0
    rid_tlv = _decode_tlv(pdu_body, ppos)
    if rid_tlv is None or rid_tlv[0] != 0x02:
        return None
    request_id = _decode_integer(rid_tlv[1])
    if request_id is None:
        return None
    ppos = rid_tlv[2]

    err_tlv = _decode_tlv(pdu_body, ppos)
    if err_tlv is None or err_tlv[0] != 0x02:
        return None
    error_status = _decode_integer(err_tlv[1])
    if error_status is None:
        return None
    ppos = err_tlv[2]

    idx_tlv = _decode_tlv(pdu_body, ppos)
    if idx_tlv is None or idx_tlv[0] != 0x02:
        return None
    error_index = _decode_integer(idx_tlv[1])
    if error_index is None:
        return None
    ppos = idx_tlv[2]

    vbl_tlv = _decode_tlv(pdu_body, ppos)
    if vbl_tlv is None or vbl_tlv[0] != 0x30:
        return None
    varbinds: list[tuple[tuple[int, ...], bytes, int]] = []
    vbpos = 0
    vb_body = vbl_tlv[1]
    while vbpos < len(vb_body):
        vb = _decode_tlv(vb_body, vbpos)
        if vb is None or vb[0] != 0x30:
            return None
        inner = vb[1]
        ipos = 0
        name_tlv = _decode_tlv(inner, ipos)
        if name_tlv is None or name_tlv[0] != 0x06:
            return None
        oid = _decode_oid(name_tlv[1])
        if oid is None:
            return None
        ipos = name_tlv[2]
        val_tlv = _decode_tlv(inner, ipos)
        if val_tlv is None:
            return None
        varbinds.append((oid, val_tlv[1], val_tlv[0]))
        vbpos = vb[2]

    return SnmpMessage(
        version=version,
        community=community,
        pdu_type=pdu_type,
        request_id=request_id,
        error_status=error_status,
        error_index=error_index,
        varbinds=tuple(varbinds),
    )


def _sysdescr_text(msg: SnmpMessage) -> str:
    for oid, value, tag in msg.varbinds:
        if oid == _OID_SYSDESCR and tag == 0x04:
            return value.decode("utf-8", "replace")
    for _oid, value, tag in msg.varbinds:
        if tag == 0x04:
            return value.decode("utf-8", "replace")
    return ""


def _is_successful_get(msg: SnmpMessage) -> bool:
    if msg.pdu_type != _PDU_GET_RESPONSE:
        return False
    if msg.error_status != _ERR_NO_ERROR:
        return False
    if not msg.varbinds:
        return False
    for _oid, _value, tag in msg.varbinds:
        if tag in {_EXC_NO_SUCH_OBJECT, _EXC_NO_SUCH_INSTANCE, _EXC_END_OF_MIB_VIEW}:
            return False
        if tag == 0x05:  # NULL — unanswered Get
            return False
    return True


def _is_nosuch_compliant(msg: SnmpMessage) -> bool:
    """RFC 1157 noSuchName or RFC 3416 exception varbind for missing OID."""
    if msg.pdu_type != _PDU_GET_RESPONSE:
        return False
    if msg.error_status == _ERR_NO_SUCH_NAME:
        return True
    if msg.error_status != _ERR_NO_ERROR:
        return True
    if not msg.varbinds:
        return False
    return all(
        tag in {_EXC_NO_SUCH_OBJECT, _EXC_NO_SUCH_INSTANCE, _EXC_END_OF_MIB_VIEW, 0x05}
        for _oid, _value, tag in msg.varbinds
    )


def _stock_sysdescr_hit(text: str) -> str | None:
    low = (text or "").strip().lower()
    if not low:
        return None
    for tell in _STOCK_SYSDESCR:
        if tell in low:
            return tell
    return None


def _query(
    host: str,
    port: int,
    community: str,
    oid: tuple[int, ...],
    *,
    version: int = _VERSION_V2C,
    request_id: int | None = None,
) -> tuple[bytes, SnmpMessage | None, str, int]:
    rid = secrets.randbelow(0x7FFFFFFF) if request_id is None else int(request_id)
    packet = build_get_request(community, oid, version=version, request_id=rid)
    raw, err = udp_transact(host, port, packet)
    if err and not raw:
        return b"", None, closed_reason(err), rid
    if not raw:
        return b"", None, "empty UDP reply", rid
    parsed = parse_snmp_message(raw)
    return raw, parsed, "", rid


def probe_snmp(host: str, port: int) -> list[Indicator]:
    # Baseline: well-known "public" community against sysDescr.0
    base_raw, base_msg, base_err, base_rid = _query(
        host, port, "public", _OID_SYSDESCR, version=_VERSION_V2C
    )
    if base_err and not base_raw:
        # Retry SNMPv1 once — some agents only speak version-1(0).
        base_raw, base_msg, base_err, base_rid = _query(
            host, port, "public", _OID_SYSDESCR, version=_VERSION_V1
        )
    if base_err and not base_raw:
        return skip_suite(_SNMP_SKIP, base_err, protocol="snmp", error=base_err)

    if base_msg is None:
        reason = "not an SNMP BER speaker"
        out: list[Indicator] = []
        for spec in _SNMP_SKIP:
            if spec[0] == "snmp.ber_framing":
                out.append(
                    Indicator(
                        id="snmp.ber_framing",
                        title="SNMP response BER/PDU framing is invalid",
                        category="static_signature",
                        triggered=True,
                        protocol="snmp",
                        detail=f"UDP reply was not a parseable SNMP message ({len(base_raw)} bytes)",
                        evidence=base_raw[:256].hex(),
                        remediation="Return a BER-encoded SNMP GetResponse (RFC 1157 / RFC 3416)",
                        fidelity="high",
                    )
                )
            else:
                out.append(skipped_indicator(*spec, reason, protocol="snmp", error=base_err))
        return out

    ber_hit = base_msg.pdu_type != _PDU_GET_RESPONSE
    ber_detail = (
        f"PDU tag 0x{base_msg.pdu_type:02x} is not GetResponse (0xA2)"
        if ber_hit
        else f"GetResponse ok version={base_msg.version} community={base_msg.community!r}"
    )

    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        safe_out: list[Indicator] = []
        for spec in _SNMP_SKIP:
            if spec[0] == "snmp.ber_framing":
                safe_out.append(
                    Indicator(
                        id="snmp.ber_framing",
                        title="SNMP response BER/PDU framing is invalid",
                        category="static_signature",
                        triggered=ber_hit,
                        protocol="snmp",
                        detail=ber_detail,
                        evidence=base_raw[:256].hex(),
                        remediation="Return a BER-encoded SNMP GetResponse (RFC 1157 / RFC 3416)",
                    )
                )
            else:
                safe_out.append(skipped_indicator(*spec, reason, protocol="snmp"))
        return safe_out

    # --- request-id echo (RFC 1157 §4.1) ---
    rid_hit = base_msg.request_id != base_rid
    rid_detail = (
        f"response request-id {base_msg.request_id} != request {base_rid}"
        if rid_hit
        else f"request-id echoed ({base_rid})"
    )

    # --- dual random communities (arbitrary auth) ---
    communities = [f"hpa-{secrets.token_hex(4)}" for _ in range(2)]
    accepted: list[str] = []
    auth_evidence: list[str] = []
    for community in communities:
        raw, msg, err, _rid = _query(host, port, community, _OID_SYSDESCR)
        if msg is not None and _is_successful_get(msg):
            accepted.append(community)
            auth_evidence.append(f"{community}: success GetResponse")
        elif msg is not None:
            auth_evidence.append(
                f"{community}: error_status={msg.error_status} pdu=0x{msg.pdu_type:02x}"
            )
        elif err:
            # Silent drop / timeout is the common compliant reject for bad communities.
            auth_evidence.append(f"{community}: unanswered ({err})")
        else:
            auth_evidence.append(f"{community}: unparseable {raw[:32]!r}")
    auth_hit = len(accepted) == len(communities)
    auth_skipped = False
    auth_skip_reason = ""
    # --- invalid version facade ---
    fac_raw, fac_msg, fac_err, _fac_rid = _query(
        host,
        port,
        "public",
        _OID_SYSDESCR,
        version=_VERSION_INVALID,
    )
    facade_hit = fac_msg is not None and _is_successful_get(fac_msg)
    facade_skipped = not fac_raw and bool(fac_err)

    # --- nonexistent OID should not return success data ---
    ns_raw, ns_msg, ns_err, _ns_rid = _query(
        host, port, "public", _OID_GARBAGE, version=_VERSION_V2C
    )
    if ns_err and not ns_raw:
        ns_raw, ns_msg, ns_err, _ns_rid = _query(
            host, port, "public", _OID_GARBAGE, version=_VERSION_V1
        )
    nosuch_skipped = not ns_raw and bool(ns_err)
    nosuch_hit = False
    nosuch_detail = "noSuch handling not evaluated"
    if ns_msg is not None:
        if _is_successful_get(ns_msg):
            nosuch_hit = True
            nosuch_detail = (
                "nonexistent OID returned error-status=0 with a populated varbind "
                "(RFC 1157 expects noSuchName; RFC 3416 expects exception tags)"
            )
        elif _is_nosuch_compliant(ns_msg):
            nosuch_detail = (
                f"compliant missing-OID handling (error_status={ns_msg.error_status})"
            )
        else:
            nosuch_detail = (
                f"non-success reply for missing OID (error_status={ns_msg.error_status})"
            )
    elif ns_raw:
        nosuch_hit = True
        nosuch_detail = "unparseable reply to missing-OID GetRequest"
    else:
        nosuch_skipped = True
        nosuch_detail = ns_err or "no reply to missing-OID GetRequest (inconclusive)"

    # --- stock sysDescr ---
    sysdescr = _sysdescr_text(base_msg) if _is_successful_get(base_msg) else ""
    stock_token = _stock_sysdescr_hit(sysdescr)
    stock_hit = bool(stock_token)
    # Corroboration-gated: alone a generic Linux string is weak.
    stock_requires = stock_token in {
        "linux #1 smp",
        "debian gnu/linux",
        "unknown",
        "device description",
    }

    return [
        Indicator(
            id="snmp.arbitrary_community",
            title="SNMP accepts two random community strings",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason=auth_skip_reason,
            error="",
            protocol="snmp",
            detail=(
                "two independent random community strings both received successful GetResponses"
                if auth_hit
                else "random community strings were not both accepted"
            ),
            evidence=",".join(accepted) if auth_hit else "; ".join(auth_evidence),
            remediation="Reject unknown SNMP community strings (do not answer GetRequest)",
            fidelity="decisive" if auth_hit else "medium",
        ),
        Indicator(
            id="snmp.request_id",
            title="SNMP GetResponse request-id does not echo the request",
            category="static_signature",
            triggered=rid_hit,
            protocol="snmp",
            detail=rid_detail,
            evidence=base_raw[:256].hex(),
            remediation="Echo the request-id in GetResponse (RFC 1157 §4.1)",
            fidelity="high" if rid_hit else "medium",
        ),
        Indicator(
            id="snmp.version_facade",
            title="SNMP answers GetRequest with an invalid protocol version",
            category="static_signature",
            triggered=facade_hit,
            skipped=facade_skipped,
            skip_reason=fac_err if facade_skipped else "",
            error=fac_err,
            protocol="snmp",
            detail=(
                f"version={_VERSION_INVALID} GetRequest still returned a successful GetResponse"
                if facade_hit
                else (
                    "invalid version rejected or unanswered"
                    if fac_raw or fac_err
                    else "invalid version not evaluated"
                )
            ),
            evidence=(fac_raw[:256].hex() if fac_raw else ""),
            remediation="Drop SNMP messages with unsupported version fields (RFC 3416)",
            fidelity="high" if facade_hit else "medium",
        ),
        Indicator(
            id="snmp.nosuch_success",
            title="SNMP returns success data for a nonexistent OID",
            category="static_signature",
            triggered=nosuch_hit,
            skipped=nosuch_skipped,
            skip_reason=nosuch_detail if nosuch_skipped else "",
            error=ns_err,
            protocol="snmp",
            detail=nosuch_detail,
            evidence=(ns_raw[:256].hex() if ns_raw else ""),
            remediation="Return noSuchName (v1) or SNMPv2 exception varbinds for unknown OIDs",
            fidelity="high" if nosuch_hit else "medium",
        ),
        Indicator(
            id="snmp.ber_framing",
            title="SNMP response BER/PDU framing is invalid",
            category="static_signature",
            triggered=ber_hit,
            protocol="snmp",
            detail=ber_detail,
            evidence=base_raw[:256].hex(),
            remediation="Return a BER-encoded SNMP GetResponse (RFC 1157 / RFC 3416)",
            fidelity="high" if ber_hit else "medium",
        ),
        Indicator(
            id="snmp.stock_sysdescr",
            title="SNMP sysDescr matches a stock honeypot lure banner",
            category="static_signature",
            triggered=stock_hit,
            skipped=not sysdescr and not _is_successful_get(base_msg),
            skip_reason="" if sysdescr or not _is_successful_get(base_msg) else "empty sysDescr",
            protocol="snmp",
            detail=(
                f"sysDescr matches lure token {stock_token!r}: {sysdescr[:160]!r}"
                if stock_hit
                else (f"sysDescr={sysdescr[:160]!r}" if sysdescr else "sysDescr not returned")
            ),
            evidence=sysdescr[:300],
            remediation="Use a unique, deployment-specific sysDescr instead of stock lure text",
            requires_corroboration=stock_requires,
            fidelity="medium",
        ),
    ]


__all__ = [
    "build_get_request",
    "build_get_response",
    "parse_snmp_message",
    "probe_snmp",
]
