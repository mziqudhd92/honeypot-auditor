"""SNMP RFC non-compliance probe tests."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.snmp as snmp
from honeypot_auditor.settings import settings


def _sysdescr_response(
    community: str = "public",
    *,
    request_id: int = 1,
    text: str = "Cisco IOS Software, C2900",
    version: int = 1,
    error_status: int = 0,
) -> bytes:
    return snmp.build_get_response(
        community,
        snmp._OID_SYSDESCR,
        text,
        version=version,
        request_id=request_id,
        error_status=error_status,
    )


def _sysobjectid_response(request_id: int = 1, version: int = 1) -> bytes:
    return snmp.build_get_response(
        "public",
        snmp._OID_SYSOBJECTID,
        (1, 3, 6, 1, 4, 1, 9, 1, 1),
        version=version,
        request_id=request_id,
        value_tag=snmp._TAG_OID,
    )


def _sysuptime_response(request_id: int = 1, version: int = 1, ticks: int = 12345) -> bytes:
    return snmp.build_get_response(
        "public",
        snmp._OID_SYSUPTIME,
        ticks,
        version=version,
        request_id=request_id,
        value_tag=snmp._TAG_TIMETICKS,
    )


def _getnext_advance_response(request_id: int = 1, version: int = 1) -> bytes:
    return snmp.build_get_response(
        "public",
        snmp._OID_SYSOBJECTID,
        (1, 3, 6, 1, 4, 1, 9, 1, 1),
        version=version,
        request_id=request_id,
        value_tag=snmp._TAG_OID,
    )


def _nosuch_v1(request_id: int = 1) -> bytes:
    return snmp.build_get_response(
        "public",
        snmp._OID_GARBAGE,
        b"",
        request_id=request_id,
        error_status=snmp._ERR_NO_SUCH_NAME,
        value_tag=0x05,
    )


def _nosuch_v2_exc(request_id: int = 1) -> bytes:
    return snmp.build_get_response(
        "public",
        snmp._OID_GARBAGE,
        b"",
        request_id=request_id,
        value_tag=snmp._EXC_NO_SUCH_OBJECT,
    )


def _success_garbage(request_id: int = 1) -> bytes:
    return snmp.build_get_response(
        "public",
        snmp._OID_GARBAGE,
        "fake-value",
        request_id=request_id,
    )


def _conformant_udp(host, port, payload, **kwargs):
    """public works; random communities fail; GetNext advances; types correct."""
    parsed = snmp.parse_snmp_message(payload)
    assert parsed is not None
    rid = parsed.request_id
    ver = parsed.version if parsed.version in (0, 1) else 1
    if parsed.version == snmp._VERSION_INVALID:
        return b"", "timed out"
    if parsed.community != "public":
        return b"", "timed out"
    if not parsed.varbinds:
        return b"", "timed out"
    oid = parsed.varbinds[0][0]
    if parsed.pdu_type == snmp._PDU_GET_NEXT_REQUEST:
        if oid == snmp._OID_SYSDESCR:
            return _getnext_advance_response(request_id=rid, version=ver), ""
        return _nosuch_v2_exc(request_id=rid), ""
    if oid == snmp._OID_GARBAGE:
        return _nosuch_v2_exc(request_id=rid), ""
    if oid == snmp._OID_SYSOBJECTID:
        return _sysobjectid_response(request_id=rid, version=ver), ""
    if oid == snmp._OID_SYSUPTIME:
        return _sysuptime_response(request_id=rid, version=ver), ""
    return _sysdescr_response(request_id=rid, text="RealDevice OS 12.1", version=ver), ""


def _honeypot_udp(host, port, payload, **kwargs):
    """Any community; canned sysDescr lure; ignores request-id / GetNext / types."""
    parsed = snmp.parse_snmp_message(payload)
    assert parsed is not None
    # Fixed canned datagram (ignores request-id) — fires response_clone.
    canned = snmp.build_get_response(
        "public",
        snmp._OID_SYSDESCR,
        "Linux #1 SMP OpenCanary fake snmp",
        request_id=1,
        version=1,
    )
    if parsed.varbinds and parsed.varbinds[0][0] == snmp._OID_GARBAGE:
        return _success_garbage(request_id=1), ""
    return canned, ""


def test_snmp_ber_round_trip():
    req = snmp.build_get_request("public", snmp._OID_SYSDESCR, request_id=42, version=1)
    assert req[0] == 0x30
    nxt = snmp.build_getnext_request("public", snmp._OID_SYSDESCR, request_id=43, version=1)
    assert snmp.parse_snmp_message(nxt) is not None
    resp = _sysdescr_response(request_id=42)
    parsed = snmp.parse_snmp_message(resp)
    assert parsed is not None
    assert parsed.request_id == 42
    assert parsed.pdu_type == snmp._PDU_GET_RESPONSE
    assert snmp._sysdescr_text(parsed).startswith("Cisco")


def test_snmp_conformant_agent_is_clean():
    with patch.object(snmp, "udp_transact", side_effect=_conformant_udp):
        inds = snmp.probe_snmp("127.0.0.1", 161)
    assert not any(ind.triggered for ind in inds)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["snmp.arbitrary_community"].skipped is False
    assert not by_id["snmp.arbitrary_community"].triggered
    assert not by_id["snmp.getnext_stub"].triggered
    assert not by_id["snmp.type_facade"].triggered
    assert not by_id["snmp.oid_echo"].triggered
    assert not by_id["snmp.response_clone"].triggered
    assert len(inds) == 10


def test_snmp_honeypot_tells_fire():
    with patch.object(snmp, "udp_transact", side_effect=_honeypot_udp):
        inds = snmp.probe_snmp("127.0.0.1", 161)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["snmp.arbitrary_community"].triggered
    assert by_id["snmp.request_id"].triggered
    assert by_id["snmp.version_facade"].triggered
    assert by_id["snmp.nosuch_success"].triggered
    assert by_id["snmp.stock_sysdescr"].triggered
    assert by_id["snmp.getnext_stub"].triggered
    assert by_id["snmp.type_facade"].triggered
    assert by_id["snmp.oid_echo"].triggered
    assert by_id["snmp.response_clone"].triggered


def test_snmp_ber_framing_on_garbage():
    with patch.object(snmp, "udp_transact", return_value=(b"not-snmp", "")):
        inds = snmp.probe_snmp("127.0.0.1", 161)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["snmp.ber_framing"].triggered
    assert all(i.skipped or i.id == "snmp.ber_framing" for i in inds)
    assert len(inds) == 10


def test_snmp_connection_error_skips_suite():
    with patch.object(snmp, "udp_transact", return_value=(b"", "timed out")):
        inds = snmp.probe_snmp("127.0.0.1", 161)
    assert len(inds) == 10
    assert all(ind.skipped for ind in inds)


def test_snmp_safe_mode_handshake_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        with patch.object(snmp.secrets, "randbelow", return_value=7):
            with patch.object(
                snmp,
                "udp_transact",
                return_value=(_sysdescr_response(request_id=7), ""),
            ):
                inds = snmp.probe_snmp("127.0.0.1", 161)
    finally:
        settings.safe_mode = old
    by_id = {ind.id: ind for ind in inds}
    assert len(inds) == 10
    assert not by_id["snmp.ber_framing"].skipped
    assert by_id["snmp.arbitrary_community"].skipped
    assert by_id["snmp.nosuch_success"].skipped
    assert by_id["snmp.getnext_stub"].skipped
    assert by_id["snmp.response_clone"].skipped


def test_snmp_nosuch_v1_compliant():
    def fake_udp(host, port, payload, **kwargs):
        parsed = snmp.parse_snmp_message(payload)
        assert parsed is not None
        rid = parsed.request_id
        ver = parsed.version if parsed.version in (0, 1) else 1
        if parsed.version == snmp._VERSION_INVALID:
            return b"", "timed out"
        if parsed.community != "public":
            return b"", "timed out"
        oid = parsed.varbinds[0][0] if parsed.varbinds else ()
        if parsed.pdu_type == snmp._PDU_GET_NEXT_REQUEST and oid == snmp._OID_SYSDESCR:
            return _getnext_advance_response(request_id=rid, version=ver), ""
        if oid == snmp._OID_GARBAGE:
            return _nosuch_v1(request_id=rid), ""
        if oid == snmp._OID_SYSOBJECTID:
            return _sysobjectid_response(request_id=rid, version=ver), ""
        if oid == snmp._OID_SYSUPTIME:
            return _sysuptime_response(request_id=rid, version=ver), ""
        return _sysdescr_response(request_id=rid, version=ver), ""

    with patch.object(snmp, "udp_transact", side_effect=fake_udp):
        inds = snmp.probe_snmp("127.0.0.1", 161)
    assert not {i.id: i for i in inds}["snmp.nosuch_success"].triggered


def test_snmp_getnext_and_type_tells_isolated():
    """GetNext same-OID stub + OctetString sysUpTime without other honeypot tells."""

    def fake_udp(host, port, payload, **kwargs):
        parsed = snmp.parse_snmp_message(payload)
        assert parsed is not None
        rid = parsed.request_id
        ver = parsed.version if parsed.version in (0, 1) else 1
        if parsed.version == snmp._VERSION_INVALID or parsed.community != "public":
            return b"", "timed out"
        oid = parsed.varbinds[0][0] if parsed.varbinds else ()
        if parsed.pdu_type == snmp._PDU_GET_NEXT_REQUEST:
            # Stub: pretend GetNext is Get(sysDescr)
            return _sysdescr_response(request_id=rid, version=ver, text="RealDevice OS"), ""
        if oid == snmp._OID_GARBAGE:
            return _nosuch_v2_exc(request_id=rid), ""
        if oid == snmp._OID_SYSOBJECTID:
            return _sysobjectid_response(request_id=rid, version=ver), ""
        if oid == snmp._OID_SYSUPTIME:
            # Wrong ASN.1 type: OctetString instead of TimeTicks
            return snmp.build_get_response(
                "public",
                snmp._OID_SYSUPTIME,
                "12345",
                version=ver,
                request_id=rid,
                value_tag=snmp._TAG_OCTET_STRING,
            ), ""
        return _sysdescr_response(request_id=rid, version=ver, text="RealDevice OS"), ""

    with patch.object(snmp, "udp_transact", side_effect=fake_udp):
        inds = snmp.probe_snmp("127.0.0.1", 161)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["snmp.getnext_stub"].triggered
    assert by_id["snmp.type_facade"].triggered
    assert not by_id["snmp.arbitrary_community"].triggered
    assert not by_id["snmp.oid_echo"].triggered
    assert not by_id["snmp.response_clone"].triggered


def test_snmp_oid_echo_on_canned_name():
    def fake_udp(host, port, payload, **kwargs):
        parsed = snmp.parse_snmp_message(payload)
        assert parsed is not None
        rid = parsed.request_id
        ver = parsed.version if parsed.version in (0, 1) else 1
        if parsed.version == snmp._VERSION_INVALID or parsed.community != "public":
            return b"", "timed out"
        oid = parsed.varbinds[0][0] if parsed.varbinds else ()
        if parsed.pdu_type == snmp._PDU_GET_NEXT_REQUEST:
            return _getnext_advance_response(request_id=rid, version=ver), ""
        if oid == snmp._OID_GARBAGE:
            return _nosuch_v2_exc(request_id=rid), ""
        if oid in {snmp._OID_SYSOBJECTID, snmp._OID_SYSUPTIME}:
            # Always name the varbind sysDescr regardless of request
            return _sysdescr_response(request_id=rid, version=ver, text="RealDevice OS"), ""
        return _sysdescr_response(request_id=rid, version=ver, text="RealDevice OS"), ""

    with patch.object(snmp, "udp_transact", side_effect=fake_udp):
        inds = snmp.probe_snmp("127.0.0.1", 161)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["snmp.oid_echo"].triggered
    assert by_id["snmp.type_facade"].triggered  # OctetString named as sysDescr for uptime path
