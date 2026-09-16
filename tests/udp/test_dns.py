"""DNS RFC non-compliance probe tests (MockUDPTransceiver; no live network)."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.udp.dns as dns
from honeypot_auditor.config import PROTOCOL_STRATEGIES
from honeypot_auditor.netutil import UdpExchange
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.probes.udp import discover_udp_engines
from honeypot_auditor.settings import settings

_DNS_IDS = (
    "dns.header_framing",
    "dns.txid",
    "dns.header_facade",
    "dns.question_echo",
    "dns.rcode_stub",
    "dns.response_clone",
    "dns.case_encoding_mismatch",
    "dns.edns_facade",
    "dns.stock_payload",
)


def _ok(data: bytes, port: int = 53, rtt: float = 1.0) -> UdpExchange:
    return UdpExchange(data=data, peer_host="127.0.0.1", peer_port=port, rtt_ms=rtt, error="")


def _err(error: str = "timed out") -> UdpExchange:
    return UdpExchange(data=b"", peer_host="", peer_port=0, rtt_ms=0.0, error=error)


def _nxdomain_reply(req: dns.DnsMessage) -> bytes:
    """Conformant NXDOMAIN for .invalid (RFC 2606); echo ID + question casing."""
    return dns.build_response(
        req,
        rcode=dns.RCODE_NXDOMAIN,
        aa=False,
        ra=True,
        answers=(),
    )


def _noerror_a_reply(req: dns.DnsMessage, *, rdata: bytes = b"\x7f\x00\x00\x01") -> bytes:
    return dns.build_response(
        req,
        rcode=dns.RCODE_NOERROR,
        aa=True,
        ra=True,
        answers=(
            dns.DnsRR(
                name=req.question_name,
                rtype=dns.TYPE_A,
                rclass=dns.CLASS_IN,
                ttl=60,
                rdata=rdata,
            ),
        ),
    )


def _conformant_exchange(host, port, payload, *, connected=False, **kwargs):
    """BIND/Unbound-like: echo ID/QNAME case, NXDOMAIN for .invalid, drop bad OPCODE, echo OPT."""
    del host, connected, kwargs
    msg = dns.parse_dns_message(payload)
    assert msg is not None
    if msg.opcode != dns.OPCODE_QUERY:
        return _err()
    if msg.qdcount < 1 or not msg.question_name:
        return _err()
    body = _nxdomain_reply(msg)
    if msg.has_opt:
        body = dns.attach_additional(body, (dns.build_opt_rr(udp_payload=1232),))
    return _ok(body, port=port, rtt=2.5)


def _patch_conformant():
    return patch.object(dns, "udp_exchange", side_effect=_conformant_exchange)


def test_dns_wire_round_trip():
    qname = "hPaUdIt-1.iNvAlId"
    req = dns.build_query(qname, txid=0xABCD, rd=True)
    parsed = dns.parse_dns_message(req)
    assert parsed is not None
    assert parsed.txid == 0xABCD
    assert parsed.qr == 0
    assert parsed.opcode == dns.OPCODE_QUERY
    assert parsed.question_name == qname
    assert parsed.qtype == dns.TYPE_A
    resp = _nxdomain_reply(parsed)
    rparsed = dns.parse_dns_message(resp)
    assert rparsed is not None
    assert rparsed.txid == 0xABCD
    assert rparsed.qr == 1
    assert rparsed.rcode == dns.RCODE_NXDOMAIN
    assert rparsed.question_name == qname


def test_dns_conformant_resolver_is_clean():
    with _patch_conformant():
        inds = dns.probe_dns("127.0.0.1", 53)
    assert len(inds) == len(_DNS_IDS)
    assert {i.id for i in inds} == set(_DNS_IDS)
    assert not any(i.triggered for i in inds)
    by_id = {i.id: i for i in inds}
    assert by_id["dns.header_framing"].skipped is False
    assert by_id["dns.case_encoding_mismatch"].skipped is False
    assert not by_id["dns.case_encoding_mismatch"].triggered
    assert not by_id["dns.response_clone"].triggered
    assert not by_id["dns.edns_facade"].triggered


def test_dns_header_framing_on_garbage(mock_udp_cls):
    mock = mock_udp_cls([(b"not-dns-at-all", 53, 1.0, "")])
    mock.queue(*[(b"", 0, 0.0, "timed out")] * 7)
    with patch.object(dns, "udp_exchange", side_effect=mock.udp_exchange):
        inds = dns.probe_dns("127.0.0.1", 53)
    by_id = {i.id: i for i in inds}
    assert len(inds) == len(_DNS_IDS)
    assert by_id["dns.header_framing"].triggered
    assert all(i.skipped or i.id == "dns.header_framing" for i in inds)


def test_dns_transport_error_skips_suite(mock_udp_cls):
    mock = mock_udp_cls([(b"", 0, 0.0, "timed out")])
    with patch.object(dns, "udp_exchange", side_effect=mock.udp_exchange):
        inds = dns.probe_dns("127.0.0.1", 53)
    assert len(inds) == len(_DNS_IDS)
    assert all(i.skipped for i in inds)
    assert not any(i.triggered for i in inds)


def test_dns_safe_mode_framing_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        with _patch_conformant():
            inds = dns.probe_dns("127.0.0.1", 53)
    finally:
        settings.safe_mode = old
    by_id = {i.id: i for i in inds}
    assert len(inds) == len(_DNS_IDS)
    assert not by_id["dns.header_framing"].skipped
    assert not by_id["dns.header_framing"].triggered
    for iid in _DNS_IDS:
        if iid == "dns.header_framing":
            continue
        assert by_id[iid].skipped
        assert "safe-mode" in by_id[iid].skip_reason.lower()


def test_dns_txid_isolated():
    """Response ID ignores request → only dns.txid (plus no clone/facade noise)."""

    def side_effect(host, port, payload, *, connected=False, **kwargs):
        del host, connected, kwargs
        msg = dns.parse_dns_message(payload)
        assert msg is not None
        if msg.opcode != dns.OPCODE_QUERY:
            return _err()
        wrong = dns.build_response(
            msg,
            rcode=dns.RCODE_NXDOMAIN,
            aa=False,
            ra=True,
            answers=(),
            txid_override=(msg.txid ^ 0x1111) & 0xFFFF,
        )
        return _ok(wrong, port=port)

    with patch.object(dns, "udp_exchange", side_effect=side_effect):
        inds = dns.probe_dns("127.0.0.1", 53)
    by_id = {i.id: i for i in inds}
    assert by_id["dns.txid"].triggered
    assert by_id["dns.txid"].fidelity in {"high", "decisive"}
    assert not by_id["dns.header_framing"].triggered
    assert not by_id["dns.question_echo"].triggered
    assert not by_id["dns.header_facade"].triggered
    assert not by_id["dns.rcode_stub"].triggered


def test_dns_header_facade_on_illegal_opcode():
    """Illegal OPCODE still answered as a normal QUERY response."""

    def side_effect(host, port, payload, *, connected=False, **kwargs):
        del host, connected, kwargs
        msg = dns.parse_dns_message(payload)
        assert msg is not None
        if msg.opcode != dns.OPCODE_QUERY:
            fake = dns.DnsMessage(
                txid=msg.txid,
                qr=0,
                opcode=dns.OPCODE_QUERY,
                aa=False,
                tc=False,
                rd=msg.rd,
                ra=False,
                rcode=0,
                qdcount=msg.qdcount,
                ancount=0,
                nscount=0,
                arcount=0,
                question_name=msg.question_name or "hpaudit.invalid",
                qtype=msg.qtype or dns.TYPE_A,
                qclass=msg.qclass or dns.CLASS_IN,
                answers=(),
                additionals=(),
                has_opt=False,
                raw_question=msg.raw_question,
            )
            return _ok(_nxdomain_reply(fake), port=port)
        return _ok(_nxdomain_reply(msg), port=port)

    with patch.object(dns, "udp_exchange", side_effect=side_effect):
        inds = dns.probe_dns("127.0.0.1", 53)
    by_id = {i.id: i for i in inds}
    assert by_id["dns.header_facade"].triggered
    assert not by_id["dns.header_framing"].triggered
    assert not by_id["dns.txid"].triggered


def test_dns_question_echo_isolated():
    """QDCOUNT=0 / missing question echo → dns.question_echo."""

    def side_effect(host, port, payload, *, connected=False, **kwargs):
        del host, connected, kwargs
        msg = dns.parse_dns_message(payload)
        assert msg is not None
        if msg.opcode != dns.OPCODE_QUERY:
            return _err()
        header = dns.pack_header(
            msg.txid,
            qr=1,
            opcode=0,
            aa=False,
            tc=False,
            rd=True,
            ra=True,
            rcode=dns.RCODE_NXDOMAIN,
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0,
        )
        return _ok(header, port=port)

    with patch.object(dns, "udp_exchange", side_effect=side_effect):
        inds = dns.probe_dns("127.0.0.1", 53)
    by_id = {i.id: i for i in inds}
    assert by_id["dns.question_echo"].triggered
    assert not by_id["dns.txid"].triggered
    assert not by_id["dns.header_framing"].triggered


def test_dns_rcode_stub_isolated():
    """NXDOMAIN name answered NOERROR with A record → dns.rcode_stub."""

    def side_effect(host, port, payload, *, connected=False, **kwargs):
        del host, connected, kwargs
        msg = dns.parse_dns_message(payload)
        assert msg is not None
        if msg.opcode != dns.OPCODE_QUERY:
            return _err()
        if msg.has_opt:
            body = dns.attach_additional(_nxdomain_reply(msg), (dns.build_opt_rr(),))
        else:
            body = _noerror_a_reply(msg)
        return _ok(body, port=port)

    with patch.object(dns, "udp_exchange", side_effect=side_effect):
        inds = dns.probe_dns("127.0.0.1", 53)
    by_id = {i.id: i for i in inds}
    assert by_id["dns.rcode_stub"].triggered
    assert not by_id["dns.header_framing"].triggered
    assert not by_id["dns.txid"].triggered


def test_dns_response_clone():
    """Distinct txids, bitwise-identical payloads → dns.response_clone (decisive)."""
    canned_holder: dict[str, bytes] = {}

    def side_effect(host, port, payload, *, connected=False, **kwargs):
        del host, connected, kwargs
        msg = dns.parse_dns_message(payload)
        assert msg is not None
        if msg.opcode != dns.OPCODE_QUERY:
            return _err()
        if "canned" not in canned_holder:
            canned_holder["canned"] = dns.build_response(
                msg,
                rcode=dns.RCODE_NXDOMAIN,
                aa=False,
                ra=True,
                answers=(),
                txid_override=1,
            )
        return _ok(canned_holder["canned"], port=port)

    with patch.object(dns, "udp_exchange", side_effect=side_effect):
        inds = dns.probe_dns("127.0.0.1", 53)
    by_id = {i.id: i for i in inds}
    assert by_id["dns.response_clone"].triggered
    assert by_id["dns.response_clone"].fidelity == "decisive"
    assert by_id["dns.txid"].triggered


def test_dns_case_encoding_mismatch_gated():
    """Lowercased QNAME echo alone → triggered with requires_corroboration."""

    def side_effect(host, port, payload, *, connected=False, **kwargs):
        del host, connected, kwargs
        msg = dns.parse_dns_message(payload)
        assert msg is not None
        if msg.opcode != dns.OPCODE_QUERY:
            return _err()
        lowered = dns.DnsMessage(
            txid=msg.txid,
            qr=0,
            opcode=msg.opcode,
            aa=False,
            tc=False,
            rd=msg.rd,
            ra=False,
            rcode=0,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
            question_name=(msg.question_name or "").lower(),
            qtype=msg.qtype,
            qclass=msg.qclass,
            answers=(),
            additionals=(),
            has_opt=False,
            raw_question=b"",
        )
        body = _nxdomain_reply(lowered)
        if msg.has_opt:
            body = dns.attach_additional(body, (dns.build_opt_rr(),))
        return _ok(body, port=port)

    with patch.object(dns, "udp_exchange", side_effect=side_effect):
        inds = dns.probe_dns("127.0.0.1", 53)
    by_id = {i.id: i for i in inds}
    assert by_id["dns.case_encoding_mismatch"].triggered
    assert by_id["dns.case_encoding_mismatch"].requires_corroboration is True
    assert not by_id["dns.txid"].triggered
    assert not by_id["dns.rcode_stub"].triggered


def test_dns_edns_facade_on_formerr():
    """Valid OPT in additional → FORMERR / garbage is dns.edns_facade."""

    def side_effect(host, port, payload, *, connected=False, **kwargs):
        del host, connected, kwargs
        msg = dns.parse_dns_message(payload)
        assert msg is not None
        if msg.opcode != dns.OPCODE_QUERY:
            return _err()
        if msg.has_opt:
            body = dns.build_response(
                msg,
                rcode=dns.RCODE_FORMERR,
                aa=False,
                ra=True,
                answers=(),
            )
            return _ok(body, port=port)
        return _ok(_nxdomain_reply(msg), port=port)

    with patch.object(dns, "udp_exchange", side_effect=side_effect):
        inds = dns.probe_dns("127.0.0.1", 53)
    by_id = {i.id: i for i in inds}
    assert by_id["dns.edns_facade"].triggered
    assert not by_id["dns.header_framing"].triggered
    assert not by_id["dns.rcode_stub"].triggered


def test_dns_stock_payload_gated():
    """TXT lure token → dns.stock_payload with requires_corroboration."""

    def side_effect(host, port, payload, *, connected=False, **kwargs):
        del host, connected, kwargs
        msg = dns.parse_dns_message(payload)
        assert msg is not None
        if msg.opcode != dns.OPCODE_QUERY:
            return _err()
        txt = b"\x18dionaea dns honeypot lure"
        answers = (
            dns.DnsRR(
                name=msg.question_name,
                rtype=dns.TYPE_TXT,
                rclass=dns.CLASS_IN,
                ttl=60,
                rdata=txt,
            ),
        )
        body = dns.build_response(
            msg,
            rcode=dns.RCODE_NXDOMAIN,
            aa=True,
            ra=True,
            answers=answers,
        )
        if msg.has_opt:
            body = dns.attach_additional(body, (dns.build_opt_rr(),))
        return _ok(body, port=port)

    with patch.object(dns, "udp_exchange", side_effect=side_effect):
        inds = dns.probe_dns("127.0.0.1", 53)
    by_id = {i.id: i for i in inds}
    assert by_id["dns.stock_payload"].triggered
    assert by_id["dns.stock_payload"].requires_corroboration is True


def test_dns_registry_and_discovery():
    assert "dns" in PROBE_BY_PROTOCOL
    assert PROBE_BY_PROTOCOL["dns"] is dns.probe_dns
    assert "dns" in PROTOCOL_STRATEGIES
    row = PROTOCOL_STRATEGIES["dns"]
    assert row["arbitrary_auth"] == ""
    assert row["state_nonpersist"] == ""
    assert "txid" in row["static_signature"].lower() or "header" in row["static_signature"].lower()
    engines = discover_udp_engines()
    names = {e.name for e in engines}
    assert "dns" in names
    assert dns.UDP_ENGINE.name == "dns"
    assert dns.UDP_ENGINE.probe is dns.probe_dns
