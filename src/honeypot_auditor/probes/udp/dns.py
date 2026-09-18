"""DNS fingerprint engine (RFC 1035 + light RFC 6891 EDNS0).

RFC non-compliance strategies (non-destructive QUERY only — never AXFR/ANY flood):
  · static_signature — header framing, txid echo, OPCODE facade, question echo,
    RCODE stub on .invalid, response clone, 0x20 case mismatch (gated),
    EDNS FORMERR on valid OPT, stock TXT/SOA lure tokens (gated)

UDP/53 (lab 15353). See docs/udp/DNS.md.
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, udp_exchange
from honeypot_auditor.probes.common import is_safe_mode, skip_suite
from honeypot_auditor.probes.udp._engine import UDPEngine

OPCODE_QUERY = 0
OPCODE_IQUERY = 1
OPCODE_STATUS = 2
OPCODE_ILLEGAL = 14  # reserved / unused — should not be answered as QUERY

TYPE_A = 1
TYPE_TXT = 16
TYPE_SOA = 6
TYPE_OPT = 41
CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_NXDOMAIN = 3

_DNS_SKIP = (
    (
        "dns.header_framing",
        "DNS response header framing is invalid",
        "static_signature",
    ),
    (
        "dns.txid",
        "DNS response transaction ID does not echo the request",
        "static_signature",
    ),
    (
        "dns.header_facade",
        "DNS answers an illegal OPCODE as a normal QUERY response",
        "static_signature",
    ),
    (
        "dns.question_echo",
        "DNS response question section does not echo the request",
        "static_signature",
    ),
    (
        "dns.rcode_stub",
        "DNS returns NOERROR with answers for an NXDOMAIN name",
        "static_signature",
    ),
    (
        "dns.response_clone",
        "DNS returns bitwise-identical replies for distinct transaction IDs",
        "static_signature",
    ),
    (
        "dns.case_encoding_mismatch",
        "DNS question QNAME casing was rewritten (0x20 mismatch)",
        "static_signature",
    ),
    (
        "dns.edns_facade",
        "DNS mishandles a valid EDNS0 OPT pseudo-RR",
        "static_signature",
    ),
    (
        "dns.stock_payload",
        "DNS answer/authority rdata matches a stock honeypot lure",
        "static_signature",
    ),
)

_STOCK_TOKENS = (
    "dionaea",
    "opencanary",
    "conpot",
    "honeytrap",
    "dns honeypot",
    "honeypot dns",
    "fake dns",
    "honeypot",
)


@dataclass(frozen=True)
class DnsRR:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes


@dataclass(frozen=True)
class DnsMessage:
    txid: int
    qr: int
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    question_name: str
    qtype: int
    qclass: int
    answers: tuple[DnsRR, ...]
    additionals: tuple[DnsRR, ...]
    has_opt: bool
    raw_question: bytes


def pack_header(
    txid: int,
    *,
    qr: int = 0,
    opcode: int = 0,
    aa: bool = False,
    tc: bool = False,
    rd: bool = False,
    ra: bool = False,
    rcode: int = 0,
    qdcount: int = 0,
    ancount: int = 0,
    nscount: int = 0,
    arcount: int = 0,
) -> bytes:
    flags = (
        ((qr & 1) << 15)
        | ((opcode & 0xF) << 11)
        | ((1 if aa else 0) << 10)
        | ((1 if tc else 0) << 9)
        | ((1 if rd else 0) << 8)
        | ((1 if ra else 0) << 7)
        | (rcode & 0xF)
    )
    return struct.pack(
        "!HHHHHH",
        txid & 0xFFFF,
        flags,
        qdcount & 0xFFFF,
        ancount & 0xFFFF,
        nscount & 0xFFFF,
        arcount & 0xFFFF,
    )


def encode_qname(name: str) -> bytes:
    """Encode a dotted name to wire labels, preserving character case."""
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("ascii", "strict")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label {label!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _decode_name(data: bytes, pos: int, *, depth: int = 0) -> tuple[str, int, bytes]:
    """Return (dotted_name, next_pos, raw_bytes_consumed_without_compression_follow)."""
    if depth > 20 or pos >= len(data):
        return "", -1, b""
    labels: list[str] = []
    raw = bytearray()
    start = pos
    jumped = False
    end_pos = pos
    while pos < len(data):
        length = data[pos]
        if length == 0:
            raw.append(0)
            pos += 1
            if not jumped:
                end_pos = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                return "", -1, b""
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                raw.extend(data[pos : pos + 2])
                end_pos = pos + 2
                jumped = True
            suffix, _, _ = _decode_name(data, pointer, depth=depth + 1)
            if suffix:
                labels.append(suffix)
            break
        if length & 0xC0:
            return "", -1, b""
        pos += 1
        if pos + length > len(data):
            return "", -1, b""
        label = data[pos : pos + length]
        raw.append(length)
        raw.extend(label)
        labels.append(label.decode("ascii", "replace"))
        pos += length
        if not jumped:
            end_pos = pos
    else:
        return "", -1, b""
    # When compression jumps mid-name, join carefully.
    if labels and "." in labels[-1] and len(labels) > 1:
        head = ".".join(labels[:-1])
        name = f"{head}.{labels[-1]}" if head else labels[-1]
    else:
        name = ".".join(labels)
    return name, end_pos if end_pos > start else pos, bytes(raw)


def _parse_rrs(data: bytes, pos: int, count: int) -> tuple[tuple[DnsRR, ...], int, bool]:
    rrs: list[DnsRR] = []
    has_opt = False
    for _ in range(count):
        name, pos, _raw = _decode_name(data, pos)
        if pos < 0 or pos + 10 > len(data):
            return tuple(rrs), -1, has_opt
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, pos)
        pos += 10
        if pos + rdlen > len(data):
            return tuple(rrs), -1, has_opt
        rdata = data[pos : pos + rdlen]
        pos += rdlen
        if rtype == TYPE_OPT:
            has_opt = True
        rrs.append(DnsRR(name=name, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata))
    return tuple(rrs), pos, has_opt


def parse_dns_message(data: bytes) -> DnsMessage | None:
    if len(data) < 12:
        return None
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, 0)
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = bool((flags >> 10) & 1)
    tc = bool((flags >> 9) & 1)
    rd = bool((flags >> 8) & 1)
    ra = bool((flags >> 7) & 1)
    rcode = flags & 0xF
    pos = 12
    question_name = ""
    qtype = 0
    qclass = 0
    raw_question = b""
    if qdcount > 0:
        question_name, pos, _ = _decode_name(data, pos)
        if pos < 0 or pos + 4 > len(data):
            return None
        qtype, qclass = struct.unpack_from("!HH", data, pos)
        # Capture exact on-wire question bytes (labels + type/class).
        raw_question = data[12 : pos + 4]
        pos += 4
        # Only consume the first question for echo checks.
        for _ in range(qdcount - 1):
            _n, pos, _ = _decode_name(data, pos)
            if pos < 0 or pos + 4 > len(data):
                return None
            pos += 4
    answers, pos, _ = _parse_rrs(data, pos, ancount)
    if pos < 0:
        return None
    _auth, pos, _ = _parse_rrs(data, pos, nscount)
    if pos < 0:
        return None
    # Fold authority into answers for stock scanning.
    answers = answers + _auth
    additionals, pos, has_opt = _parse_rrs(data, pos, arcount)
    if pos < 0:
        return None
    if any(rr.rtype == TYPE_OPT for rr in additionals):
        has_opt = True
    return DnsMessage(
        txid=txid,
        qr=qr,
        opcode=opcode,
        aa=aa,
        tc=tc,
        rd=rd,
        ra=ra,
        rcode=rcode,
        qdcount=qdcount,
        ancount=ancount,
        nscount=nscount,
        arcount=arcount,
        question_name=question_name,
        qtype=qtype,
        qclass=qclass,
        answers=answers,
        additionals=additionals,
        has_opt=has_opt,
        raw_question=raw_question,
    )


def _encode_rr(rr: DnsRR) -> bytes:
    return encode_qname(rr.name) + struct.pack(
        "!HHIH", rr.rtype, rr.rclass, rr.ttl & 0xFFFFFFFF, len(rr.rdata)
    ) + rr.rdata


def build_opt_rr(*, udp_payload: int = 1232, version: int = 0) -> DnsRR:
    # OPT: NAME=root, TYPE=41, CLASS=UDP payload, TTL=ext-rcode|version|flags
    ttl = (version & 0xFF) << 16
    return DnsRR(name="", rtype=TYPE_OPT, rclass=udp_payload & 0xFFFF, ttl=ttl, rdata=b"")


def build_query(
    qname: str,
    *,
    txid: int | None = None,
    rd: bool = True,
    qtype: int = TYPE_A,
    qclass: int = CLASS_IN,
    opcode: int = OPCODE_QUERY,
    opt: DnsRR | None = None,
) -> bytes:
    if txid is None:
        txid = secrets.randbelow(0x10000)
    question = encode_qname(qname) + struct.pack("!HH", qtype, qclass)
    arcount = 1 if opt is not None else 0
    header = pack_header(
        txid,
        qr=0,
        opcode=opcode,
        rd=rd,
        qdcount=1,
        arcount=arcount,
    )
    body = header + question
    if opt is not None:
        body += _encode_rr(opt)
    return body


def build_response(
    request: DnsMessage,
    *,
    rcode: int,
    aa: bool = False,
    ra: bool = True,
    answers: tuple[DnsRR, ...] = (),
    txid_override: int | None = None,
    qr: int = 1,
    echo_question: bool = True,
) -> bytes:
    txid = request.txid if txid_override is None else (txid_override & 0xFFFF)
    if echo_question and request.question_name:
        qname = request.question_name
        qtype = request.qtype or TYPE_A
        qclass = request.qclass or CLASS_IN
        question = encode_qname(qname) + struct.pack("!HH", qtype, qclass)
        qdcount = 1
    else:
        question = b""
        qdcount = 0
    an_bytes = b"".join(_encode_rr(rr) for rr in answers)
    header = pack_header(
        txid,
        qr=qr,
        opcode=OPCODE_QUERY,
        aa=aa,
        rd=request.rd,
        ra=ra,
        rcode=rcode,
        qdcount=qdcount,
        ancount=len(answers),
    )
    return header + question + an_bytes


def attach_additional(message: bytes, additionals: tuple[DnsRR, ...]) -> bytes:
    """Rewrite ARCOUNT and append additional RRs onto an existing message."""
    if len(message) < 12:
        return message
    txid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", message, 0)
    ar = len(additionals)
    header = struct.pack("!HHHHHH", txid, flags, qd, an, ns, ar)
    return header + message[12:] + b"".join(_encode_rr(rr) for rr in additionals)


def _mixed_case_qname() -> str:
    """Synthetic .invalid name with mixed case for 0x20 checks."""
    nonce = secrets.token_hex(2)
    raw = f"hpaudit-{nonce}.invalid"
    out: list[str] = []
    flip = True
    for ch in raw:
        if ch.isalpha():
            out.append(ch.upper() if flip else ch.lower())
            flip = not flip
        else:
            out.append(ch)
    return "".join(out)


def _exchange(host: str, port: int, payload: bytes):
    ex = udp_exchange(host, port, payload, connected=False)
    return ex


def _stock_hit(text: str) -> str:
    low = text.lower()
    for token in _STOCK_TOKENS:
        if token in low:
            return token
    return ""


def _rr_text(rr: DnsRR) -> str:
    if rr.rtype == TYPE_TXT:
        # TXT: length-prefixed character-strings.
        parts: list[str] = []
        i = 0
        while i < len(rr.rdata):
            n = rr.rdata[i]
            i += 1
            parts.append(rr.rdata[i : i + n].decode("utf-8", "replace"))
            i += n
        return " ".join(parts)
    if rr.rtype == TYPE_SOA:
        return rr.rdata.decode("utf-8", "replace")
    return rr.rdata.decode("utf-8", "replace")


def probe_dns(host: str, port: int) -> list[Indicator]:
    qname = _mixed_case_qname()
    base_txid = secrets.randbelow(0x10000) or 1
    base_payload = build_query(qname, txid=base_txid, rd=True)
    base_ex = _exchange(host, port, base_payload)

    if base_ex.error and not base_ex.data:
        return skip_suite(
            _DNS_SKIP, closed_reason(base_ex.error), protocol="dns", error=base_ex.error
        )

    base_msg = parse_dns_message(base_ex.data)
    if base_msg is None or base_msg.qr != 1:
        reason = "not a DNS QR=1 speaker"
        out: list[Indicator] = []
        for spec in _DNS_SKIP:
            if spec[0] == "dns.header_framing":
                detail = (
                    f"UDP reply was not a parseable DNS response ({len(base_ex.data)} bytes)"
                    if base_msg is None
                    else f"QR={base_msg.qr} (expected 1)"
                )
                out.append(
                    Indicator(
                        id="dns.header_framing",
                        title="DNS response header framing is invalid",
                        category="static_signature",
                        triggered=True,
                        protocol="dns",
                        detail=detail,
                        evidence=base_ex.data[:256].hex(),
                        remediation="Return a DNS header with QR=1 (RFC 1035 §4.1.1)",
                        fidelity="high",
                    )
                )
            else:
                out.append(skipped_indicator(*spec, reason, protocol="dns", error=base_ex.error))
        return out

    framing_hit = False
    framing_detail = (
        f"QR=1 ok txid={base_msg.txid} rcode={base_msg.rcode} qname={base_msg.question_name!r}"
    )

    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        safe_out: list[Indicator] = []
        for spec in _DNS_SKIP:
            if spec[0] == "dns.header_framing":
                safe_out.append(
                    Indicator(
                        id="dns.header_framing",
                        title="DNS response header framing is invalid",
                        category="static_signature",
                        triggered=framing_hit,
                        protocol="dns",
                        detail=framing_detail,
                        evidence=base_ex.data[:256].hex(),
                        remediation="Return a DNS header with QR=1 (RFC 1035 §4.1.1)",
                    )
                )
            else:
                safe_out.append(skipped_indicator(*spec, reason, protocol="dns"))
        return safe_out

    # --- txid ---
    txid_hit = base_msg.txid != base_txid
    txid_detail = (
        f"response txid {base_msg.txid} != request {base_txid}"
        if txid_hit
        else f"txid echoed ({base_txid})"
    )

    # --- question echo ---
    question_hit = False
    question_detail = "question echoed"
    if base_msg.qdcount < 1 or not base_msg.question_name:
        question_hit = True
        question_detail = f"QDCOUNT={base_msg.qdcount} missing question echo"
    elif base_msg.qtype != TYPE_A or base_msg.qclass != CLASS_IN:
        question_hit = True
        question_detail = (
            f"question type/class {base_msg.qtype}/{base_msg.qclass} != {TYPE_A}/{CLASS_IN}"
        )
    elif base_msg.question_name.lower() != qname.lower():
        question_hit = True
        question_detail = (
            f"question name {base_msg.question_name!r} != request {qname!r} (case-insensitive)"
        )

    # --- 0x20 case encoding ---
    case_hit = False
    case_detail = "QNAME casing echoed"
    if (
        not question_hit
        and base_msg.question_name
        and base_msg.question_name != qname
        and base_msg.question_name.lower() == qname.lower()
    ):
        case_hit = True
        case_detail = (
            f"QNAME casing rewritten: sent {qname!r} got {base_msg.question_name!r}"
        )

    # --- rcode stub (.invalid → NXDOMAIN) ---
    rcode_hit = False
    rcode_detail = f"rcode={base_msg.rcode}"
    if base_msg.rcode == RCODE_NOERROR and base_msg.ancount > 0 and base_msg.answers:
        # Answers present for .invalid is the stub tell.
        if any(rr.rtype != TYPE_OPT for rr in base_msg.answers):
            rcode_hit = True
            rcode_detail = (
                f"NOERROR with {base_msg.ancount} answer RR(s) for .invalid "
                "(expected NXDOMAIN)"
            )
    elif base_msg.rcode == RCODE_NXDOMAIN:
        rcode_detail = "NXDOMAIN for .invalid (ok)"
    else:
        rcode_detail = f"rcode={base_msg.rcode} ancount={base_msg.ancount} (not stub-scored)"

    # --- stock lure in answers ---
    lure_match = ""
    for rr in base_msg.answers:
        lure_match = _stock_hit(_rr_text(rr))
        if lure_match:
            break
    stock_hit = bool(lure_match)

    # --- illegal OPCODE facade ---
    # Conformant resolvers typically *drop* reserved OPCODEs (surfaces as UDP
    # timeout). That is a clean non-hit — not a skipped probe. Only score when
    # the peer answers as a normal QUERY (or FORMERR, which we treat as ok).
    fac_txid = (base_txid + 1) % 0x10000 or 1
    fac_payload = build_query(qname, txid=fac_txid, rd=True, opcode=OPCODE_ILLEGAL)
    fac_ex = _exchange(host, port, fac_payload)
    facade_hit = False
    facade_detail = "illegal OPCODE unanswered (ok)"
    if fac_ex.data:
        fac_msg = parse_dns_message(fac_ex.data)
        if fac_msg is not None and fac_msg.qr == 1 and fac_msg.rcode != RCODE_FORMERR:
            facade_hit = True
            facade_detail = (
                f"illegal OPCODE={OPCODE_ILLEGAL} answered "
                f"rcode={fac_msg.rcode} qr={fac_msg.qr}"
            )
        elif fac_msg is not None and fac_msg.rcode == RCODE_FORMERR:
            facade_detail = "FORMERR for illegal OPCODE (ok)"
        elif fac_msg is None:
            facade_detail = "unparseable reply to illegal OPCODE (inconclusive)"
    elif fac_ex.error:
        facade_detail = f"illegal OPCODE unanswered ({closed_reason(fac_ex.error)}; ok)"

    # --- response clone (distinct txid) ---
    clone_txid = (base_txid + 2) % 0x10000 or 2
    if clone_txid == base_txid:
        clone_txid = (base_txid + 3) % 0x10000 or 3
    clone_payload = build_query(qname, txid=clone_txid, rd=True)
    clone_ex = _exchange(host, port, clone_payload)
    clone_skipped = bool(clone_ex.error) and not clone_ex.data
    clone_hit = False
    clone_detail = "distinct replies"
    if clone_ex.data and base_ex.data and clone_ex.data == base_ex.data:
        clone_hit = True
        clone_detail = (
            f"bitwise-identical UDP payloads for txid {base_txid} and {clone_txid}"
        )
        # Identical bytes with distinct request IDs also imply txid mismatch on at least one.
        if not txid_hit:
            txid_hit = True
            txid_detail = "canned reply ignored distinct transaction IDs"
    elif clone_skipped:
        clone_detail = clone_ex.error or "no reply to clone probe"
    elif clone_ex.data:
        clone_detail = "distinct reply payloads (ok)"

    # --- EDNS OPT ---
    edns_txid = (base_txid + 4) % 0x10000 or 4
    edns_payload = build_query(
        qname, txid=edns_txid, rd=True, opt=build_opt_rr(udp_payload=1232)
    )
    edns_ex = _exchange(host, port, edns_payload)
    edns_skipped = bool(edns_ex.error) and not edns_ex.data
    edns_hit = False
    edns_detail = "EDNS OPT accepted or ignored without FORMERR"
    if edns_ex.data:
        edns_msg = parse_dns_message(edns_ex.data)
        if edns_msg is None:
            edns_hit = True
            edns_detail = "unparseable reply to valid OPT"
        elif edns_msg.rcode == RCODE_FORMERR:
            edns_hit = True
            edns_detail = "FORMERR for a valid EDNS0 OPT (RFC 6891)"
        else:
            edns_detail = f"OPT reply rcode={edns_msg.rcode} (ok; OPT absence alone not scored)"
    elif edns_skipped:
        edns_detail = edns_ex.error or "no reply to EDNS probe (skip)"

    # case_encoding is always corroboration-gated (FP: real forwarders lowercase).
    case_requires = True
    # stock always gated in v1 (weak lure tokens).
    stock_requires = True

    rtt_note = f"baseline_rtt_ms={base_ex.rtt_ms:.2f}"

    return [
        Indicator(
            id="dns.header_framing",
            title="DNS response header framing is invalid",
            category="static_signature",
            triggered=framing_hit,
            protocol="dns",
            detail=framing_detail,
            evidence=f"{rtt_note}; {base_ex.data[:128].hex()}",
            remediation="Return a DNS header with QR=1 (RFC 1035 §4.1.1)",
            fidelity="high",
        ),
        Indicator(
            id="dns.txid",
            title="DNS response transaction ID does not echo the request",
            category="static_signature",
            triggered=txid_hit,
            protocol="dns",
            detail=txid_detail,
            evidence=f"request={base_txid} response={base_msg.txid}",
            remediation="Echo the query transaction ID (RFC 1035 §4.1.1)",
            fidelity="high",
        ),
        Indicator(
            id="dns.header_facade",
            title="DNS answers an illegal OPCODE as a normal QUERY response",
            category="static_signature",
            triggered=facade_hit,
            protocol="dns",
            detail=facade_detail,
            evidence=fac_ex.data[:128].hex() if fac_ex.data else "",
            remediation="Drop or FORMERR reserved/illegal OPCODEs",
            fidelity="high",
        ),
        Indicator(
            id="dns.question_echo",
            title="DNS response question section does not echo the request",
            category="static_signature",
            triggered=question_hit,
            protocol="dns",
            detail=question_detail,
            evidence=f"qdcount={base_msg.qdcount} qname={base_msg.question_name!r}",
            remediation="Echo the question section (RFC 1035 §4.1.1)",
            fidelity="high",
        ),
        Indicator(
            id="dns.rcode_stub",
            title="DNS returns NOERROR with answers for an NXDOMAIN name",
            category="static_signature",
            triggered=rcode_hit,
            protocol="dns",
            detail=rcode_detail,
            evidence=f"rcode={base_msg.rcode} ancount={base_msg.ancount}",
            remediation="Return NXDOMAIN for nonexistent names (RFC 1035 / RFC 2606 .invalid)",
            fidelity="high",
        ),
        (
            skipped_indicator(
                "dns.response_clone",
                "DNS returns bitwise-identical replies for distinct transaction IDs",
                "static_signature",
                clone_detail,
                protocol="dns",
                error=clone_ex.error,
            )
            if clone_skipped
            else Indicator(
                id="dns.response_clone",
                title="DNS returns bitwise-identical replies for distinct transaction IDs",
                category="static_signature",
                triggered=clone_hit,
                protocol="dns",
                detail=clone_detail,
                evidence=(
                    f"len={len(base_ex.data)} match={clone_hit}"
                    if clone_ex.data
                    else clone_detail
                ),
                remediation="Build per-request responses that echo the query ID",
                fidelity="decisive",
            )
        ),
        Indicator(
            id="dns.case_encoding_mismatch",
            title="DNS question QNAME casing was rewritten (0x20 mismatch)",
            category="static_signature",
            triggered=case_hit,
            protocol="dns",
            detail=case_detail,
            evidence=f"sent={qname!r} got={base_msg.question_name!r}",
            remediation="Echo question QNAME bytes exactly (0x20 encoding)",
            fidelity="high",
            requires_corroboration=case_requires if case_hit else False,
        ),
        (
            skipped_indicator(
                "dns.edns_facade",
                "DNS mishandles a valid EDNS0 OPT pseudo-RR",
                "static_signature",
                edns_detail,
                protocol="dns",
                error=edns_ex.error,
            )
            if edns_skipped
            else Indicator(
                id="dns.edns_facade",
                title="DNS mishandles a valid EDNS0 OPT pseudo-RR",
                category="static_signature",
                triggered=edns_hit,
                protocol="dns",
                detail=edns_detail,
                evidence=edns_ex.data[:128].hex() if edns_ex.data else "",
                remediation="Accept or ignore a valid OPT without FORMERR (RFC 6891)",
                fidelity="high",
            )
        ),
        Indicator(
            id="dns.stock_payload",
            title="DNS answer/authority rdata matches a stock honeypot lure",
            category="static_signature",
            triggered=stock_hit,
            protocol="dns",
            detail=f"matched lure {lure_match!r}" if stock_hit else "no stock lure token",
            evidence=lure_match,
            remediation="Avoid canned honeypot lure strings in DNS rdata",
            fidelity="medium",
            requires_corroboration=stock_requires if stock_hit else False,
        ),
    ]


UDP_ENGINE = UDPEngine(name="dns", probe=probe_dns)

__all__ = [
    "CLASS_IN",
    "DnsMessage",
    "DnsRR",
    "OPCODE_ILLEGAL",
    "OPCODE_QUERY",
    "RCODE_FORMERR",
    "RCODE_NOERROR",
    "RCODE_NXDOMAIN",
    "TYPE_A",
    "TYPE_OPT",
    "TYPE_SOA",
    "TYPE_TXT",
    "UDP_ENGINE",
    "attach_additional",
    "build_opt_rr",
    "build_query",
    "build_response",
    "encode_qname",
    "pack_header",
    "parse_dns_message",
    "probe_dns",
]
