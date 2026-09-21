"""TFTP fingerprint engine (RFC 1350 + light RFC 2347 options).

RFC non-compliance strategies (non-destructive RRQ/WRQ headers only — never DATA upload):
  · static_signature — TID source port, opcode/error/mode/WRQ facades,
    option blindness, response clone, no OACK retransmit, DATA block-size
    arithmetic, stock ERROR/DATA lure
  · state_nonpersist — server TID reused across independent RRQs

UDP/69 (lab 1069). See docs/udp/TFTP.md, RFC 1350, RFC 2347.
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import (
    closed_reason,
    udp_exchange,
    udp_exchange_to,
    udp_exchange_with_retransmit_watch,
)
from honeypot_auditor.probes.common import is_safe_mode, skip_suite
from honeypot_auditor.probes.udp._engine import UDPEngine

_TFTP_SKIP = (
    (
        "tftp.framing",
        "TFTP response framing is invalid",
        "static_signature",
    ),
    (
        "tftp.fixed_source_port",
        "TFTP reply uses the service port as TID",
        "static_signature",
    ),
    (
        "tftp.opcode_facade",
        "TFTP answers RRQ with an unexpected opcode",
        "static_signature",
    ),
    (
        "tftp.error_stub",
        "TFTP missing-file / ERROR semantics are stubbed",
        "static_signature",
    ),
    (
        "tftp.mode_facade",
        "TFTP serves DATA for an illegal transfer mode",
        "static_signature",
    ),
    (
        "tftp.wrq_stub",
        "TFTP WRQ is answered with DATA instead of ACK/ERROR",
        "static_signature",
    ),
    (
        "tftp.option_blindness",
        "TFTP chokes on RFC 2347 option negotiation",
        "static_signature",
    ),
    (
        "tftp.block_size_violation",
        "TFTP DATA block exceeds 512 bytes without a larger negotiated blksize",
        "static_signature",
    ),
    (
        "tftp.tid_reuse",
        "TFTP reuses the same server TID across independent transfers",
        "state_nonpersist",
    ),
    (
        "tftp.response_clone",
        "TFTP returns a canned identical payload for distinct RRQs",
        "static_signature",
    ),
    (
        "tftp.no_retransmit",
        "TFTP never retransmits OACK when ACK is withheld",
        "static_signature",
    ),
    (
        "tftp.stock_payload",
        "TFTP ERROR/DATA matches a stock honeypot lure",
        "static_signature",
    ),
)

OP_RRQ = 1
OP_WRQ = 2
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5
OP_OACK = 6

ERR_UNDEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
ERR_DISK_FULL = 3
ERR_ILLEGAL_OPERATION = 4
ERR_UNKNOWN_TID = 5
ERR_FILE_EXISTS = 6
ERR_NO_SUCH_USER = 7
# RFC 2347 option negotiation failed (commonly 8 when implemented).
ERR_OPTION_NEGOTIATION = 8

_STOCK_TOKENS = (
    "honeypot",
    "conpot",
    "opencanary",
    "tftp stub",
    "fake tftp",
    "honeytrap",
)


@dataclass(frozen=True)
class TftpPacket:
    opcode: int
    filename: str = ""
    mode: str = ""
    block: int = 0
    data: bytes = b""
    error_code: int = 0
    error_message: str = ""
    options: tuple[tuple[str, str], ...] = ()


def _nul_fields(payload: bytes) -> list[str]:
    parts = payload.split(b"\x00")
    out: list[str] = []
    for part in parts:
        if not part and not out:
            continue
        out.append(part.decode("utf-8", "replace"))
    # Trailing empty from final NUL is normal; drop empties at end.
    while out and out[-1] == "":
        out.pop()
    return out


def parse_tftp(data: bytes) -> TftpPacket | None:
    if len(data) < 2:
        return None
    opcode = struct.unpack("!H", data[:2])[0]
    if opcode not in {OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR, OP_OACK}:
        return None
    body = data[2:]
    if opcode in (OP_RRQ, OP_WRQ):
        fields = _nul_fields(body)
        if len(fields) < 2:
            return None
        filename, mode = fields[0], fields[1]
        opts: list[tuple[str, str]] = []
        rest = fields[2:]
        for i in range(0, len(rest) - 1, 2):
            opts.append((rest[i], rest[i + 1]))
        return TftpPacket(opcode=opcode, filename=filename, mode=mode, options=tuple(opts))
    if opcode == OP_DATA:
        if len(body) < 2:
            return None
        block = struct.unpack("!H", body[:2])[0]
        return TftpPacket(opcode=opcode, block=block, data=body[2:])
    if opcode == OP_ACK:
        if len(body) < 2:
            return None
        block = struct.unpack("!H", body[:2])[0]
        return TftpPacket(opcode=opcode, block=block)
    if opcode == OP_ERROR:
        if len(body) < 2:
            return None
        code = struct.unpack("!H", body[:2])[0]
        msg = body[2:].split(b"\x00", 1)[0].decode("utf-8", "replace")
        return TftpPacket(opcode=opcode, error_code=code, error_message=msg)
    # OACK
    fields = _nul_fields(body)
    opts = []
    for i in range(0, len(fields) - 1, 2):
        opts.append((fields[i], fields[i + 1]))
    return TftpPacket(opcode=opcode, options=tuple(opts))


def _encode_rrq_wrq(opcode: int, filename: str, mode: str, options: dict[str, str] | None) -> bytes:
    parts = [
        struct.pack("!H", opcode),
        filename.encode("utf-8"),
        b"\x00",
        mode.encode("ascii"),
        b"\x00",
    ]
    if options:
        for key, value in options.items():
            parts.extend([key.encode("ascii"), b"\x00", str(value).encode("ascii"), b"\x00"])
    return b"".join(parts)


def build_rrq(
    filename: str, mode: str = "octet", *, options: dict[str, str] | None = None
) -> bytes:
    return _encode_rrq_wrq(OP_RRQ, filename, mode, options)


def build_wrq(
    filename: str, mode: str = "octet", *, options: dict[str, str] | None = None
) -> bytes:
    return _encode_rrq_wrq(OP_WRQ, filename, mode, options)


def build_data(block: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HH", OP_DATA, block & 0xFFFF) + payload


def build_ack(block: int) -> bytes:
    return struct.pack("!HH", OP_ACK, block & 0xFFFF)


def build_error(code: int, message: str = "") -> bytes:
    return (
        struct.pack("!HH", OP_ERROR, code & 0xFFFF) + message.encode("utf-8", "replace") + b"\x00"
    )


def build_oack(options: dict[str, str]) -> bytes:
    parts = [struct.pack("!H", OP_OACK)]
    for key, value in options.items():
        parts.extend([key.encode("ascii"), b"\x00", str(value).encode("ascii"), b"\x00"])
    return b"".join(parts)


def _stock_hit(text: str) -> str:
    lowered = text.lower()
    for token in _STOCK_TOKENS:
        if token in lowered:
            return token
    return ""


def _collect_stock_text(pkt: TftpPacket | None) -> str:
    if pkt is None:
        return ""
    if pkt.opcode == OP_ERROR:
        return pkt.error_message
    if pkt.opcode == OP_DATA:
        return pkt.data.decode("utf-8", "replace")
    return ""


def _absorb_stock(stock_text: str, stock_token: str, pkt: TftpPacket | None) -> tuple[str, str]:
    """Merge ERROR/DATA lure text from a later exchange without masking prior hits.

    Always scan the new packet for stock tokens even when ``stock_text`` is already
    set (a clean baseline ERROR must not hide a honeypot lure on a later DATA).
    """
    extra = _collect_stock_text(pkt)
    if not extra:
        return stock_text, stock_token
    token = _stock_hit(extra)
    if token and not stock_token:
        return extra, token
    if not stock_text:
        return extra, stock_token
    return stock_text, stock_token


def _is_stubby_clone_payload(pkt: TftpPacket | None) -> bool:
    """True when an identical replay is suspicious (not a normal File not found ERROR)."""
    if pkt is None:
        return False
    if pkt.opcode in (OP_DATA, OP_ACK):
        return True
    if pkt.opcode == OP_ERROR:
        if pkt.error_code == ERR_UNDEFINED and not pkt.error_message.strip():
            return True
        if pkt.error_code > 7:
            return True
        return False
    return False


def _ind(
    spec: tuple[str, str, str],
    *,
    triggered: bool,
    detail: str,
    evidence: str = "",
    fidelity: str = "high",
    requires_corroboration: bool = False,
    skipped: bool = False,
    skip_reason: str = "",
    error: str = "",
) -> Indicator:
    ind_id, title, category = spec
    if skipped:
        return skipped_indicator(ind_id, title, category, skip_reason, protocol="tftp", error=error)
    return Indicator(
        id=ind_id,
        title=title,
        category=category,
        triggered=triggered,
        protocol="tftp",
        detail=detail,
        evidence=evidence,
        fidelity=fidelity,
        requires_corroboration=requires_corroboration,
        remediation="Speak RFC 1350 TFTP with a distinct server TID and honest ERROR/ACK semantics",
    )


def _spec(ind_id: str) -> tuple[str, str, str]:
    for row in _TFTP_SKIP:
        if row[0] == ind_id:
            return row
    raise KeyError(ind_id)


def probe_tftp(host: str, port: int) -> list[Indicator]:
    nonce = secrets.token_hex(4)
    filename = f"hpaudit-{nonce}.bin"

    # 1) Baseline RRQ — missing file, mode octet (unconnected for TID learning).
    baseline = udp_exchange(host, port, build_rrq(filename, "octet"), connected=False)
    if baseline.error and not baseline.data:
        return skip_suite(
            _TFTP_SKIP, closed_reason(baseline.error), protocol="tftp", error=baseline.error
        )

    base_pkt = parse_tftp(baseline.data)
    if base_pkt is None:
        framing_detail = f"UDP reply was not a parseable TFTP packet ({len(baseline.data)} bytes)"
        out: list[Indicator] = []
        reason = "not a TFTP speaker"
        for spec in _TFTP_SKIP:
            if spec[0] == "tftp.framing":
                out.append(
                    _ind(
                        spec,
                        triggered=True,
                        detail=framing_detail,
                        evidence=baseline.data[:256].hex(),
                        fidelity="high",
                    )
                )
            else:
                out.append(skipped_indicator(*spec, reason, protocol="tftp"))
        return out

    framing_detail = f"TFTP opcode={base_pkt.opcode} peer_port={baseline.peer_port}"

    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        safe_out: list[Indicator] = []
        for spec in _TFTP_SKIP:
            if spec[0] == "tftp.framing":
                safe_out.append(
                    _ind(
                        spec,
                        triggered=False,
                        detail=framing_detail,
                        evidence=baseline.data[:256].hex(),
                    )
                )
            else:
                safe_out.append(skipped_indicator(*spec, reason, protocol="tftp"))
        return safe_out

    # --- fixed_source_port: peer must be a new TID, not the service port ---
    fixed_hit = baseline.peer_port == port
    fixed_detail = (
        f"reply peer_port={baseline.peer_port} equals dst_port={port} (RFC 1350 requires a new TID)"
        if fixed_hit
        else f"reply TID peer_port={baseline.peer_port} (dst={port})"
    )

    # --- opcode_facade / error_stub on baseline missing-file RRQ ---
    opcode_hit = base_pkt.opcode in (OP_DATA, OP_ACK)
    opcode_detail = (
        f"missing-file RRQ answered with opcode={base_pkt.opcode} (expected ERROR)"
        if opcode_hit
        else f"baseline opcode={base_pkt.opcode}"
    )

    error_hit = False
    error_detail = "ERROR semantics not evaluated"
    if base_pkt.opcode == OP_DATA:
        error_hit = True
        error_detail = "missing-file RRQ returned DATA (success path)"
    elif base_pkt.opcode == OP_ERROR:
        if base_pkt.error_code > 7:
            # RFC 1350 §5 defines 0–7; code 8 (option negotiation) belongs on option probes.
            error_hit = True
            error_detail = f"ERROR code {base_pkt.error_code} outside RFC 1350 range 0–7"
        else:
            error_detail = f"ERROR code={base_pkt.error_code} msg={base_pkt.error_message!r}"
    elif base_pkt.opcode == OP_ACK:
        error_hit = True
        error_detail = "missing-file RRQ returned ACK (stub)"

    stock_text = _collect_stock_text(base_pkt)
    stock_token = _stock_hit(stock_text)

    # --- second independent RRQ: TID reuse + response clone ---
    filename2 = f"hpaudit-{secrets.token_hex(4)}.bin"
    second = udp_exchange(host, port, build_rrq(filename2, "octet"), connected=False)
    second_pkt = parse_tftp(second.data) if second.data else None
    second_skipped = bool(second.error and not second.data)

    tid_reuse_hit = False
    tid_reuse_detail = "TID reuse not evaluated"
    tid_reuse_skipped = second_skipped
    if not second_skipped and baseline.peer_port and second.peer_port:
        # Only score reused *ephemeral* TIDs (service-port reuse is fixed_source_port).
        if (
            baseline.peer_port == second.peer_port
            and baseline.peer_port != port
            and second.peer_port != port
        ):
            tid_reuse_hit = True
            tid_reuse_detail = f"independent RRQs reused server TID peer_port={baseline.peer_port}"
        else:
            tid_reuse_detail = (
                f"TIDs baseline={baseline.peer_port} second={second.peer_port} (distinct ok)"
            )
    elif second_skipped:
        tid_reuse_detail = second.error or "no reply to second RRQ"

    clone_hit = False
    clone_detail = "response clone not evaluated"
    clone_skipped = second_skipped
    if not second_skipped and baseline.data and second.data and baseline.data == second.data:
        if _is_stubby_clone_payload(base_pkt) or _is_stubby_clone_payload(second_pkt):
            clone_hit = True
            clone_detail = (
                f"bitwise-identical {len(baseline.data)}-byte reply for distinct missing-file RRQs"
            )
        else:
            clone_detail = (
                "identical ERROR payloads for distinct names "
                "(normal File not found; not scored as clone)"
            )
    elif not second_skipped:
        clone_detail = "second RRQ payload differs from baseline (ok)"
    else:
        clone_detail = second.error or "no reply to second RRQ"
    stock_text, stock_token = _absorb_stock(stock_text, stock_token, second_pkt)

    # --- mode facade: illegal mode should not serve DATA ---
    # Silent drop/timeout is inconclusive-but-clean (not a skip); only DATA is a hit.
    mode_ex = udp_exchange(host, port, build_rrq(filename, "hpaudit"), connected=False)
    mode_pkt = parse_tftp(mode_ex.data) if mode_ex.data else None
    mode_hit = mode_pkt is not None and mode_pkt.opcode == OP_DATA
    mode_detail = (
        "illegal mode served DATA"
        if mode_hit
        else (
            f"illegal mode unanswered ({closed_reason(mode_ex.error)}; ok)"
            if mode_ex.error and not mode_ex.data
            else f"illegal mode reply opcode={mode_pkt.opcode if mode_pkt else 'unparseable'}"
        )
    )
    stock_text, stock_token = _absorb_stock(stock_text, stock_token, mode_pkt)

    # --- WRQ stub: expect ACK(0) or ERROR, never DATA ---
    wrq_ex = udp_exchange(host, port, build_wrq(filename, "octet"), connected=False)
    wrq_pkt = parse_tftp(wrq_ex.data) if wrq_ex.data else None
    wrq_skipped = bool(wrq_ex.error and not wrq_ex.data)
    wrq_hit = wrq_pkt is not None and wrq_pkt.opcode == OP_DATA
    wrq_detail = (
        "WRQ answered with DATA"
        if wrq_hit
        else (
            wrq_ex.error
            if wrq_skipped
            else f"WRQ reply opcode={wrq_pkt.opcode if wrq_pkt else 'unparseable'}"
        )
    )
    stock_text, stock_token = _absorb_stock(stock_text, stock_token, wrq_pkt)

    # --- option blindness + OACK retransmit watch ---
    opt_ex, opt_rexmit = udp_exchange_with_retransmit_watch(
        host,
        port,
        build_rrq(filename, "octet", options={"blksize": "512"}),
        connected=False,
    )
    opt_pkt = parse_tftp(opt_ex.data) if opt_ex.data else None
    opt_skipped = bool(opt_ex.error and not opt_ex.data)
    option_hit = False
    option_detail = "option negotiation not evaluated"
    no_rexmit_hit = False
    no_rexmit_skipped = True
    no_rexmit_detail = "OACK retransmit not evaluated"
    no_rexmit_err = ""
    if opt_skipped:
        option_detail = opt_ex.error or "no reply to optioned RRQ (inconclusive)"
        no_rexmit_detail = option_detail
        no_rexmit_err = opt_ex.error
    elif opt_pkt is None:
        option_hit = True
        option_detail = "unparseable reply to RRQ+blksize"
        no_rexmit_detail = "no OACK to watch for retransmit"
        no_rexmit_err = opt_ex.error
    elif opt_pkt.opcode == OP_OACK:
        option_detail = f"OACK options={dict(opt_pkt.options)}"
        no_rexmit_skipped = False
        if opt_rexmit.data:
            no_rexmit_detail = (
                f"OACK retransmitted ({len(opt_rexmit.data)} bytes; rtt_ms={opt_rexmit.rtt_ms:.3f})"
            )
        else:
            no_rexmit_hit = True
            no_rexmit_detail = (
                f"OACK not retransmitted while ACK withheld ({closed_reason(opt_rexmit.error)})"
            )
            no_rexmit_err = opt_rexmit.error
        # ACK the OACK on the learned TID (no DATA upload) after the watch window.
        if opt_ex.peer_port:
            udp_exchange_to(host, opt_ex.peer_port, build_ack(0))
    elif (
        opt_pkt.opcode == OP_ERROR
        and opt_pkt.error_code == ERR_UNDEFINED
        and not opt_pkt.error_message.strip()
    ):
        option_hit = True
        option_detail = "RRQ+blksize returned ERROR 0 with empty message (option choke)"
        no_rexmit_detail = "option ERROR (no OACK retransmit watch)"
    elif opt_pkt.opcode == OP_ERROR and opt_pkt.error_code in {
        ERR_FILE_NOT_FOUND,
        ERR_ILLEGAL_OPERATION,
        ERR_OPTION_NEGOTIATION,
        ERR_ACCESS_VIOLATION,
    }:
        option_detail = f"proper ERROR to optioned RRQ (code={opt_pkt.error_code} msg={opt_pkt.error_message!r})"
        no_rexmit_detail = "option ERROR (no OACK retransmit watch)"
    elif opt_pkt.opcode == OP_DATA:
        option_hit = True
        option_detail = "RRQ+blksize returned DATA without OACK"
        # DATA also expects ACK — one-shot DATA is the same class of stub.
        no_rexmit_skipped = False
        if opt_rexmit.data:
            no_rexmit_detail = f"DATA retransmitted ({len(opt_rexmit.data)} bytes)"
        else:
            no_rexmit_hit = True
            no_rexmit_detail = (
                f"DATA not retransmitted while ACK withheld ({closed_reason(opt_rexmit.error)})"
            )
            no_rexmit_err = opt_rexmit.error
    else:
        option_detail = f"optioned RRQ opcode={opt_pkt.opcode}"
        no_rexmit_detail = f"opcode={opt_pkt.opcode} (no OACK retransmit watch)"
    stock_text, stock_token = _absorb_stock(stock_text, stock_token, opt_pkt)
    stock_hit = bool(stock_token)

    # --- DATA block-size arithmetic (RFC 1350 §5: data ≤512 unless blksize
    # negotiated; our only blksize request is 512, so >512 is always illegal) ---
    opt_rexmit_pkt = parse_tftp(opt_rexmit.data) if opt_rexmit.data else None
    data_blocks: list[tuple[str, int]] = []
    for label, pkt in (
        ("baseline", base_pkt),
        ("second", second_pkt),
        ("mode", mode_pkt),
        ("wrq", wrq_pkt),
        ("optioned", opt_pkt),
        ("oack-retransmit", opt_rexmit_pkt),
    ):
        if pkt is not None and pkt.opcode == OP_DATA:
            data_blocks.append((label, len(pkt.data)))
    over_limit = [(lbl, n) for lbl, n in data_blocks if n > 512]
    block_hit = bool(over_limit)
    if over_limit:
        lbl, n = over_limit[0]
        block_detail = f"{lbl} RRQ served a {n}-byte DATA block (RFC 1350 cap is 512)"
        block_evidence = f"{lbl}:{n}B"
    elif data_blocks:
        block_detail = f"max DATA payload {max(n for _, n in data_blocks)}/512 bytes (ok)"
        block_evidence = ""
    else:
        block_detail = "no DATA blocks served (ok)"
        block_evidence = ""

    if stock_token:
        stock_detail = f"stock lure token {stock_token!r} in TFTP payload"
    else:
        stock_detail = "no stock lure tokens"

    results = [
        _ind(
            _spec("tftp.framing"),
            triggered=False,
            detail=framing_detail,
            evidence=baseline.data[:256].hex(),
            fidelity="high",
        ),
        _ind(
            _spec("tftp.fixed_source_port"),
            triggered=fixed_hit,
            detail=fixed_detail,
            evidence=f"peer_port={baseline.peer_port};rtt_ms={baseline.rtt_ms:.3f}",
            fidelity="high",
        ),
        _ind(
            _spec("tftp.opcode_facade"),
            triggered=opcode_hit,
            detail=opcode_detail,
            evidence=baseline.data[:256].hex(),
            fidelity="high",
        ),
        _ind(
            _spec("tftp.error_stub"),
            triggered=error_hit,
            detail=error_detail,
            evidence=baseline.data[:256].hex(),
            fidelity="high",
        ),
        _ind(
            _spec("tftp.mode_facade"),
            triggered=mode_hit,
            detail=mode_detail,
            evidence=(mode_ex.data[:256].hex() if mode_ex.data else ""),
            fidelity="high",
        ),
        (
            skipped_indicator(
                *_spec("tftp.wrq_stub"),
                wrq_detail,
                protocol="tftp",
                error=wrq_ex.error,
            )
            if wrq_skipped
            else _ind(
                _spec("tftp.wrq_stub"),
                triggered=wrq_hit,
                detail=wrq_detail,
                evidence=(wrq_ex.data[:256].hex() if wrq_ex.data else ""),
                fidelity="high",
            )
        ),
        (
            skipped_indicator(
                *_spec("tftp.option_blindness"),
                option_detail,
                protocol="tftp",
                error=opt_ex.error,
            )
            if opt_skipped
            else _ind(
                _spec("tftp.option_blindness"),
                triggered=option_hit,
                detail=option_detail,
                evidence=(opt_ex.data[:256].hex() if opt_ex.data else ""),
                fidelity="high",
            )
        ),
        _ind(
            _spec("tftp.block_size_violation"),
            triggered=block_hit,
            detail=block_detail,
            evidence=block_evidence,
            fidelity="high",
        ),
        (
            skipped_indicator(
                *_spec("tftp.tid_reuse"),
                tid_reuse_detail,
                protocol="tftp",
                error=second.error,
            )
            if tid_reuse_skipped
            else _ind(
                _spec("tftp.tid_reuse"),
                triggered=tid_reuse_hit,
                detail=tid_reuse_detail,
                evidence=f"baseline_tid={baseline.peer_port};second_tid={second.peer_port}",
                fidelity="high",
            )
        ),
        (
            skipped_indicator(
                *_spec("tftp.response_clone"),
                clone_detail,
                protocol="tftp",
                error=second.error,
            )
            if clone_skipped
            else _ind(
                _spec("tftp.response_clone"),
                triggered=clone_hit,
                detail=clone_detail,
                evidence=(baseline.data[:128].hex() if clone_hit else ""),
                fidelity="high",
            )
        ),
        (
            skipped_indicator(
                *_spec("tftp.no_retransmit"),
                no_rexmit_detail,
                protocol="tftp",
                error=no_rexmit_err,
            )
            if no_rexmit_skipped
            else _ind(
                _spec("tftp.no_retransmit"),
                triggered=no_rexmit_hit,
                detail=no_rexmit_detail,
                evidence=(opt_ex.data[:128].hex() if opt_ex.data else ""),
                fidelity="high",
            )
        ),
        _ind(
            _spec("tftp.stock_payload"),
            triggered=stock_hit,
            detail=stock_detail,
            evidence=stock_text[:200],
            fidelity="medium",
            requires_corroboration=True,
        ),
    ]
    return results


UDP_ENGINE = UDPEngine(name="tftp", probe=probe_tftp)

__all__ = [
    "ERR_FILE_NOT_FOUND",
    "ERR_ILLEGAL_OPERATION",
    "ERR_UNDEFINED",
    "OP_ACK",
    "OP_DATA",
    "OP_ERROR",
    "OP_OACK",
    "OP_RRQ",
    "OP_WRQ",
    "UDP_ENGINE",
    "build_ack",
    "build_data",
    "build_error",
    "build_oack",
    "build_rrq",
    "build_wrq",
    "parse_tftp",
    "probe_tftp",
    "_TFTP_SKIP",
]
