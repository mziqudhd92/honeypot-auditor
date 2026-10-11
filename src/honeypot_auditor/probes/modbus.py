"""Modbus TCP fingerprint engine (MODBUS Application Protocol v1.1b3, TCP).

Strategies (RFC-behavioral, no vendor signatures):
  · state_nonpersist — MBAP transaction ID not echoed across two requests
  · static_signature — MBAP framing violations (protocol ID, length coherence)
  · static_signature — reply to a broadcast (unit ID 255) request
  · static_signature — undefined function code answered normally
  · static_signature — illegal read quantity answered with data

Non-destructive: read-only function codes (Read Coils) and one undefined
function code; never writes registers, coils, or files.
TCP/502 (lab 1502). See docs/strategies/modbus/, MODBUS Application Protocol
specification V1.1b3.
"""

from __future__ import annotations

import secrets
from contextlib import closing

from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason
from honeypot_auditor.probes.common import is_safe_mode, skip_suite
from honeypot_auditor.proxy_transport import create_connection
from honeypot_auditor.settings import settings

_MODBUS_SKIP = (
    ("modbus.trnid_echo", "Modbus transaction ID is not echoed", "state_nonpersist"),
    ("modbus.framing", "Modbus MBAP framing is invalid", "static_signature"),
    (
        "modbus.broadcast_reply",
        "Modbus replies to a broadcast (unit 255) request",
        "static_signature",
    ),
    (
        "modbus.illegal_function",
        "Modbus answers an undefined function code normally",
        "static_signature",
    ),
    (
        "modbus.quantity_check",
        "Modbus serves an illegal read quantity",
        "static_signature",
    ),
)

_FC_READ_COILS = 0x01
_FC_UNDEFINED = 0x4F  # unassigned by the MODBUS spec; high bit clear of 0x80
_UNIT_BROADCAST = 0xFF
_MAX_READ_QTY = 2000  # spec: 1..2000 (0x07D0) for read functions


def _request(trn: int, unit: int, function: int, data: bytes = b"") -> bytes:
    """MBAP header + PDU: TRN(2) PROTO(2)=0 LEN(2) UNIT(1) FC(1) data."""
    pdu = bytes([function]) + data
    header = trn.to_bytes(2, "big") + b"\x00\x00"
    length = (1 + len(pdu)).to_bytes(2, "big")  # unit id + PDU
    return header + length + bytes([unit]) + pdu


def _read_coils(trn: int, unit: int, *, address: int = 0, quantity: int) -> bytes:
    data = address.to_bytes(2, "big") + quantity.to_bytes(2, "big")
    return _request(trn, unit, _FC_READ_COILS, data)


def _recv_exact(sock, count: int) -> bytes:
    """Read up to count bytes; a timeout keeps the partial read (framing evidence)."""
    buf = b""
    while len(buf) < count:
        try:
            chunk = sock.recv(count - len(buf))
        except TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _read_response(sock) -> bytes:
    """Read one MBAP response (header + length-declared body)."""
    header = _recv_exact(sock, 6)
    if len(header) < 6:
        return header
    length = int.from_bytes(header[4:6], "big")
    if not 2 <= length <= 260:  # unit + FC .. max PDU+unit
        return header
    return header + _recv_exact(sock, length)


def _framing_fault(reply: bytes) -> str:
    """MBAP coherence: protocol ID 0 and LEN matching the delivered body."""
    if len(reply) < 8:
        return f"response shorter than MBAP+FC header ({len(reply)}B)"
    proto = int.from_bytes(reply[2:4], "big")
    if proto != 0:
        return f"protocol ID is {proto}, must be 0 for Modbus TCP"
    length = int.from_bytes(reply[4:6], "big")
    if length != len(reply) - 6:
        return f"MBAP length says {length} but {len(reply) - 6} bytes delivered"
    return ""


def _is_exception(reply: bytes, function: int) -> bool:
    return len(reply) >= 9 and reply[7] == (function | 0x80)


def probe_modbus(host: str, port: int) -> list[Indicator]:
    if is_safe_mode():
        return skip_suite(_MODBUS_SKIP, "safe-mode: handshake-only probe", protocol="modbus")
    trn_a, trn_b = secrets.randbelow(65536), secrets.randbelow(65536)
    trn_c, trn_d, trn_e = (
        secrets.randbelow(65536),
        secrets.randbelow(65536),
        secrets.randbelow(65536),
    )
    wire = b""
    try:
        with closing(create_connection(host, port, settings.timeout_seconds)) as sock:
            sock.settimeout(settings.timeout_seconds)
            # One connection, sequential requests (Modbus TCP allows this safely).
            for req in (
                _read_coils(trn_a, 1, quantity=8),  # valid baseline (TRN echo A)
                _read_coils(trn_b, 1, quantity=8),  # valid baseline (TRN echo B)
                _request(trn_c, 1, _FC_UNDEFINED),  # undefined FC -> exception 1
                _read_coils(trn_d, 1, quantity=_MAX_READ_QTY + 1),  # illegal qty
                _read_coils(trn_e, _UNIT_BROADCAST, quantity=8),  # broadcast
            ):
                sock.sendall(req)
                reply = _read_response(sock)
                if reply:
                    wire += reply
                elif not wire:
                    # Silent server: one full timeout is enough evidence; do not
                    # burn four more timeouts on a dead endpoint.
                    break
                # Silence after valid replies is expected for the broadcast.
    except OSError as exc:
        return skip_suite(_MODBUS_SKIP, closed_reason(str(exc)), protocol="modbus", error=str(exc))

    if not wire:
        return skip_suite(
            _MODBUS_SKIP, "no Modbus response (closed, filtered, or silent)", protocol="modbus"
        )

    # Split the concatenated stream back into MBAP responses for per-reply checks.
    replies: list[bytes] = []
    i = 0
    while i + 8 <= len(wire):
        length = int.from_bytes(wire[i + 4 : i + 6], "big")
        total = 6 + length
        replies.append(wire[i : i + total])
        i += total
    if i < len(wire):  # trailing partial frame
        replies.append(wire[i:])

    framing_faults = [f for r in replies if (f := _framing_fault(r))]
    trn_ok = any(r[:2] == trn_a.to_bytes(2, "big") for r in replies) or any(
        r[:2] == trn_b.to_bytes(2, "big") for r in replies
    )
    # Broadcast: unit 255 requests must draw NO response at all.
    broadcast_replies = [
        r
        for r in replies
        if len(r) >= 8 and r[6] == _UNIT_BROADCAST and r[:2] == trn_e.to_bytes(2, "big")
    ]
    # A canned always-reply server answers the broadcast with a fixed TRN and any
    # unit — five replies to five requests (broadcast last) proves it.
    if len(replies) > 4 and not broadcast_replies:
        broadcast_replies = [replies[-1]]
    undefined_normal = [
        r
        for r in replies
        if len(r) >= 8 and r[:2] == trn_c.to_bytes(2, "big") and not _is_exception(r, _FC_UNDEFINED)
    ]
    qty_normal = [
        r
        for r in replies
        if len(r) >= 8
        and r[:2] == trn_d.to_bytes(2, "big")
        and not _is_exception(r, _FC_READ_COILS)
    ]

    evidence = "; ".join(f"len={len(r)}" for r in replies[:6])
    return [
        Indicator(
            id="modbus.trnid_echo",
            title="Modbus transaction ID is not echoed",
            category="state_nonpersist",
            triggered=not trn_ok,
            protocol="modbus",
            detail=(
                "no response echoed its MBAP transaction ID (spec: the response "
                "transaction ID is the request's) — canned responder"
                if not trn_ok
                else "transaction IDs echoed correctly"
            ),
            evidence=evidence,
            remediation="Copy the request transaction ID into every MBAP response",
        ),
        Indicator(
            id="modbus.framing",
            title="Modbus MBAP framing is invalid",
            category="static_signature",
            triggered=bool(framing_faults),
            protocol="modbus",
            detail="; ".join(framing_faults) if framing_faults else "MBAP framing conforms",
            evidence=evidence,
            remediation="Emit protocol ID 0 and a length matching the delivered body",
        ),
        Indicator(
            id="modbus.broadcast_reply",
            title="Modbus replies to a broadcast (unit 255) request",
            category="static_signature",
            triggered=bool(broadcast_replies),
            protocol="modbus",
            detail=(
                "broadcast request (unit ID 255) drew a response — spec requires silence"
                if broadcast_replies
                else "broadcast request stayed silent, as required"
            ),
            evidence=evidence,
            remediation="Never answer broadcast (unit 255) requests",
        ),
        Indicator(
            id="modbus.illegal_function",
            title="Modbus answers an undefined function code normally",
            category="static_signature",
            triggered=bool(undefined_normal),
            protocol="modbus",
            detail=(
                "undefined function 0x4f answered with data instead of ILLEGAL FUNCTION"
                if undefined_normal
                else "undefined function code answered with an exception"
            ),
            evidence=evidence,
            remediation="Answer unsupported function codes with exception 01 (ILLEGAL FUNCTION)",
        ),
        Indicator(
            id="modbus.quantity_check",
            title="Modbus serves an illegal read quantity",
            category="static_signature",
            triggered=bool(qty_normal),
            protocol="modbus",
            detail=(
                "Read Coils with quantity 2001 (> spec max 2000) answered with data "
                "instead of ILLEGAL DATA VALUE"
                if qty_normal
                else "illegal read quantity rejected with an exception"
            ),
            evidence=evidence,
            remediation="Validate read quantity (1..2000) and answer exception 03",
        ),
    ]
