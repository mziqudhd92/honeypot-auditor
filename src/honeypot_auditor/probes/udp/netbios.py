"""NetBIOS fingerprint engine (RFC 1001/1002).

Covers both faces an auditor can reach on a single host:
  · NBNS (UDP 137, lab 1137) — Node Status / NBSTAT queries (RFC 1002 §4.2)
  · Session service (TCP 139, lab 1139) — RFC 1002 session protocol

RFC-behavioral strategies (no product signatures):
  · state_nonpersist — transaction ID (TRN ID) not echoed across two queries
  · static_signature — NBNS framing violations, canned node-status clone for
    distinct queried names
  · arbitrary_auth  — session granted for a called name that cannot exist
Non-destructive: name queries and one session request, never any SMB payload.
"""

from __future__ import annotations

import secrets
import string
from contextlib import closing

from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, udp_exchange
from honeypot_auditor.probes.common import skip_suite
from honeypot_auditor.probes.udp._engine import UDPEngine
from honeypot_auditor.proxy_transport import create_connection
from honeypot_auditor.settings import settings

_NBNS_PORTS = frozenset({137, 1137})

_QTYPE_NBSTAT = 0x0021
_QCLASS_IN = 0x0001


def _encode_nbname(name: str) -> bytes:
    """RFC 1001 first-level encoding: 16-byte half-ASCII (15 chars + 0x00 suffix)."""
    padded = name.upper().ljust(15)[:15] + "\x00"
    encoded = "".join(f"{(b >> 4) + 0x41:X}{(b & 0x0F) + 0x41:X}" for b in padded.encode())
    return bytes([len(encoded)]) + encoded.encode("ascii") + b"\x00"


def _random_name() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(10))


def _build_nbstat_query(trn_id: int, name: str) -> bytes:
    """NBSTAT (node status) query — RFC 1002 §4.2.6 packet format, one question."""
    header = trn_id.to_bytes(2, "big") + b"\x00\x10" + b"\x00\x01" + b"\x00" * 6
    question = (
        _encode_nbname(name) + _QTYPE_NBSTAT.to_bytes(2, "big") + _QCLASS_IN.to_bytes(2, "big")
    )
    return header + question


def _nbns_framing_fault(reply: bytes) -> str:
    """RFC 1002 §4.2.1.1 header sanity for a response we did ask for."""
    if len(reply) < 12:
        return f"response shorter than NBNS header ({len(reply)}B)"
    flags = int.from_bytes(reply[2:4], "big")
    if not flags & 0x8000:
        return "response bit (QR) not set — reply is not a response"
    qdcount = int.from_bytes(reply[4:6], "big")
    ancount = int.from_bytes(reply[6:8], "big")
    if qdcount == 0 and ancount == 0:
        return "no question echoed and no answers (empty NBNS reply)"
    return ""


def _nbns_session(host: str, port: int) -> list[tuple[int, bytes, str]]:
    """Two NBSTAT queries with distinct TRN IDs and distinct names."""
    trn_a, trn_b = secrets.randbelow(65536), secrets.randbelow(65536)
    name_a, name_b = _random_name(), _random_name()
    out: list[tuple[int, bytes, str]] = []
    for trn_id, name in ((trn_a, name_a), (trn_b, name_b)):
        try:
            exchange = udp_exchange(
                host,
                port,
                _build_nbstat_query(trn_id, name),
                timeout=settings.timeout_seconds,
            )
        except Exception as exc:
            out.append((trn_id, b"", closed_reason(str(exc))))
            continue
        out.append((trn_id, exchange.data, exchange.error))
    return out


def probe_nbns(host: str, port: int) -> list[Indicator]:
    sessions = _nbns_session(host, port)
    replies = [(trn, data) for trn, data, _err in sessions if data]
    if not replies:
        reason = sessions[0][2] or "no NBNS reply (closed, filtered, or silent)"
        specs = (
            ("netbios.trnid_echo", "NBNS transaction ID is not echoed", "state_nonpersist"),
            ("netbios.framing", "NBNS response violates RFC 1002 framing", "static_signature"),
            (
                "netbios.canned_nbstat",
                "NBNS node status is a canned clone for distinct queried names",
                "static_signature",
            ),
        )
        return skip_suite(specs, reason, protocol="netbios", error=sessions[0][2])

    framing_faults: list[str] = []
    for trn_id, reply in replies:
        fault = _nbns_framing_fault(reply)
        if fault:
            framing_faults.append(fault)

    echoed = any(reply[:2] == trn_id.to_bytes(2, "big") for trn_id, reply in replies)
    trn_hit = len(replies) >= 2 and not echoed

    if len(replies) >= 2 and replies[0][1] == replies[1][1]:
        canned_hit = "identical node-status reply for two distinct queried names"
    else:
        canned_hit = ""

    evidence = "; ".join(f"trn={trn_id:04x} len={len(data)}" for trn_id, data, _e in sessions)
    return [
        Indicator(
            id="netbios.trnid_echo",
            title="NBNS transaction ID is not echoed",
            category="state_nonpersist",
            triggered=trn_hit,
            protocol="netbios",
            detail=(
                "neither NBSTAT reply echoed its request TRN ID (RFC 1002 requires the "
                "transaction ID be copied); canned responders reuse one fixed ID"
                if trn_hit
                else "TRN IDs echoed correctly across queries"
            ),
            evidence=evidence,
            remediation="Echo the request transaction ID in every NBNS response",
        ),
        Indicator(
            id="netbios.framing",
            title="NBNS response violates RFC 1002 framing",
            category="static_signature",
            triggered=bool(framing_faults),
            protocol="netbios",
            detail="; ".join(framing_faults)
            if framing_faults
            else "NBNS header/RR framing conforms",
            evidence=evidence,
            remediation="Emit RFC 1002 header and resource-record framing",
        ),
        Indicator(
            id="netbios.canned_nbstat",
            title="NBNS node status is a canned clone for distinct queried names",
            category="static_signature",
            triggered=bool(canned_hit),
            protocol="netbios",
            detail=canned_hit or "node-status replies differ per queried name (question echoed)",
            evidence=evidence,
            remediation="Echo the queried name in the node-status resource record",
        ),
    ]


def _build_session_request(called: str, calling: str) -> bytes:
    """RFC 1002 §4.3.2 SESSION REQUEST: type 0x81 + length + called + calling names."""
    body = _encode_nbname(called) + _encode_nbname(calling)
    return b"\x81" + len(body).to_bytes(2, "big") + body


def probe_ssn(host: str, port: int) -> list[Indicator]:
    calling = _random_name()
    called = _random_name()  # a name that cannot be registered on any real host
    reply = b""
    error = ""
    try:
        with closing(create_connection(host, port, settings.timeout_seconds)) as sock:
            sock.settimeout(settings.timeout_seconds)
            sock.sendall(_build_session_request(called, calling))
            header = b""
            while len(header) < 4:
                chunk = sock.recv(4 - len(header))
                if not chunk:
                    break
                header += chunk
            if len(header) < 4:
                error = "no session response (closed or silent)"
            else:
                rtype = header[0]
                length = int.from_bytes(header[1:4], "big")
                body = b""
                while len(body) < min(length, 256):
                    chunk = sock.recv(min(length, 256) - len(body))
                    if not chunk:
                        break
                    body += chunk
                reply = header + body
                if rtype == 0x82:
                    error = ""
                elif rtype in (0x83, 0x8F):
                    error = ""  # negative/retarget session response: honest behavior
                else:
                    error = f"invalid session response type 0x{rtype:02x}"
    except OSError as exc:
        error = closed_reason(str(exc))

    granted = bool(reply) and reply[0] == 0x82
    framing_hit = bool(reply) and reply[0] not in (0x82, 0x83, 0x8F)
    skipped = not reply and not error
    return [
        Indicator(
            id="netbios.session_grant",
            title="NetBIOS session granted for any called name",
            category="arbitrary_auth",
            triggered=granted,
            skipped=skipped,
            skip_reason="session service silent/closed" if skipped else "",
            protocol="netbios",
            detail=(
                f"SESSION REQUEST for a nonexistent called name {called!r} was granted "
                "(type 0x82) — real hosts answer negative (0x83) or retarget (0x8F)"
                if granted
                else "session request not granted (negative, retarget, or silence)"
            ),
            evidence=(reply[:24].hex() if reply else ""),
            remediation="Answer RFC 1002 negative session response for unknown called names",
        ),
        Indicator(
            id="netbios.session_framing",
            title="NetBIOS session response violates RFC 1002 framing",
            category="static_signature",
            triggered=framing_hit,
            skipped=skipped,
            skip_reason="session service silent/closed" if skipped else "",
            protocol="netbios",
            detail=(
                error
                if framing_hit or (error and not reply)
                else "session response type conforms (0x82/0x83/0x8F)"
            ),
            evidence=(reply[:24].hex() if reply else ""),
            remediation="Reply with RFC 1002 session response types only (0x82/0x83/0x8F)",
        ),
    ]


def probe_netbios(host: str, port: int) -> list[Indicator]:
    """NBNS on 137/1137, session service on 139/1139 — dispatch by port."""
    if int(port) in _NBNS_PORTS:
        return probe_nbns(host, port)
    return probe_ssn(host, port)


UDP_ENGINE = UDPEngine(name="netbios", probe=probe_netbios)

__all__ = ["UDP_ENGINE", "probe_netbios", "probe_nbns", "probe_ssn"]
