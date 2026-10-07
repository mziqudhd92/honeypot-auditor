"""DHCP fingerprint engine (RFC 2131).

UDP 67 (lab 1067). The client side of DHCP is privileged — the probe binds the
client port 68, so it is capability-gated and skips cleanly without root/admin.

RFC-behavioral strategies (no product signatures):
  · state_nonpersist — transaction ID (xid) not echoed across two DISCOVERs
    (RFC 2131 §4.1: "The transaction ID ... MUST be copied from the request")
  · static_signature — BOOTP framing violations: short reply, wrong op (must be
    BOOTREPLY), missing magic cookie, missing/invalid DHCP message-type option,
    or DHCPACK/NAK to a DISCOVER (RFC 2131 §4.3.1 requires DHCPOFFER)
  · static_signature — bitwise-identical OFFER for two DISCOVERs with distinct
    xid and chaddr (canned responder)

Non-destructive: DISCOVER never allocates a lease (that is REQUEST), and the
probe never REQUESTs the offered address.
"""

from __future__ import annotations

import secrets
import socket

from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason
from honeypot_auditor.probes.common import skip_suite
from honeypot_auditor.probes.udp._engine import UDPEngine
from honeypot_auditor.settings import settings

_BOOTREPLY_OP = 2
_MAGIC_COOKIE = b"\x63\x82\x53\x63"
_MSG_OFFER = 2
_CLIENT_PORT = 68

_DHCP_SKIP = (
    ("dhcp.xid_echo", "DHCP transaction ID is not echoed", "state_nonpersist"),
    ("dhcp.framing", "DHCP reply violates RFC 2131 framing", "static_signature"),
    (
        "dhcp.canned_offer",
        "DHCP OFFER is a canned clone across distinct DISCOVERs",
        "static_signature",
    ),
)


def _build_discover(xid: int, chaddr: bytes) -> bytes:
    """RFC 2131 §2 fixed fields + cookie + options 53 (DISCOVER), 61, 55, end."""
    packet = bytearray(236)
    packet[0] = 1  # op: BOOTREQUEST
    packet[1] = 1  # htype: ethernet
    packet[2] = 6  # hlen
    packet[3] = 0  # hops
    packet[4:8] = xid.to_bytes(4, "big")
    packet[10:12] = (0x8000).to_bytes(2, "big")  # flags: broadcast
    packet[28:34] = chaddr
    packet[236:240] = _MAGIC_COOKIE
    options = bytearray()
    options += b"\x35\x01\x01"  # option 53: DHCPDISCOVER
    options += b"\x3d\x07\x01" + chaddr  # option 61: client identifier (type 1 = MAC)
    options += b"\x37\x04\x01\x03\x06\x0f"  # option 55: subnet, router, dns, domain
    options += b"\xff"  # end
    return bytes(packet) + bytes(options)


def _dhcp_message_type(reply: bytes) -> int:
    """Option 53 value from a BOOTP reply (0 when absent)."""
    options = reply[240:]
    i = 0
    while i < len(options):
        tag = options[i]
        if tag == 0xFF:
            break
        if tag == 0x00:
            i += 1
            continue
        if i + 1 >= len(options):
            break
        length = options[i + 1]
        if tag == 53 and i + 2 < len(options):
            return options[i + 2]
        i += 2 + length
    return 0


def _dhcp_exchange_pair(host: str, port: int) -> tuple[bytes, int, bytes, int, str]:
    """Two DISCOVERs (distinct xid/chaddr) from the privileged client port.

    Returns (reply_a, xid_a, reply_b, xid_b, error). Empty replies with no
    error mean the target never answered (treated as closed/filtered).
    """
    chaddr_a = secrets.token_bytes(6)
    chaddr_b = secrets.token_bytes(6)
    xid_a, xid_b = secrets.randbelow(1 << 32), secrets.randbelow(1 << 32)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("0.0.0.0", _CLIENT_PORT))
        sock.settimeout(settings.timeout_seconds)
        sock.sendto(_build_discover(xid_a, chaddr_a), (host, port))
        reply_a = b""
        try:
            reply_a, _peer = sock.recvfrom(1024)
        except TimeoutError:
            pass
        sock.sendto(_build_discover(xid_b, chaddr_b), (host, port))
        reply_b = b""
        try:
            reply_b, _peer = sock.recvfrom(1024)
        except TimeoutError:
            pass
        return reply_a, xid_a, reply_b, xid_b, ""
    except OSError as exc:
        return b"", xid_a, b"", xid_b, closed_reason(str(exc))
    finally:
        sock.close()


def _framing_fault(reply: bytes) -> str:
    if len(reply) < 240 or reply[236:240] != _MAGIC_COOKIE:
        return f"reply is not BOOTP+DHCP framing ({len(reply)}B, cookie missing)"
    if reply[0] != _BOOTREPLY_OP:
        return f"op is {reply[0]}, BOOTREPLY (2) required"
    msg_type = _dhcp_message_type(reply)
    if msg_type == 0:
        return "no DHCP message-type option (53) in reply"
    if msg_type != _MSG_OFFER:
        return f"option 53 = {msg_type} — DISCOVER must be answered with DHCPOFFER (2)"
    return ""


def probe_dhcp(host: str, port: int) -> list[Indicator]:
    try:
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe_sock.bind(("0.0.0.0", _CLIENT_PORT))
        finally:
            probe_sock.close()
    except OSError as exc:
        reason = (
            "capability: DHCP probes bind the privileged client port 68 "
            f"(run elevated) — bind failed: {closed_reason(str(exc))}"
        )
        return skip_suite(_DHCP_SKIP, reason, protocol="dhcp", error=str(exc))

    reply_a, xid_a, reply_b, xid_b, error = _dhcp_exchange_pair(host, port)
    replies = [r for r in (reply_a, reply_b) if r]
    if not replies:
        reason = error or "no DHCP reply (closed, filtered, or silent)"
        return skip_suite(_DHCP_SKIP, reason, protocol="dhcp", error=error)

    framing_faults = [f for r in replies if (f := _framing_fault(r))]

    # RFC 2131 §4.1: the reply MUST copy the request xid. A responder that
    # answers two distinct xids with the same (or no) xid is canned.
    echo_ok = bool(reply_a and reply_a[4:8] == xid_a.to_bytes(4, "big")) or bool(
        reply_b and reply_b[4:8] == xid_b.to_bytes(4, "big")
    )
    xid_hit = not echo_ok

    canned_hit = ""
    if len(replies) >= 2:
        if reply_a == reply_b:
            canned_hit = "identical OFFER bytes for two DISCOVERs with distinct xid/chaddr"
        else:
            mask_a = bytearray(reply_a)
            mask_b = bytearray(reply_b)
            for masked in (mask_a, mask_b):
                masked[4:8] = b"\x00\x00\x00\x00"  # xid
                masked[28:44] = b"\x00" * 16  # chaddr
            if bytes(mask_a) == bytes(mask_b):
                canned_hit = "OFFERS identical apart from xid/chaddr (canned template)"

    evidence = "; ".join(f"reply {n}: {len(r)}B" for n, r in enumerate(replies, 1))
    return [
        Indicator(
            id="dhcp.xid_echo",
            title="DHCP transaction ID is not echoed",
            category="state_nonpersist",
            triggered=xid_hit,
            protocol="dhcp",
            detail=(
                "neither DISCOVER reply echoed its request xid (RFC 2131 §4.1 requires "
                "the xid be copied) — canned responder"
                if xid_hit
                else "xid echoed correctly across DISCOVERs"
            ),
            evidence=evidence,
            remediation="Copy the request xid into the reply (RFC 2131 §4.1)",
        ),
        Indicator(
            id="dhcp.framing",
            title="DHCP reply violates RFC 2131 framing",
            category="static_signature",
            triggered=bool(framing_faults),
            protocol="dhcp",
            detail="; ".join(framing_faults) if framing_faults else "BOOTP framing conforms",
            evidence=evidence,
            remediation="Answer DHCPOFFER with RFC 2131 fixed fields, cookie, and option 53",
        ),
        Indicator(
            id="dhcp.canned_offer",
            title="DHCP OFFER is a canned clone across distinct DISCOVERs",
            category="static_signature",
            triggered=bool(canned_hit),
            protocol="dhcp",
            detail=canned_hit or "OFFERs differ across distinct DISCOVERs",
            evidence=evidence,
            remediation="Vary offers per client and copy request fields",
        ),
    ]


UDP_ENGINE = UDPEngine(name="dhcp", probe=probe_dhcp)

__all__ = ["UDP_ENGINE", "probe_dhcp"]
