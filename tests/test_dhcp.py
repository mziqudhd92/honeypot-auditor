"""DHCP RFC 2131 behavioral probe tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import honeypot_auditor.probes.udp.dhcp as dhcp


def _offer(
    xid: int, *, op: int = 2, msg_type: int = 2, yiaddr: bytes = b"\x0a\x00\x00\x50"
) -> bytes:
    """Minimal conformant DHCPOFFER."""
    packet = bytearray(240)
    packet[0] = op
    packet[1] = 1
    packet[2] = 6
    packet[4:8] = xid.to_bytes(4, "big")
    packet[16:20] = yiaddr
    packet[236:240] = dhcp._MAGIC_COOKIE
    options = bytes([53, 1, msg_type]) + b"\xff"
    return bytes(packet) + options


def test_dhcp_capability_gate_skips_without_privileged_bind():
    sock = MagicMock()
    sock.bind.side_effect = OSError("operation not permitted")
    with patch.object(dhcp.socket, "socket", return_value=sock):
        inds = dhcp.probe_dhcp("127.0.0.1", 67)
    assert all(i.skipped for i in inds)
    assert any("capability" in i.skip_reason for i in inds)


def test_dhcp_conformant_offer_pair_is_clean():
    # Distinct yiaddr/lease fields per client — a real server varies its offers.
    pair = (
        _offer(0x01020304, yiaddr=b"\x0a\x00\x00\x50"),
        0x01020304,
        _offer(0x05060708, yiaddr=b"\x0a\x00\x00\x51"),
        0x05060708,
        "",
    )
    with patch.object(dhcp, "_dhcp_exchange_pair", return_value=pair):
        inds = dhcp.probe_dhcp("127.0.0.1", 67)
    by_id = {i.id: i for i in inds}
    assert not by_id["dhcp.xid_echo"].triggered
    assert not by_id["dhcp.framing"].triggered
    assert not by_id["dhcp.canned_offer"].triggered


def test_dhcp_fixed_xid_and_clone_fire():
    # Same reply bytes twice: xid cannot match two different requests, and the
    # OFFER payload is a canned clone.
    pair = (_offer(0xAABBCCDD), 0x01020304, _offer(0xAABBCCDD), 0x05060708, "")
    with patch.object(dhcp, "_dhcp_exchange_pair", return_value=pair):
        inds = dhcp.probe_dhcp("127.0.0.1", 67)
    by_id = {i.id: i for i in inds}
    assert by_id["dhcp.xid_echo"].triggered
    assert by_id["dhcp.canned_offer"].triggered
    assert "canned responder" in by_id["dhcp.xid_echo"].detail


def test_dhcp_offers_identical_apart_from_xid_chaddr_is_canned():
    a = bytearray(_offer(0x11111111))
    a[28:34] = b"\xaa" * 6  # distinct chaddr
    b = bytearray(_offer(0x22222222))
    b[28:34] = b"\xbb" * 6
    pair = (bytes(a), 0x11111111, bytes(b), 0x22222222, "")
    with patch.object(dhcp, "_dhcp_exchange_pair", return_value=pair):
        inds = dhcp.probe_dhcp("127.0.0.1", 67)
    by_id = {i.id: i for i in inds}
    assert by_id["dhcp.canned_offer"].triggered
    assert "canned template" in by_id["dhcp.canned_offer"].detail
    assert not by_id["dhcp.xid_echo"].triggered  # xids echoed correctly


def test_dhcp_ack_to_discover_is_a_framing_fault():
    pair = (_offer(0x01020304, msg_type=5), 0x01020304, b"", 0x05060708, "")
    with patch.object(dhcp, "_dhcp_exchange_pair", return_value=pair):
        inds = dhcp.probe_dhcp("127.0.0.1", 67)
    by_id = {i.id: i for i in inds}
    assert by_id["dhcp.framing"].triggered
    assert "DHCPOFFER" in by_id["dhcp.framing"].detail


def test_dhcp_framing_unit_cases():
    bad_cookie = bytearray(_offer(1))
    bad_cookie[236:240] = b"\x00\x00\x00\x00"
    assert "cookie" in dhcp._framing_fault(bytes(bad_cookie))
    assert "framing" in dhcp._framing_fault(b"\x02\x01\x06")
    assert "BOOTREPLY" in dhcp._framing_fault(_offer(1, op=1))
    assert dhcp._framing_fault(_offer(1)) == ""


def test_dhcp_no_reply_skips_suite():
    pair = (b"", 1, b"", 2, "timeout")
    with patch.object(dhcp, "_dhcp_exchange_pair", return_value=pair):
        inds = dhcp.probe_dhcp("127.0.0.1", 67)
    assert all(i.skipped for i in inds)
