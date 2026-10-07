"""NetBIOS RFC 1001/1002 behavioral probe tests (NBNS + session service)."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.udp.netbios as netbios
from honeypot_auditor.netutil import UdpExchange


class _FakeTcpSock:
    def __init__(self, wire: bytes) -> None:
        self._wire = wire
        self.sent: list[bytes] = []

    def settimeout(self, value) -> None:
        return None

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        chunk = self._wire[:size]
        self._wire = self._wire[len(chunk) :]
        return chunk

    def close(self) -> None:
        return None


def _nbns_reply(trn: int, *, flags: int = 0x8000, qd: int = 1, an: int = 1) -> bytes:
    """Minimal RFC 1002 header-shaped NBNS response."""
    return (
        trn.to_bytes(2, "big")
        + flags.to_bytes(2, "big")
        + qd.to_bytes(2, "big")
        + an.to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
    )


def _nbns_exchanges(replies: list[bytes]):
    def side_effect(host, port, payload, timeout=None):
        data = replies.pop(0) if replies else b""
        return UdpExchange(
            data=data, peer_host=host, peer_port=137, rtt_ms=0.4, error="" if data else "timeout"
        )

    return side_effect


def test_netbios_trn_echo_is_clean():
    """Both NBSTAT replies echo their request TRN ID — RFC 1002 conformant."""

    def echo_back(host, port, payload, timeout=None):
        trn = int.from_bytes(payload[:2], "big")
        return UdpExchange(
            data=_nbns_reply(trn), peer_host=host, peer_port=137, rtt_ms=0.4, error=""
        )

    with patch.object(netbios, "udp_exchange", side_effect=echo_back):
        inds = netbios.probe_nbns("127.0.0.1", 137)
    by_id = {i.id: i for i in inds}
    assert not by_id["netbios.trnid_echo"].triggered
    assert not by_id["netbios.canned_nbstat"].triggered
    assert not by_id["netbios.framing"].triggered


def test_netbios_fixed_trn_and_canned_clone_fire():
    fixed = _nbns_reply(0x1234)
    with patch.object(netbios, "udp_exchange", side_effect=_nbns_exchanges([fixed, fixed])):
        inds = netbios.probe_nbns("127.0.0.1", 137)
    by_id = {i.id: i for i in inds}
    assert by_id["netbios.trnid_echo"].triggered
    assert by_id["netbios.canned_nbstat"].triggered
    assert "distinct queried names" in by_id["netbios.canned_nbstat"].detail


def test_netbios_missing_response_bit_is_framing_fault():
    def echo_clear_qr(host, port, payload, timeout=None):
        trn = int.from_bytes(payload[:2], "big")
        return UdpExchange(
            data=_nbns_reply(trn, flags=0x0000),  # QR bit clear: not a response
            peer_host=host,
            peer_port=137,
            rtt_ms=0.4,
            error="",
        )

    with patch.object(netbios, "udp_exchange", side_effect=echo_clear_qr):
        inds = netbios.probe_nbns("127.0.0.1", 137)
    by_id = {i.id: i for i in inds}
    assert by_id["netbios.framing"].triggered
    assert "response bit" in by_id["netbios.framing"].detail
    assert not by_id["netbios.trnid_echo"].triggered


def test_netbios_no_reply_skips_suite():
    with patch.object(netbios, "udp_exchange", side_effect=_nbns_exchanges([b"", b""])):
        inds = netbios.probe_nbns("127.0.0.1", 137)
    assert all(i.skipped for i in inds)


def test_netbios_negative_session_is_clean():
    sock = _FakeTcpSock(b"\x83\x00\x00\x04\x00\x00\x00\x00")
    with patch.object(netbios, "create_connection", return_value=sock):
        inds = netbios.probe_ssn("127.0.0.1", 139)
    by_id = {i.id: i for i in inds}
    assert not by_id["netbios.session_grant"].triggered
    assert not by_id["netbios.session_framing"].triggered
    assert sock.sent, "session request was not sent"


def test_netbios_session_granted_for_any_name_is_a_tell():
    sock = _FakeTcpSock(b"\x82\x00\x00\x04\x00\x00\x00\x00")
    with patch.object(netbios, "create_connection", return_value=sock):
        inds = netbios.probe_ssn("127.0.0.1", 139)
    by_id = {i.id: i for i in inds}
    assert by_id["netbios.session_grant"].triggered
    assert "nonexistent called name" in by_id["netbios.session_grant"].detail


def test_netbios_invalid_session_response_type_is_framing():
    sock = _FakeTcpSock(b"\x7f\x00\x00\x02\x00\x00")
    with patch.object(netbios, "create_connection", return_value=sock):
        inds = netbios.probe_ssn("127.0.0.1", 139)
    by_id = {i.id: i for i in inds}
    assert by_id["netbios.session_framing"].triggered
    assert "0x7f" in by_id["netbios.session_framing"].detail


def test_netbios_port_dispatch():
    assert netbios._NBNS_PORTS == frozenset({137, 1137})
    # SSN dispatch is exercised via probe_ssn above; probe_netbios routes by port.
    with patch.object(netbios, "probe_ssn") as ssn:
        netbios.probe_netbios("127.0.0.1", 139)
    assert ssn.called
