"""TFTP RFC 1350 / 2347 light probe tests (MockUDPTransceiver, no live network)."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.udp.tftp as tftp
from honeypot_auditor.config import PROTOCOL_STRATEGIES
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.settings import settings
from tests.udp.conftest import MockUDPTransceiver, ScriptedReply

_DST = 69
_TID = 49152  # ephemeral Transfer ID (≠ dst)


def _error(
    code: int = tftp.ERR_FILE_NOT_FOUND,
    message: str = "File not found",
) -> bytes:
    return tftp.build_error(code, message)


def _data(block: int = 1, payload: bytes = b"lure") -> bytes:
    return tftp.build_data(block, payload)


def _ack(block: int = 0) -> bytes:
    return tftp.build_ack(block)


def _oack(options: dict[str, str] | None = None) -> bytes:
    return tftp.build_oack(options or {"blksize": "512"})


def _reply(data: bytes, *, peer_port: int = _TID, rtt_ms: float = 2.0) -> ScriptedReply:
    return ScriptedReply(data=data, peer_port=peer_port, rtt_ms=rtt_ms, error="")


def _timeout() -> ScriptedReply:
    return ScriptedReply(data=b"", peer_port=0, rtt_ms=0.0, error="timed out")


def _conformant_replies() -> list[ScriptedReply]:
    """Real tftpd shape: ERROR from ephemeral TID; reject bad mode; ACK WRQ; OACK options."""
    return [
        _reply(_error()),  # baseline RRQ missing file
        _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),  # bad mode
        _reply(_ack(0)),  # WRQ → ACK block 0
        _reply(_oack()),  # RRQ+blksize → OACK
    ]


def _run(replies: list[ScriptedReply], *, port: int = _DST):
    mock = MockUDPTransceiver(replies)
    with mock.patch("honeypot_auditor.probes.udp.tftp"):
        return tftp.probe_tftp("127.0.0.1", port), mock


def test_tftp_packet_builders_round_trip():
    rrq = tftp.build_rrq("hpaudit.bin", "octet")
    assert rrq[:2] == b"\x00\x01"
    wrq = tftp.build_wrq("hpaudit.bin", "octet")
    assert wrq[:2] == b"\x00\x02"
    opt = tftp.build_rrq("hpaudit.bin", "octet", options={"blksize": "512"})
    assert b"blksize\x00512\x00" in opt
    err = _error()
    parsed = tftp.parse_tftp(err)
    assert parsed is not None
    assert parsed.opcode == tftp.OP_ERROR
    assert parsed.error_code == tftp.ERR_FILE_NOT_FOUND


def test_tftp_conformant_agent_is_clean():
    inds, mock = _run(_conformant_replies())
    assert not any(ind.triggered for ind in inds)
    by_id = {ind.id: ind for ind in inds}
    assert set(by_id) == {spec[0] for spec in tftp._TFTP_SKIP}
    assert by_id["tftp.framing"].skipped is False
    assert by_id["tftp.fixed_source_port"].skipped is False
    assert not by_id["tftp.fixed_source_port"].triggered
    assert not by_id["tftp.opcode_facade"].triggered
    assert not by_id["tftp.error_stub"].triggered
    assert not by_id["tftp.mode_facade"].triggered
    assert not by_id["tftp.wrq_stub"].triggered
    assert not by_id["tftp.option_blindness"].triggered
    assert not by_id["tftp.stock_payload"].triggered
    # First exchange learns TID; option follow-up may use udp_exchange_to.
    assert mock.calls
    assert mock.calls[0]["port"] == _DST
    assert mock.calls[0]["connected"] is False


def test_tftp_framing_on_garbage():
    inds, _ = _run([_reply(b"not-tftp")])
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.framing"].triggered
    assert all(i.skipped or i.id == "tftp.framing" for i in inds)


def test_tftp_fixed_source_port_when_peer_equals_dst():
    """RFC 1350: server must reply from a new TID, not the service port."""
    inds, _ = _run(
        [
            _reply(_error(), peer_port=_DST),  # baseline from 69
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            _reply(_oack()),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.fixed_source_port"].triggered
    assert by_id["tftp.fixed_source_port"].fidelity == "high"
    assert not by_id["tftp.framing"].triggered
    assert not by_id["tftp.error_stub"].triggered


def test_tftp_opcode_facade_on_data_for_rrq():
    inds, _ = _run(
        [
            _reply(_data(1, b"hello")),  # RRQ missing → DATA (facade)
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            _reply(_oack()),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.opcode_facade"].triggered
    assert by_id["tftp.error_stub"].triggered  # missing file served as DATA


def test_tftp_error_stub_on_out_of_range_code():
    inds, _ = _run(
        [
            _reply(_error(99, "wat")),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            _reply(_oack()),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.error_stub"].triggered
    assert not by_id["tftp.opcode_facade"].triggered


def test_tftp_mode_facade_serves_data_for_illegal_mode():
    inds, _ = _run(
        [
            _reply(_error()),
            _reply(_data(1, b"x")),  # illegal mode still DATA
            _reply(_ack(0)),
            _reply(_oack()),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.mode_facade"].triggered
    assert not by_id["tftp.error_stub"].triggered


def test_tftp_wrq_stub_on_data_reply():
    inds, _ = _run(
        [
            _reply(_error()),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_data(1, b"nope")),  # WRQ → DATA
            _reply(_oack()),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.wrq_stub"].triggered


def test_tftp_option_blindness_on_error_zero_empty():
    inds, mock = _run(
        [
            _reply(_error()),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            _reply(_error(tftp.ERR_UNDEFINED, "")),  # options choke
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.option_blindness"].triggered
    # Option RRQ goes to service port; OACK ACK follow-up uses learned TID when present.
    assert any(c["payload"][:2] == b"\x00\x01" and b"blksize" in c["payload"] for c in mock.calls)


def test_tftp_stock_payload_requires_corroboration():
    inds, _ = _run(
        [
            _reply(_error(tftp.ERR_FILE_NOT_FOUND, "honeypot tftp stub")),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            _reply(_oack()),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.stock_payload"].triggered
    assert by_id["tftp.stock_payload"].requires_corroboration is True
    # Stock alone — no other ungated hits in this fixture.
    assert not by_id["tftp.error_stub"].triggered
    assert not by_id["tftp.opcode_facade"].triggered


def test_tftp_safe_mode_framing_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        inds, _ = _run([_reply(_error())])
        by_id = {ind.id: ind for ind in inds}
        assert by_id["tftp.framing"].skipped is False
        assert not by_id["tftp.framing"].triggered
        for ind in inds:
            if ind.id != "tftp.framing":
                assert ind.skipped
                assert "safe-mode" in ind.skip_reason
    finally:
        settings.safe_mode = old


def test_tftp_safe_mode_framing_hit():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        inds, _ = _run([_reply(b"garbage")])
        by_id = {ind.id: ind for ind in inds}
        assert by_id["tftp.framing"].triggered
        assert all(i.skipped or i.id == "tftp.framing" for i in inds)
    finally:
        settings.safe_mode = old


def test_tftp_transport_error_skips_suite():
    inds, _ = _run([_timeout()])
    assert len(inds) == len(tftp._TFTP_SKIP)
    assert all(ind.skipped for ind in inds)
    assert not any(ind.triggered for ind in inds)


def test_tftp_registry_and_strategies():
    assert "tftp" in PROBE_BY_PROTOCOL
    assert PROBE_BY_PROTOCOL["tftp"] is tftp.probe_tftp
    assert "tftp" in PROTOCOL_STRATEGIES
    row = PROTOCOL_STRATEGIES["tftp"]
    assert row["arbitrary_auth"] == ""
    assert row["state_nonpersist"] == ""
    assert "TID" in row["static_signature"] or "fixed" in row["static_signature"].lower()
    assert tftp.UDP_ENGINE.name == "tftp"
    assert tftp.UDP_ENGINE.probe is tftp.probe_tftp


def test_tftp_uses_udp_exchange_to_for_oack_ack():
    """After OACK from an ephemeral TID, ACK options via udp_exchange_to (no DATA upload)."""
    inds, mock = _run(
        [
            _reply(_error()),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            _reply(_oack(), peer_port=_TID),
            _reply(_error()),  # optional post-ACK (ignored / timeout ok)
        ]
    )
    assert not any(ind.triggered for ind in inds)
    # At least one call targeted the learned TID (not only dst 69).
    assert any(c["port"] == _TID for c in mock.calls)


def test_tftp_ports_in_presets():
    from honeypot_auditor.config import PORT_PRESET_DOCKER_RESEARCH, PORT_PRESET_IANA, probe_port_map

    assert PORT_PRESET_IANA["tftp"] == 69
    assert PORT_PRESET_DOCKER_RESEARCH["tftp"] == 1069
    both = probe_port_map("both")
    assert 69 in both["tftp"]
    assert 1069 in both["tftp"]
