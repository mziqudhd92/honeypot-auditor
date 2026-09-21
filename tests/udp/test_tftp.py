"""TFTP RFC 1350 / 2347 light probe tests (MockUDPTransceiver, no live network)."""

from __future__ import annotations

from typing import Any

import pytest

import honeypot_auditor.probes.udp.tftp as tftp
from honeypot_auditor.config import PROTOCOL_STRATEGIES
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.settings import settings

_DST = 69
_TID = 49152  # ephemeral Transfer ID (≠ dst)
_TID2 = 49153

# Bound by autouse fixture from conftest ``mock_udp_cls`` (avoid importing conftest).
_MockUDP: Any = None
Reply = tuple[bytes, int, float, str]


@pytest.fixture(autouse=True)
def _bind_mock_udp(mock_udp_cls: type):
    global _MockUDP
    _MockUDP = mock_udp_cls
    yield
    _MockUDP = None


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


def _reply(data: bytes, *, peer_port: int = _TID, rtt_ms: float = 2.0) -> Reply:
    return (data, peer_port, rtt_ms, "")


def _timeout() -> Reply:
    return (b"", 0, 0.0, "timed out")


def _second_rrq(*, peer_port: int = _TID2, data: bytes | None = None) -> Reply:
    """Independent missing-file RRQ (distinct TID by default)."""
    return _reply(data if data is not None else _error(), peer_port=peer_port)


def _opt_pair(first: Reply, rexmit: Reply | None = None) -> list[Reply]:
    """Option RRQ first reply + idle retransmit listen."""
    return [first, rexmit if rexmit is not None else _reply(_oack())]


def _conformant_replies() -> list[Reply]:
    """Real tftpd: distinct TIDs, mode reject, WRQ ACK, OACK + retransmit."""
    return [
        _reply(_error()),
        _second_rrq(),
        _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
        _reply(_ack(0)),
        *_opt_pair(_reply(_oack()), _reply(_oack())),
    ]


def _run(replies: list[Reply], *, port: int = _DST):
    mock = _MockUDP(replies)
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
    assert by_id["tftp.mode_facade"].skipped is False
    assert not by_id["tftp.wrq_stub"].triggered
    assert not by_id["tftp.option_blindness"].triggered
    assert not by_id["tftp.tid_reuse"].triggered
    assert not by_id["tftp.response_clone"].triggered
    assert not by_id["tftp.no_retransmit"].triggered
    assert not by_id["tftp.stock_payload"].triggered
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
            _reply(_error(), peer_port=_DST),
            _second_rrq(peer_port=_TID2),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack()), _reply(_oack())),
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
            _reply(_data(1, b"hello")),
            _second_rrq(data=_error()),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack()), _reply(_oack())),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.opcode_facade"].triggered
    assert by_id["tftp.error_stub"].triggered


def test_tftp_error_stub_on_out_of_range_code():
    inds, _ = _run(
        [
            _reply(_error(99, "wat")),
            _second_rrq(),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack()), _reply(_oack())),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.error_stub"].triggered
    assert not by_id["tftp.opcode_facade"].triggered


def test_tftp_mode_facade_serves_data_for_illegal_mode():
    inds, _ = _run(
        [
            _reply(_error()),
            _second_rrq(),
            _reply(_data(1, b"x")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack()), _reply(_oack())),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.mode_facade"].triggered
    assert not by_id["tftp.error_stub"].triggered


def test_tftp_wrq_stub_on_data_reply():
    inds, _ = _run(
        [
            _reply(_error()),
            _second_rrq(),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_data(1, b"nope")),
            *_opt_pair(_reply(_oack()), _reply(_oack())),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.wrq_stub"].triggered


def test_tftp_option_blindness_on_error_zero_empty():
    inds, mock = _run(
        [
            _reply(_error()),
            _second_rrq(),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_error(tftp.ERR_UNDEFINED, "")), _timeout()),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.option_blindness"].triggered
    assert by_id["tftp.no_retransmit"].skipped
    assert any(c["payload"][:2] == b"\x00\x01" and b"blksize" in c["payload"] for c in mock.calls)


def test_tftp_tid_reuse_across_transfers():
    inds, _ = _run(
        [
            _reply(_error(), peer_port=_TID),
            _second_rrq(peer_port=_TID),  # same ephemeral TID
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack()), _reply(_oack())),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.tid_reuse"].triggered
    assert by_id["tftp.tid_reuse"].category == "state_nonpersist"
    assert not by_id["tftp.fixed_source_port"].triggered


def test_tftp_response_clone_on_identical_data():
    lure = _data(1, b"canned")
    inds, _ = _run(
        [
            _reply(lure),
            _second_rrq(data=lure),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack()), _reply(_oack())),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.response_clone"].triggered
    assert by_id["tftp.opcode_facade"].triggered


def test_tftp_identical_file_not_found_is_not_clone():
    """Normal tftpd often returns the same File not found ERROR for any missing name."""
    err = _error()
    inds, _ = _run(
        [
            _reply(err),
            _second_rrq(data=err),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack()), _reply(_oack())),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["tftp.response_clone"].triggered


def test_tftp_no_retransmit_on_one_shot_oack():
    inds, _ = _run(
        [
            _reply(_error()),
            _second_rrq(),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack()), _timeout()),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.no_retransmit"].triggered
    assert not by_id["tftp.option_blindness"].triggered


def test_tftp_stock_payload_requires_corroboration():
    inds, _ = _run(
        [
            _reply(_error(tftp.ERR_FILE_NOT_FOUND, "honeypot tftp stub")),
            _second_rrq(),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack()), _reply(_oack())),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.stock_payload"].triggered
    assert by_id["tftp.stock_payload"].requires_corroboration is True
    assert not by_id["tftp.error_stub"].triggered
    assert not by_id["tftp.opcode_facade"].triggered


def test_tftp_stock_payload_from_later_exchange_despite_clean_baseline():
    """Clean baseline ERROR text must not mask a lure token on a later DATA reply."""
    inds, _ = _run(
        [
            _reply(_error()),
            _second_rrq(),
            _reply(_data(1, b"conpot tftp lure")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack()), _reply(_oack())),
        ]
    )
    by_id = {ind.id: ind for ind in inds}
    assert by_id["tftp.mode_facade"].triggered
    assert by_id["tftp.stock_payload"].triggered
    assert "conpot" in by_id["tftp.stock_payload"].detail


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
    assert "TID reuse" in row["state_nonpersist"]
    assert (
        "clone" in row["static_signature"].lower()
        or "retransmit" in row["static_signature"].lower()
    )
    assert tftp.UDP_ENGINE.name == "tftp"
    assert tftp.UDP_ENGINE.probe is tftp.probe_tftp


def test_tftp_uses_udp_exchange_to_for_oack_ack():
    """After OACK from an ephemeral TID, ACK options via udp_exchange_to (no DATA upload)."""
    inds, mock = _run(
        [
            _reply(_error()),
            _second_rrq(),
            _reply(_error(tftp.ERR_ILLEGAL_OPERATION, "Illegal TFTP operation")),
            _reply(_ack(0)),
            *_opt_pair(_reply(_oack(), peer_port=_TID), _reply(_oack(), peer_port=_TID)),
            _reply(_error()),
        ]
    )
    assert not any(ind.triggered for ind in inds)
    assert any(c["port"] == _TID for c in mock.calls)


def test_tftp_ports_in_presets():
    from honeypot_auditor.config import (
        PORT_PRESET_DOCKER_RESEARCH,
        PORT_PRESET_IANA,
        probe_port_map,
    )

    assert PORT_PRESET_IANA["tftp"] == 69
    assert PORT_PRESET_DOCKER_RESEARCH["tftp"] == 1069
    both = probe_port_map("both")
    assert 69 in both["tftp"]
    assert 1069 in both["tftp"]
