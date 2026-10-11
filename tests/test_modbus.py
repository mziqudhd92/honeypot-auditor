"""Modbus TCP RFC-behavioral probe tests."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.modbus as modbus


class ScriptedSock:
    """Answers MBAP requests per a policy function; records sent bytes."""

    def __init__(self, policy) -> None:
        self._policy = policy
        self.sent: list[bytes] = []
        self._buf = bytearray()

    def settimeout(self, value) -> None:
        return None

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)
        reply = self._policy(data)
        if reply:
            self._buf.extend(reply)

    def recv(self, size: int) -> bytes:
        if not self._buf:
            raise TimeoutError()
        chunk = bytes(self._buf[:size])
        del self._buf[:size]
        return chunk

    def close(self) -> None:
        return None


def _mbap(trn: int, unit: int, function: int, data: bytes = b"") -> bytes:
    return modbus._request(trn, unit, function, data)


def _plc_policy(request: bytes) -> bytes:
    """Conformant PLC: echoes TRN, proto 0, correct length, proper exceptions."""

    def response(trn: int, unit: int, fc: int, data: bytes) -> bytes:
        return _mbap(trn, unit, fc, data)

    trn = int.from_bytes(request[:2], "big")
    unit = request[6]
    fc = request[7]
    if unit == 0xFF:
        return b""  # broadcast: silence
    if fc == 0x4F:
        return response(trn, unit, fc | 0x80, b"\x01")  # ILLEGAL FUNCTION
    qty = int.from_bytes(request[10:12], "big")
    if fc == 0x01 and not 1 <= qty <= 2000:
        return response(trn, unit, fc | 0x80, b"\x03")  # ILLEGAL DATA VALUE
    if fc == 0x01:
        return response(trn, unit, fc, b"\x01\x55")  # 1 byte of coils
    return response(trn, unit, fc | 0x80, b"\x01")


def _run(policy):
    sock = ScriptedSock(policy)
    with patch.object(modbus, "create_connection", return_value=sock):
        return modbus.probe_modbus("127.0.0.1", 502), sock


def test_conformant_plc_is_clean():
    inds, _sock = _run(_plc_policy)
    by_id = {i.id: i for i in inds}
    assert not any(i.triggered for i in inds)
    assert not any(i.skipped for i in inds)
    assert by_id["modbus.trnid_echo"].detail.startswith("transaction IDs echoed")


def test_fixed_trn_responder_fires_trn_echo():
    def canned(request: bytes) -> bytes:
        # ignores the request entirely: fixed TRN, always data
        return _mbap(0x1234, request[6], 0x01, b"\x01\x55")

    inds, _sock = _run(canned)
    by_id = {i.id: i for i in inds}
    assert by_id["modbus.trnid_echo"].triggered
    assert by_id["modbus.broadcast_reply"].triggered  # canned server answers broadcasts too


def test_nonzero_protocol_id_is_framing_fault():
    def bad_proto(request: bytes) -> bytes:
        reply = bytearray(_plc_policy(request))
        if reply:
            reply[2:4] = b"\x00\x01"  # protocol ID 1
        return bytes(reply)

    inds, _sock = _run(bad_proto)
    by_id = {i.id: i for i in inds}
    assert by_id["modbus.framing"].triggered
    assert "protocol ID is 1" in by_id["modbus.framing"].detail


def test_length_mismatch_is_framing_fault():
    def bad_len(request: bytes) -> bytes:
        reply = bytearray(_plc_policy(request))
        if reply:
            reply[4:6] = (int.from_bytes(reply[4:6], "big") + 1).to_bytes(2, "big")
        return bytes(reply)

    inds, _sock = _run(bad_len)
    assert {i.id: i for i in inds}["modbus.framing"].triggered


def test_broadcast_reply_is_a_tell():
    def answers_broadcast(request: bytes) -> bytes:
        return _plc_policy(bytearray(request[:6]) + b"\x01" + request[7:])  # treat as unit 1

    inds, _sock = _run(answers_broadcast)
    by_id = {i.id: i for i in inds}
    assert by_id["modbus.broadcast_reply"].triggered
    assert "unit ID 255" in by_id["modbus.broadcast_reply"].detail


def test_undefined_function_answered_normally_is_a_tell():
    def serves_anything(request: bytes) -> bytes:
        trn = int.from_bytes(request[:2], "big")
        return _mbap(trn, request[6], request[7], b"\x01\x55")

    inds, _sock = _run(serves_anything)
    by_id = {i.id: i for i in inds}
    assert by_id["modbus.illegal_function"].triggered
    assert "0x4f" in by_id["modbus.illegal_function"].detail


def test_illegal_quantity_served_is_a_tell():
    def no_validation(request: bytes) -> bytes:
        trn = int.from_bytes(request[:2], "big")
        qty = int.from_bytes(request[10:12], "big")
        nbytes = (qty + 7) // 8
        return _mbap(trn, request[6], request[7], bytes([nbytes]) + b"\x00" * nbytes)

    inds, _sock = _run(no_validation)
    by_id = {i.id: i for i in inds}
    assert by_id["modbus.quantity_check"].triggered
    assert "2001" in by_id["modbus.quantity_check"].detail


def test_silent_server_skips_after_one_timeout():
    sock = ScriptedSock(lambda request: b"")
    with patch.object(modbus, "create_connection", return_value=sock):
        inds = modbus.probe_modbus("127.0.0.1", 502)
    assert all(i.skipped for i in inds)
    assert len(sock.sent) == 1  # bailed after the first timeout, not five


def test_connection_error_skips_suite():
    with patch.object(modbus, "create_connection", side_effect=OSError("refused")):
        inds = modbus.probe_modbus("127.0.0.1", 502)
    assert len(inds) == len(modbus._MODBUS_SKIP)
    assert all(i.skipped for i in inds)


def test_request_builder_shape():
    req = modbus._read_coils(0x0102, 1, quantity=8)
    assert req[:2] == b"\x01\x02"  # TRN
    assert req[2:4] == b"\x00\x00"  # protocol ID
    assert req[4:6] == b"\x00\x06"  # unit + FC + addr(2) + qty(2)
    assert req[6] == 1 and req[7] == 0x01
