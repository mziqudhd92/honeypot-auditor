"""PPTP control-channel non-compliance probe tests (RFC 2637)."""

from __future__ import annotations

import struct
from unittest.mock import patch

import honeypot_auditor.probes.pptp as pptp
from honeypot_auditor.config import PROTOCOL_STRATEGIES
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.settings import settings


def _sccrp(
    *,
    version: int = 0x0100,
    result: int = 1,
    hostname: str = "vpn1",
    vendor: str = "Microsoft",
) -> bytes:
    return struct.pack(
        "!HHIHHHBBIIHH64s64s",
        156,
        1,
        pptp.PPTP_MAGIC,
        2,
        0,
        version,
        result,
        0,
        1,
        1,
        0,
        1,
        hostname.encode().ljust(64, b"\x00")[:64],
        vendor.encode().ljust(64, b"\x00")[:64],
    )


def _echo_reply(identifier: int, *, result: int = 1) -> bytes:
    return struct.pack(
        "!HHIHHIBBH",
        20,
        1,
        pptp.PPTP_MAGIC,
        6,
        0,
        identifier & 0xFFFFFFFF,
        result,
        0,
        0,
    )


def _ocrp(*, result: int = 1, call_id: int = 1, peer: int = 2) -> bytes:
    return struct.pack(
        "!HHIHHHHBB",
        32,
        1,
        pptp.PPTP_MAGIC,
        8,
        0,
        call_id & 0xFFFF,
        peer & 0xFFFF,
        result,
        0,
    ) + b"\x00" * 16


def _stop_ccrp() -> bytes:
    """Honest Stop-Control-Connection-Reply shaped body (not SCCRP)."""
    return struct.pack("!HHIHHBBH", 16, 1, pptp.PPTP_MAGIC, 4, 0, 1, 0, 0)


class _ScriptedTCP:
    """Queue of replies for tcp_transact / tcp_roundtrips patches."""

    def __init__(self, replies: list[bytes | None]):
        self.replies = list(replies)
        self.calls: list[tuple] = []

    def transact(self, host, port, payload=b"", **kwargs):
        self.calls.append(("transact", payload))
        if not self.replies:
            return b"", "timed out"
        item = self.replies.pop(0)
        if item is None:
            return b"", "timed out"
        return item, ""

    def roundtrips(self, host, port, payloads, **kwargs):
        self.calls.append(("roundtrips", list(payloads)))
        out: list[bytes] = []
        for _ in payloads:
            if not self.replies:
                out.append(b"")
                continue
            item = self.replies.pop(0)
            out.append(b"" if item is None else item)
        return out, ""


def _run(replies: list[bytes | None]):
    script = _ScriptedTCP(replies)
    with (
        patch("honeypot_auditor.probes.pptp.tcp_transact", script.transact),
        patch("honeypot_auditor.probes.pptp.tcp_roundtrips", script.roundtrips),
        patch("honeypot_auditor.probes.pptp.jittered_reconnect_pause", lambda: 0.0),
    ):
        return pptp.probe_pptp("127.0.0.1", 1723), script


def _conformant_queue() -> list[bytes | None]:
    """Real PPTP: honest SCCRP, echo ID, deny calls, silence/Stop on garbage."""
    # baseline tcp_transact SCCRQ
    # session roundtrips: SCCRP, Echo-Reply(id), OCRP deny, Stop/empty
    # reconnect: SCCRP, OCRP deny
    # Echo id is unknown until request is built — probe generates it. Capture via
    # side channel by answering whatever ID was sent using a custom roundtrips.
    return [_sccrp()]  # only baseline; custom runner below


def test_pptp_builders_and_parse_round_trip():
    sccrq = pptp.build_sccrq()
    assert len(sccrq) == 156
    assert pptp.parse_control_header(sccrq)["control"] == pptp.CTRL_SCCRQ
    assert len(pptp.build_echo_request(0x11)) == 16
    assert len(pptp.build_ocrq(call_id=7, phone="+15551212")) == 168
    assert len(pptp.build_unknown_control()) == 12

    sccrp = _sccrp()
    msg = pptp.parse_sccrp(sccrp)
    assert msg is not None
    assert msg["version"] == 0x0100
    assert msg["hostname"] == "vpn1"

    er = _echo_reply(0xABCDEF)
    assert pptp.parse_echo_reply(er)["identifier"] == 0xABCDEF
    assert pptp.parse_ocrp(_ocrp(result=1))["result"] == 1


def test_pptp_conformant_device_is_clean():
    """Real PPTP: echo IDs, and establish calls pre-auth with call-id fidelity.

    RFC 2637 call establishment precedes PPP authentication, so an honest
    concentrator answers Outgoing-Call-Requests with Result=1 — but the OCRP
    must echo our Call ID in Peer's Call ID and carry its own distinct,
    non-zero server Call ID. Acceptance alone must never fire `pptp.call_facade`.
    """

    class _Honest(_ScriptedTCP):
        def __init__(self):
            super().__init__([])
            self._server_call_id = 0

        def transact(self, host, port, payload=b"", **kwargs):
            self.calls.append(("transact", payload))
            return _sccrp(), ""

        def roundtrips(self, host, port, payloads, **kwargs):
            self.calls.append(("roundtrips", list(payloads)))
            out: list[bytes] = []
            for payload in payloads:
                ctrl = pptp.parse_control_header(payload)
                if ctrl and ctrl["control"] == pptp.CTRL_SCCRQ:
                    out.append(_sccrp())
                elif ctrl and ctrl["control"] == pptp.CTRL_ECHO_REQ:
                    ident = struct.unpack_from("!I", payload, 12)[0]
                    out.append(_echo_reply(ident))
                elif ctrl and ctrl["control"] == pptp.CTRL_OCRQ:
                    self._server_call_id += 1
                    our_call_id = struct.unpack_from("!H", payload, 12)[0]
                    out.append(
                        _ocrp(result=1, call_id=self._server_call_id, peer=our_call_id)
                    )
                elif ctrl and ctrl["control"] == pptp.CTRL_GARBAGE:
                    out.append(_stop_ccrp())
                else:
                    out.append(b"")
            return out, ""

    import struct

    script = _Honest()
    with (
        patch("honeypot_auditor.probes.pptp.tcp_transact", script.transact),
        patch("honeypot_auditor.probes.pptp.tcp_roundtrips", script.roundtrips),
        patch("honeypot_auditor.probes.pptp.jittered_reconnect_pause", lambda: 0.0),
    ):
        inds = pptp.probe_pptp("127.0.0.1", 1723)
    assert len(inds) == len(pptp._PPTP_SKIP)
    assert {i.id for i in inds} == {row[0] for row in pptp._PPTP_SKIP}
    assert not any(i.triggered for i in inds)


def test_pptp_framing_on_garbage():
    inds, _ = _run([b"not-pptp"])
    by_id = {i.id: i for i in inds}
    assert by_id["pptp.framing"].triggered
    assert all(i.skipped or i.id == "pptp.framing" for i in inds)


def test_pptp_transport_error_skips_suite():
    inds, _ = _run([None])
    assert len(inds) == len(pptp._PPTP_SKIP)
    assert all(i.skipped for i in inds)


def test_pptp_safe_mode_framing_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        inds, _ = _run([_sccrp()])
        by_id = {i.id: i for i in inds}
        assert by_id["pptp.framing"].skipped is False
        assert not by_id["pptp.framing"].triggered
        for ind in inds:
            if ind.id != "pptp.framing":
                assert ind.skipped
    finally:
        settings.safe_mode = old


def test_pptp_version_facade():
    inds, _ = _run(
        [
            _sccrp(version=0x0000),
            _sccrp(version=0x0000),
            _echo_reply(1),
            _ocrp(result=2),
            b"",
            _sccrp(version=0x0000),
            _ocrp(result=2),
        ]
    )
    # echo id won't match — that's ok; version must fire
    by_id = {i.id: i for i in inds}
    assert by_id["pptp.version_facade"].triggered


def test_pptp_stock_vendor_gated():
    inds, _ = _run(
        [
            _sccrp(vendor="Linux PPTP honeypot/1.0"),
            _sccrp(),
            _echo_reply(1),
            _ocrp(result=2),
            b"",
            _sccrp(),
            _ocrp(result=2),
        ]
    )
    by_id = {i.id: i for i in inds}
    assert by_id["pptp.version_facade"].triggered
    assert by_id["pptp.version_facade"].requires_corroboration is True


def test_pptp_echo_id_mismatch():
    class _BadEcho(_ScriptedTCP):
        def transact(self, host, port, payload=b"", **kwargs):
            self.calls.append(("transact", payload))
            return _sccrp(), ""

        def roundtrips(self, host, port, payloads, **kwargs):
            self.calls.append(("roundtrips", list(payloads)))
            out: list[bytes] = []
            for payload in payloads:
                ctrl = pptp.parse_control_header(payload)
                if ctrl and ctrl["control"] == pptp.CTRL_SCCRQ:
                    out.append(_sccrp())
                elif ctrl and ctrl["control"] == pptp.CTRL_ECHO_REQ:
                    out.append(_echo_reply(0x11111111))  # wrong id
                elif ctrl and ctrl["control"] == pptp.CTRL_OCRQ:
                    out.append(_ocrp(result=2))
                else:
                    out.append(_stop_ccrp())
            return out, ""

    script = _BadEcho([])
    with (
        patch("honeypot_auditor.probes.pptp.tcp_transact", script.transact),
        patch("honeypot_auditor.probes.pptp.tcp_roundtrips", script.roundtrips),
        patch("honeypot_auditor.probes.pptp.jittered_reconnect_pause", lambda: 0.0),
    ):
        inds = pptp.probe_pptp("127.0.0.1", 1723)
    by_id = {i.id: i for i in inds}
    assert by_id["pptp.echo_id"].triggered


def test_pptp_call_facade_dual_accept():
    """Result=1 without the Peer's Call-ID echo is fabricated acceptance."""

    class _AnyCall(_ScriptedTCP):
        def transact(self, host, port, payload=b"", **kwargs):
            return _sccrp(), ""

        def roundtrips(self, host, port, payloads, **kwargs):
            out: list[bytes] = []
            for payload in payloads:
                ctrl = pptp.parse_control_header(payload)
                if ctrl and ctrl["control"] == pptp.CTRL_SCCRQ:
                    out.append(_sccrp())
                elif ctrl and ctrl["control"] == pptp.CTRL_ECHO_REQ:
                    ident = struct.unpack_from("!I", payload, 12)[0]
                    out.append(_echo_reply(ident))
                elif ctrl and ctrl["control"] == pptp.CTRL_OCRQ:
                    out.append(_ocrp(result=1, peer=0))  # never echoes
                else:
                    out.append(_stop_ccrp())
            return out, ""

    import struct

    script = _AnyCall([])
    with (
        patch("honeypot_auditor.probes.pptp.tcp_transact", script.transact),
        patch("honeypot_auditor.probes.pptp.tcp_roundtrips", script.roundtrips),
        patch("honeypot_auditor.probes.pptp.jittered_reconnect_pause", lambda: 0.0),
    ):
        inds = pptp.probe_pptp("127.0.0.1", 1723)
    by_id = {i.id: i for i in inds}
    assert by_id["pptp.call_facade"].triggered
    assert by_id["pptp.call_facade"].category == "arbitrary_auth"


def test_pptp_call_facade_hollow_server_call_id():
    """Peer echo present but a zero server Call ID is still a hollow call."""

    class _Hollow(_ScriptedTCP):
        def transact(self, host, port, payload=b"", **kwargs):
            return _sccrp(), ""

        def roundtrips(self, host, port, payloads, **kwargs):
            out: list[bytes] = []
            for payload in payloads:
                ctrl = pptp.parse_control_header(payload)
                if ctrl and ctrl["control"] == pptp.CTRL_SCCRQ:
                    out.append(_sccrp())
                elif ctrl and ctrl["control"] == pptp.CTRL_ECHO_REQ:
                    ident = struct.unpack_from("!I", payload, 12)[0]
                    out.append(_echo_reply(ident))
                elif ctrl and ctrl["control"] == pptp.CTRL_OCRQ:
                    our_call_id = struct.unpack_from("!H", payload, 12)[0]
                    out.append(_ocrp(result=1, call_id=0, peer=our_call_id))
                else:
                    out.append(_stop_ccrp())
            return out, ""

    script = _Hollow([])
    with (
        patch("honeypot_auditor.probes.pptp.tcp_transact", script.transact),
        patch("honeypot_auditor.probes.pptp.tcp_roundtrips", script.roundtrips),
        patch("honeypot_auditor.probes.pptp.jittered_reconnect_pause", lambda: 0.0),
    ):
        inds = pptp.probe_pptp("127.0.0.1", 1723)
    by_id = {i.id: i for i in inds}
    assert by_id["pptp.call_facade"].triggered


def test_pptp_call_facade_honest_acceptance_is_clean():
    """Result=1 with peer echo and distinct non-zero server IDs stays clean."""

    class _RealServer(_ScriptedTCP):
        def __init__(self):
            super().__init__([])
            self._server_call_id = 100

        def transact(self, host, port, payload=b"", **kwargs):
            return _sccrp(), ""

        def roundtrips(self, host, port, payloads, **kwargs):
            out: list[bytes] = []
            for payload in payloads:
                ctrl = pptp.parse_control_header(payload)
                if ctrl and ctrl["control"] == pptp.CTRL_SCCRQ:
                    out.append(_sccrp())
                elif ctrl and ctrl["control"] == pptp.CTRL_ECHO_REQ:
                    ident = struct.unpack_from("!I", payload, 12)[0]
                    out.append(_echo_reply(ident))
                elif ctrl and ctrl["control"] == pptp.CTRL_OCRQ:
                    self._server_call_id += 1
                    our_call_id = struct.unpack_from("!H", payload, 12)[0]
                    out.append(
                        _ocrp(result=1, call_id=self._server_call_id, peer=our_call_id)
                    )
                else:
                    out.append(_stop_ccrp())
            return out, ""

    script = _RealServer()
    with (
        patch("honeypot_auditor.probes.pptp.tcp_transact", script.transact),
        patch("honeypot_auditor.probes.pptp.tcp_roundtrips", script.roundtrips),
        patch("honeypot_auditor.probes.pptp.jittered_reconnect_pause", lambda: 0.0),
    ):
        inds = pptp.probe_pptp("127.0.0.1", 1723)
    by_id = {i.id: i for i in inds}
    assert not by_id["pptp.call_facade"].triggered


def test_pptp_control_stub_sccrp_on_garbage():
    class _Stub(_ScriptedTCP):
        def transact(self, host, port, payload=b"", **kwargs):
            return _sccrp(), ""

        def roundtrips(self, host, port, payloads, **kwargs):
            out: list[bytes] = []
            for payload in payloads:
                ctrl = pptp.parse_control_header(payload)
                if ctrl and ctrl["control"] == pptp.CTRL_SCCRQ:
                    out.append(_sccrp())
                elif ctrl and ctrl["control"] == pptp.CTRL_ECHO_REQ:
                    ident = struct.unpack_from("!I", payload, 12)[0]
                    out.append(_echo_reply(ident))
                elif ctrl and ctrl["control"] == pptp.CTRL_OCRQ:
                    out.append(_ocrp(result=2))
                elif ctrl and ctrl["control"] == pptp.CTRL_GARBAGE:
                    out.append(_sccrp())  # stub: SCCRP again
                else:
                    out.append(b"")
            return out, ""

    import struct

    script = _Stub([])
    with (
        patch("honeypot_auditor.probes.pptp.tcp_transact", script.transact),
        patch("honeypot_auditor.probes.pptp.tcp_roundtrips", script.roundtrips),
        patch("honeypot_auditor.probes.pptp.jittered_reconnect_pause", lambda: 0.0),
    ):
        inds = pptp.probe_pptp("127.0.0.1", 1723)
    by_id = {i.id: i for i in inds}
    assert by_id["pptp.control_stub"].triggered


def test_pptp_registry_and_strategies():
    assert "pptp" in PROBE_BY_PROTOCOL
    assert PROBE_BY_PROTOCOL["pptp"] is pptp.probe_pptp
    row = PROTOCOL_STRATEGIES["pptp"]
    assert row["arbitrary_auth"]
    assert row["state_nonpersist"]
    assert row["static_signature"]


def test_pptp_ports_in_presets():
    from honeypot_auditor.config import (
        PORT_PRESET_DOCKER_RESEARCH,
        PORT_PRESET_IANA,
        probe_port_map,
    )

    assert PORT_PRESET_IANA["pptp"] == 1723
    assert PORT_PRESET_DOCKER_RESEARCH["pptp"] == 11723
    both = probe_port_map("both")
    assert 1723 in both["pptp"]
    assert 11723 in both["pptp"]
