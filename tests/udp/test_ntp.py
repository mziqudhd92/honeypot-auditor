"""NTP RFC 5905 non-compliance probe tests (MockUDPTransceiver; no live network)."""

from __future__ import annotations

from honeypot_auditor.config import PROTOCOL_STRATEGIES
from honeypot_auditor.netutil import UdpExchange
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.settings import settings
from tests.udp.conftest import MockUDPTransceiver, ScriptedReply

import honeypot_auditor.probes.udp.ntp as ntp

_NTP_IDS = (
    "ntp.framing",
    "ntp.mode_facade",
    "ntp.org_echo",
    "ntp.stratum_facade",
    "ntp.response_clone",
    "ntp.zeroed_clock_metrics",
    "ntp.epoch_zero",
    "ntp.stock_refid",
)


def _ts(seconds: int, fraction: int = 0) -> int:
    return ((seconds & 0xFFFFFFFF) << 32) | (fraction & 0xFFFFFFFF)


# Plausible "now" in NTP era (≈ 2024-ish).
_NOW = _ts(0xE8D4A510, 0x12345678)
_UNIX_EPOCH_NTP = ntp._UNIX_EPOCH_NTP_SECONDS


def _conformant_reply(req: bytes, *, xmt_override: int | None = None) -> bytes:
    """Chrony/ntpd-shaped mode-4 reply: org echo, stratum 2, non-zero metrics."""
    parsed = ntp.parse_ntp_packet(req)
    assert parsed is not None
    client_xmt = parsed.transmit_timestamp
    return ntp.build_ntp_packet(
        li=0,
        vn=4,
        mode=ntp._MODE_SERVER,
        stratum=2,
        poll=6,
        precision=-20,
        root_delay=0x00000100,
        root_dispersion=0x00000050,
        reference_id=b"GPS\x00",
        reference_timestamp=_NOW - _ts(10),
        originate_timestamp=client_xmt,
        receive_timestamp=_NOW - _ts(0, 0x1000),
        transmit_timestamp=xmt_override if xmt_override is not None else _NOW,
    )


def _scripted_from_callable(fn, *, drop_invalid_vn: bool = True):
    """Adapt a request→bytes (or (bytes, err)) callable into MockUDPTransceiver replies.

    When ``drop_invalid_vn`` is True (default), unsupported VN is timed out so
    isolation tests do not co-fire ``ntp.mode_facade``.
    """

    def _wrapped(host, port, payload):
        if drop_invalid_vn:
            parsed = ntp.parse_ntp_packet(payload)
            if parsed is not None and parsed.vn not in (3, 4):
                return b"", "timed out"
        return fn(host, port, payload)

    class _Dynamic(MockUDPTransceiver):
        def _next(self, host: str, port: int, payload: bytes, *, connected: bool):
            self.calls.append(
                {
                    "host": host,
                    "port": port,
                    "payload": payload,
                    "connected": connected,
                }
            )
            data = _wrapped(host, port, payload)
            if isinstance(data, tuple):
                raw, err = data
                if err:
                    return UdpExchange(
                        data=b"", peer_host="", peer_port=0, rtt_ms=0.0, error=err
                    )
                data = raw
            return UdpExchange(
                data=data,
                peer_host=self.peer_host,
                peer_port=port,
                rtt_ms=1.5,
                error="",
            )

    return _Dynamic()


def _patch_conformant():
    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        if parsed is None:
            return b"", "timed out"
        # Real daemons drop unsupported VN; do not serve VN=0.
        if parsed.vn not in (3, 4) or parsed.mode != ntp._MODE_CLIENT:
            return b"", "timed out"
        return _conformant_reply(payload)

    return _scripted_from_callable(reply, drop_invalid_vn=False)


def test_ntp_packet_round_trip():
    xmt = _ts(0xABCDEF01, 0x55AA55AA)
    req = ntp.build_client_request(transmit_timestamp=xmt)
    assert len(req) == 48
    parsed = ntp.parse_ntp_packet(req)
    assert parsed is not None
    assert parsed.vn == 4
    assert parsed.mode == ntp._MODE_CLIENT
    assert parsed.transmit_timestamp == xmt
    resp = _conformant_reply(req)
    r = ntp.parse_ntp_packet(resp)
    assert r is not None
    assert r.mode == ntp._MODE_SERVER
    assert r.originate_timestamp == xmt


def test_ntp_conformant_agent_is_clean():
    trx = _patch_conformant()
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    assert len(inds) == len(_NTP_IDS)
    assert {i.id for i in inds} == set(_NTP_IDS)
    assert not any(i.triggered for i in inds)
    assert not any(i.skipped for i in inds)


def test_ntp_framing_on_garbage():
    trx = MockUDPTransceiver([ScriptedReply(data=b"not-ntp", peer_port=123, rtt_ms=1.0)])
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.framing"].triggered
    assert all(i.skipped or i.id == "ntp.framing" for i in inds)
    assert len(inds) == len(_NTP_IDS)


def test_ntp_connection_error_skips_suite():
    trx = MockUDPTransceiver([ScriptedReply(error="timed out")])
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    assert len(inds) == len(_NTP_IDS)
    assert all(i.skipped for i in inds)
    assert not any(i.triggered for i in inds)


def test_ntp_safe_mode_framing_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        trx = _patch_conformant()
        with trx.patch():  # patches honeypot_auditor.netutil
            inds = ntp.probe_ntp("127.0.0.1", 123)
    finally:
        settings.safe_mode = old
    by_id = {i.id: i for i in inds}
    assert len(inds) == len(_NTP_IDS)
    assert not by_id["ntp.framing"].skipped
    assert not by_id["ntp.framing"].triggered
    for iid in _NTP_IDS:
        if iid == "ntp.framing":
            continue
        assert by_id[iid].skipped
        assert "safe-mode" in by_id[iid].skip_reason


def test_ntp_mode_facade_wrong_mode():
    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        # Echo as mode 3 (client) instead of server mode 4.
        return ntp.build_ntp_packet(
            li=0,
            vn=4,
            mode=ntp._MODE_CLIENT,
            stratum=2,
            poll=6,
            precision=-20,
            root_delay=0x100,
            root_dispersion=0x50,
            reference_id=b"GPS\x00",
            reference_timestamp=_NOW,
            originate_timestamp=parsed.transmit_timestamp,
            receive_timestamp=_NOW,
            transmit_timestamp=_NOW,
        )

    trx = _scripted_from_callable(reply)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.mode_facade"].triggered
    assert not by_id["ntp.framing"].triggered
    assert not by_id["ntp.org_echo"].triggered


def test_ntp_mode_facade_invalid_vn_still_serves():
    """VN=0 client packet still receiving a mode-4 reply → mode_facade."""

    call_n = {"n": 0}

    def reply(host, port, payload):
        del host, port
        call_n["n"] += 1
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        # Always serve mode-4 regardless of request VN.
        return _conformant_reply(payload)

    trx = _scripted_from_callable(reply, drop_invalid_vn=False)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.mode_facade"].triggered
    assert not by_id["ntp.org_echo"].triggered


def test_ntp_org_echo_mismatch():
    def reply(host, port, payload):
        del host, port
        # Wrong originate: ignore client xmt.
        return ntp.build_ntp_packet(
            li=0,
            vn=4,
            mode=ntp._MODE_SERVER,
            stratum=2,
            poll=6,
            precision=-20,
            root_delay=0x100,
            root_dispersion=0x50,
            reference_id=b"GPS\x00",
            reference_timestamp=_NOW,
            originate_timestamp=0x1111111111111111,
            receive_timestamp=_NOW,
            transmit_timestamp=_NOW,
        )

    trx = _scripted_from_callable(reply)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.org_echo"].triggered
    assert not by_id["ntp.mode_facade"].triggered
    assert not by_id["ntp.framing"].triggered


def test_ntp_stratum_facade_stratum_zero_without_kiss():
    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        return ntp.build_ntp_packet(
            li=0,
            vn=4,
            mode=ntp._MODE_SERVER,
            stratum=0,
            poll=6,
            precision=-20,
            root_delay=0x100,
            root_dispersion=0x50,
            reference_id=b"\x00\x00\x00\x00",  # not a kiss code
            reference_timestamp=_NOW,
            originate_timestamp=parsed.transmit_timestamp,
            receive_timestamp=_NOW,
            transmit_timestamp=_NOW,
        )

    trx = _scripted_from_callable(reply)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.stratum_facade"].triggered
    assert not by_id["ntp.org_echo"].triggered


def test_ntp_stratum_facade_stratum_ge_16():
    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        return ntp.build_ntp_packet(
            li=0,
            vn=4,
            mode=ntp._MODE_SERVER,
            stratum=16,
            poll=6,
            precision=-20,
            root_delay=0x100,
            root_dispersion=0x50,
            reference_id=b"GPS\x00",
            reference_timestamp=_NOW,
            originate_timestamp=parsed.transmit_timestamp,
            receive_timestamp=_NOW,
            transmit_timestamp=_NOW,
        )

    trx = _scripted_from_callable(reply)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    assert {i.id: i for i in inds}["ntp.stratum_facade"].triggered


def test_ntp_response_clone():
    canned = ntp.build_ntp_packet(
        li=0,
        vn=4,
        mode=ntp._MODE_SERVER,
        stratum=2,
        poll=6,
        precision=-20,
        root_delay=0x100,
        root_dispersion=0x50,
        reference_id=b"GPS\x00",
        reference_timestamp=_NOW,
        originate_timestamp=0,  # ignored org — also org_echo, but clone is the focus
        receive_timestamp=_NOW,
        transmit_timestamp=_NOW,
    )

    def reply(host, port, payload):
        del host, port, payload
        return canned

    trx = _scripted_from_callable(reply)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.response_clone"].triggered
    assert by_id["ntp.response_clone"].fidelity == "decisive"


def test_ntp_zeroed_clock_metrics_gated():
    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        return ntp.build_ntp_packet(
            li=0,
            vn=4,
            mode=ntp._MODE_SERVER,
            stratum=2,
            poll=6,
            precision=-20,
            root_delay=0,
            root_dispersion=0,
            reference_id=b"GPS\x00",
            reference_timestamp=0,
            originate_timestamp=parsed.transmit_timestamp,
            receive_timestamp=_NOW,
            transmit_timestamp=_NOW,
        )

    trx = _scripted_from_callable(reply)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.zeroed_clock_metrics"].triggered
    assert by_id["ntp.zeroed_clock_metrics"].requires_corroboration is True
    assert not by_id["ntp.org_echo"].triggered
    assert not by_id["ntp.mode_facade"].triggered


def test_ntp_epoch_zero_gated():
    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        zero = _ts(0)
        return ntp.build_ntp_packet(
            li=0,
            vn=4,
            mode=ntp._MODE_SERVER,
            stratum=2,
            poll=6,
            precision=-20,
            root_delay=0x100,
            root_dispersion=0x50,
            reference_id=b"GPS\x00",
            reference_timestamp=zero,
            originate_timestamp=parsed.transmit_timestamp,
            receive_timestamp=zero,
            transmit_timestamp=zero,
        )

    trx = _scripted_from_callable(reply)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.epoch_zero"].triggered
    assert by_id["ntp.epoch_zero"].requires_corroboration is True
    assert not by_id["ntp.zeroed_clock_metrics"].triggered


def test_ntp_epoch_zero_unix_epoch_gated():
    unix_ntp = _ts(_UNIX_EPOCH_NTP)

    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        return ntp.build_ntp_packet(
            li=0,
            vn=4,
            mode=ntp._MODE_SERVER,
            stratum=2,
            poll=6,
            precision=-20,
            root_delay=0x100,
            root_dispersion=0x50,
            reference_id=b"GPS\x00",
            reference_timestamp=unix_ntp,
            originate_timestamp=parsed.transmit_timestamp,
            receive_timestamp=unix_ntp,
            transmit_timestamp=unix_ntp,
        )

    trx = _scripted_from_callable(reply)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.epoch_zero"].triggered
    assert by_id["ntp.epoch_zero"].requires_corroboration is True


def test_ntp_stock_refid_gated():
    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        return ntp.build_ntp_packet(
            li=0,
            vn=4,
            mode=ntp._MODE_SERVER,
            stratum=2,
            poll=6,
            precision=-20,
            root_delay=0x100,
            root_dispersion=0x50,
            reference_id=b"FAKE",
            reference_timestamp=_NOW,
            originate_timestamp=parsed.transmit_timestamp,
            receive_timestamp=_NOW,
            transmit_timestamp=_NOW,
        )

    trx = _scripted_from_callable(reply)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.stock_refid"].triggered
    assert by_id["ntp.stock_refid"].requires_corroboration is True


def test_ntp_kiss_of_death_stratum_zero_is_clean():
    """RFC kiss codes with stratum 0 are compliant; not stratum_facade."""

    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        # Kiss-o'-death INIT — real servers may send this when unsynced.
        return ntp.build_ntp_packet(
            li=0,
            vn=4,
            mode=ntp._MODE_SERVER,
            stratum=0,
            poll=6,
            precision=-20,
            root_delay=0x100,
            root_dispersion=0x50,
            reference_id=b"INIT",
            reference_timestamp=_NOW,
            originate_timestamp=parsed.transmit_timestamp,
            receive_timestamp=_NOW,
            transmit_timestamp=_NOW,
        )

    trx = _scripted_from_callable(reply)
    with trx.patch():  # patches honeypot_auditor.netutil
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert not by_id["ntp.stratum_facade"].triggered
    assert not by_id["ntp.framing"].triggered


def test_ntp_registry_and_strategies():
    assert "ntp" in PROBE_BY_PROTOCOL
    assert PROBE_BY_PROTOCOL["ntp"] is ntp.probe_ntp
    assert "ntp" in PROTOCOL_STRATEGIES
    row = PROTOCOL_STRATEGIES["ntp"]
    assert row["arbitrary_auth"] == ""
    assert row["state_nonpersist"] == ""
    assert "static_signature" in row and row["static_signature"]
    assert ntp.UDP_ENGINE.name == "ntp"
    assert ntp.UDP_ENGINE.probe is ntp.probe_ntp


def test_ntp_no_monlist_or_mode7_in_probe_requests():
    """Packet budget must never emit mode-7 / monlist control queries."""
    trx = _patch_conformant()
    with trx.patch():  # patches honeypot_auditor.netutil
        ntp.probe_ntp("127.0.0.1", 123)
    assert trx.calls
    assert len(trx.calls) <= 8
    for call in trx.calls:
        pkt = ntp.parse_ntp_packet(call["payload"])
        assert pkt is not None
        # Control/monlist historically used private mode 7 — never send it.
        assert pkt.mode != 7
        assert call["payload"][0] & 0x07 != 7
        assert pkt.mode == ntp._MODE_CLIENT
