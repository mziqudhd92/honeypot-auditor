"""NTP RFC 5905 non-compliance probe tests (MockUDPTransceiver; no live network)."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

import honeypot_auditor.probes.udp.ntp as ntp
from honeypot_auditor.analyzer import build_report
from honeypot_auditor.config import (
    PORT_PRESET_DOCKER_RESEARCH,
    PORT_PRESET_IANA,
    PROTOCOL_STRATEGIES,
    probe_port_map,
    protocol_for_port,
)
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import UdpExchange
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.settings import settings

_NTP_IDS = (
    "ntp.kod_absent",
    "ntp.state_nonpersist",
    "ntp.framing",
    "ntp.mode_facade",
    "ntp.org_echo",
    "ntp.stratum_facade",
    "ntp.response_clone",
    "ntp.zeroed_clock_metrics",
    "ntp.epoch_zero",
    "ntp.stock_refid",
)

# Bound by autouse fixtures from conftest (avoid importing conftest as a package).
MockUDPTransceiver: Any = None
ScriptedReply: Any = None


@pytest.fixture(autouse=True)
def _bind_udp_harness(mock_udp_cls: type, scripted_reply_cls: type):
    global MockUDPTransceiver, ScriptedReply
    MockUDPTransceiver = mock_udp_cls
    ScriptedReply = scripted_reply_cls
    yield
    MockUDPTransceiver = None
    ScriptedReply = None


def _ts(seconds: int, fraction: int = 0) -> int:
    return ((seconds & 0xFFFFFFFF) << 32) | (fraction & 0xFFFFFFFF)


# Plausible "now" in NTP era (≈ 2024-ish).
_NOW = _ts(0xE8D4A510, 0x12345678)
_UNIX_EPOCH_NTP = ntp._UNIX_EPOCH_NTP_SECONDS
_CONFORMANT_TICK = {"n": 0}


def _conformant_reply(req: bytes, *, xmt_override: int | None = None) -> bytes:
    """Chrony/ntpd-shaped mode-4 reply: org echo, stratum 2, advancing clock."""
    parsed = ntp.parse_ntp_packet(req)
    assert parsed is not None
    client_xmt = parsed.transmit_timestamp
    _CONFORMANT_TICK["n"] += 1
    tick = _CONFORMANT_TICK["n"]
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
        reference_timestamp=_NOW - _ts(10) + _ts(tick),
        originate_timestamp=client_xmt,
        receive_timestamp=_NOW - _ts(0, 0x1000) + _ts(0, tick),
        transmit_timestamp=xmt_override if xmt_override is not None else (_NOW + _ts(tick)),
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


def test_ntp_parse_rejects_short_and_empty():
    assert ntp.parse_ntp_packet(b"") is None
    assert ntp.parse_ntp_packet(b"\x00" * 47) is None
    assert ntp.parse_ntp_packet(b"\x00" * 48) is not None


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


def test_ntp_invalid_vn_dropped_is_clean():
    """Real daemons drop unsupported VN; that must not fire mode_facade."""

    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        if parsed.vn not in (3, 4):
            return b"", "timed out"
        return _conformant_reply(payload)

    trx = _scripted_from_callable(reply, drop_invalid_vn=False)
    with trx.patch():
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert not by_id["ntp.mode_facade"].triggered
    assert not by_id["ntp.framing"].triggered
    assert not any(i.triggered for i in inds)


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


@pytest.mark.parametrize("refid", [b"fake", b"HONE", b"stub", b"mock"])
def test_ntp_stock_refid_case_and_substring(refid: bytes):
    """Stock lure matching is case-insensitive over the 4-byte refid field."""

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
            reference_id=refid,
            reference_timestamp=_NOW,
            originate_timestamp=parsed.transmit_timestamp,
            receive_timestamp=_NOW,
            transmit_timestamp=_NOW,
        )

    trx = _scripted_from_callable(reply)
    with trx.patch():
        inds = ntp.probe_ntp("127.0.0.1", 123)
    stock = {i.id: i for i in inds}["ntp.stock_refid"]
    assert stock.triggered
    assert stock.requires_corroboration is True


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
    assert "KoD" in row["arbitrary_auth"] or "mode-3" in row["arbitrary_auth"]
    assert "monotonic" in row["state_nonpersist"].lower() or "timestamp" in row["state_nonpersist"].lower()
    assert "static_signature" in row and row["static_signature"]
    assert ntp.UDP_ENGINE.name == "ntp"
    assert ntp.UDP_ENGINE.probe is ntp.probe_ntp


def test_ntp_ports_iana_and_lab():
    assert PORT_PRESET_IANA["ntp"] == 123
    assert PORT_PRESET_DOCKER_RESEARCH["ntp"] == 1123
    assert protocol_for_port(123) == "ntp"
    assert protocol_for_port(1123) == "ntp"
    both = probe_port_map("both")
    assert both["ntp"] == [123, 1123]
    assert probe_port_map("both", extra_ports=[1123]) == {"ntp": [1123]}


def test_ntp_kod_absent_and_state_frozen():
    """Uniform mode-4 burst without KoD + frozen timestamps across exchanges."""
    frozen_xmt = _NOW

    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        if parsed.vn not in (3, 4) or parsed.mode != ntp._MODE_CLIENT:
            return b"", "timed out"
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
            reference_timestamp=frozen_xmt,
            originate_timestamp=parsed.transmit_timestamp,
            receive_timestamp=frozen_xmt,
            transmit_timestamp=frozen_xmt,
        )

    trx = _scripted_from_callable(reply, drop_invalid_vn=False)
    with (
        trx.patch(),
        patch.object(ntp, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert by_id["ntp.kod_absent"].triggered
    assert by_id["ntp.state_nonpersist"].triggered


def test_ntp_kod_rate_clears_auth():
    """Stratum-0 RATE kiss under burst must not score kod_absent."""
    call_n = {"n": 0}

    def reply(host, port, payload):
        del host, port
        parsed = ntp.parse_ntp_packet(payload)
        assert parsed is not None
        if parsed.vn not in (3, 4) or parsed.mode != ntp._MODE_CLIENT:
            return b"", "timed out"
        call_n["n"] += 1
        # After baseline+clone, burst replies get KoD RATE.
        if call_n["n"] >= 3:
            return ntp.build_ntp_packet(
                li=0,
                vn=4,
                mode=ntp._MODE_SERVER,
                stratum=0,
                poll=6,
                precision=-20,
                reference_id=b"RATE",
                originate_timestamp=parsed.transmit_timestamp,
                receive_timestamp=_NOW + call_n["n"],
                transmit_timestamp=_NOW + call_n["n"] * 2,
                reference_timestamp=_NOW,
                root_delay=0x100,
                root_dispersion=0x50,
            )
        return _conformant_reply(payload)

    trx = _scripted_from_callable(reply, drop_invalid_vn=False)
    with (
        trx.patch(),
        patch.object(ntp, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = ntp.probe_ntp("127.0.0.1", 123)
    by_id = {i.id: i for i in inds}
    assert not by_id["ntp.kod_absent"].triggered


def test_ntp_gated_tells_suppressed_alone_in_default_report():
    """Lone gated NTP stock/zeroed/epoch tells must not inflate default score."""
    inds = [
        Indicator(
            id="ntp.stock_refid",
            title="NTP reference ID matches a stock honeypot lure token",
            category="static_signature",
            triggered=True,
            protocol="ntp",
            detail="refid lure token 'FAKE'",
            requires_corroboration=True,
        ),
        Indicator(
            id="ntp.zeroed_clock_metrics",
            title="NTP root delay, dispersion, and reference timestamp are all zero",
            category="static_signature",
            triggered=True,
            protocol="ntp",
            detail="root_delay, root_dispersion, and reference_timestamp are all zero",
            requires_corroboration=True,
        ),
    ]
    report = build_report(
        target="203.0.113.123",
        resolved_ip="203.0.113.123",
        ports={"ntp": [123]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
        deep=False,
    )
    by_id = {i.id: i for i in report.indicators}
    assert not by_id["ntp.stock_refid"].triggered
    assert not by_id["ntp.zeroed_clock_metrics"].triggered
    assert report.score == 0.0
    assert "suppressed: no corroborating tell" in by_id["ntp.stock_refid"].detail


def test_ntp_gated_tells_kept_with_ungated_corroboration():
    """Gated NTP lure stays live when an ungated tell (e.g. response_clone) fires."""
    inds = [
        Indicator(
            id="ntp.stock_refid",
            title="NTP reference ID matches a stock honeypot lure token",
            category="static_signature",
            triggered=True,
            protocol="ntp",
            detail="refid lure token 'FAKE'",
            requires_corroboration=True,
        ),
        Indicator(
            id="ntp.response_clone",
            title="NTP returns bitwise-identical replies for distinct requests",
            category="static_signature",
            triggered=True,
            protocol="ntp",
            detail="bitwise-identical UDP payloads",
            fidelity="decisive",
        ),
    ]
    report = build_report(
        target="203.0.113.123",
        resolved_ip="203.0.113.123",
        ports={"ntp": [123]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
        deep=False,
    )
    by_id = {i.id: i for i in report.indicators}
    assert by_id["ntp.stock_refid"].triggered
    assert "suppressed" not in by_id["ntp.stock_refid"].detail
    assert report.score > 0


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
