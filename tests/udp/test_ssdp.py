"""SSDP / UPnP discovery probe tests (MockUDPTransceiver; no live network)."""

from __future__ import annotations

from typing import Any

import pytest

import honeypot_auditor.probes.udp.ssdp as ssdp
from honeypot_auditor.config import PROTOCOL_STRATEGIES
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.settings import settings

_DST = 1900

# Bound by autouse fixture from conftest ``mock_udp_cls`` (avoid importing conftest).
_MockUDP: Any = None
Reply = tuple[bytes, int, float, str]


@pytest.fixture(autouse=True)
def _bind_mock_udp(mock_udp_cls: type):
    global _MockUDP
    _MockUDP = mock_udp_cls
    yield
    _MockUDP = None


def _ok_response(
    *,
    st: str = "upnp:rootdevice",
    usn: str = "uuid:11111111-2222-3333-4444-555555555555::upnp:rootdevice",
    location: str = "http://192.0.2.10:8080/rootDesc.xml",
    server: str = "Linux/5.10 UPnP/1.1 MiniUPnPd/2.3",
    status: str = "HTTP/1.1 200 OK",
) -> bytes:
    return ssdp.build_ssdp_response(
        status=status,
        headers={
            "CACHE-CONTROL": "max-age=120",
            "EXT": "",
            "LOCATION": location,
            "SERVER": server,
            "ST": st,
            "USN": usn,
        },
    )


def _reply(data: bytes, *, peer_port: int = _DST, rtt_ms: float = 2.0) -> Reply:
    return (data, peer_port, rtt_ms, "")


def _timeout() -> Reply:
    return (b"", 0, 0.0, "timed out")


def _conformant_replies() -> list[Reply]:
    """Real UPnP shape: honest ST, no clone, silence on garbage method."""
    return [
        _reply(_ok_response()),  # M-SEARCH upnp:rootdevice
        _timeout(),  # distinct ST (unknown URN) — no match
        _timeout(),  # non-M-SEARCH method — drop
    ]


def _run(replies: list[Reply], *, port: int = _DST):
    mock = _MockUDP(replies)
    with mock.patch("honeypot_auditor.probes.udp.ssdp"):
        return ssdp.probe_ssdp("127.0.0.1", port), mock


def test_ssdp_builders_and_parse_round_trip():
    req = ssdp.build_msearch("192.0.2.10", 1900, st="upnp:rootdevice", mx=1)
    assert req.startswith(b"M-SEARCH * HTTP/1.1\r\n")
    assert b'ST: upnp:rootdevice\r\n' in req
    assert b"MX: 1\r\n" in req
    assert b'MAN: "ssdp:discover"\r\n' in req

    raw = _ok_response()
    msg = ssdp.parse_ssdp_message(raw)
    assert msg is not None
    assert msg.is_response
    assert msg.status_code == 200
    assert msg.headers["st"] == "upnp:rootdevice"
    assert msg.headers["server"].startswith("Linux/")
    assert "location" in msg.headers
    assert "usn" in msg.headers


def test_ssdp_conformant_device_is_clean():
    inds, mock = _run(_conformant_replies())
    assert len(inds) == len(ssdp._SSDP_SKIP)
    assert {i.id for i in inds} == {row[0] for row in ssdp._SSDP_SKIP}
    assert not any(i.triggered for i in inds)
    assert len(mock.calls) <= 4
    assert any(b"M-SEARCH" in c["payload"] for c in mock.calls)
    assert any(b"upnp:rootdevice" in c["payload"] for c in mock.calls)


def test_ssdp_framing_on_garbage():
    inds, _ = _run([_reply(b"not-ssdp-at-all")])
    by_id = {i.id: i for i in inds}
    assert by_id["ssdp.framing"].triggered
    assert all(i.skipped or i.id == "ssdp.framing" for i in inds)


def test_ssdp_transport_error_skips_suite():
    inds, _ = _run([_timeout()])
    assert len(inds) == len(ssdp._SSDP_SKIP)
    assert all(i.skipped for i in inds)
    assert not any(i.triggered for i in inds)


def test_ssdp_safe_mode_framing_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        inds, _ = _run([_reply(_ok_response())])
        by_id = {i.id: i for i in inds}
        assert by_id["ssdp.framing"].skipped is False
        assert not by_id["ssdp.framing"].triggered
        for ind in inds:
            if ind.id != "ssdp.framing":
                assert ind.skipped
                assert "safe-mode" in ind.skip_reason.lower()
    finally:
        settings.safe_mode = old


def test_ssdp_safe_mode_framing_hit():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        inds, _ = _run([_reply(b"garbage")])
        by_id = {i.id: i for i in inds}
        assert by_id["ssdp.framing"].triggered
        assert all(i.skipped or i.id == "ssdp.framing" for i in inds)
    finally:
        settings.safe_mode = old


def test_ssdp_header_facade_missing_required():
    thin = ssdp.build_ssdp_response(
        status="HTTP/1.1 200 OK",
        headers={"CACHE-CONTROL": "max-age=60"},
    )
    inds, _ = _run([_reply(thin), _timeout(), _timeout()])
    by_id = {i.id: i for i in inds}
    assert by_id["ssdp.header_facade"].triggered
    assert not by_id["ssdp.framing"].triggered


def test_ssdp_st_echo_mismatch():
    bad = _ok_response(st="ssdp:all")  # asked for upnp:rootdevice
    inds, _ = _run([_reply(bad), _timeout(), _timeout()])
    by_id = {i.id: i for i in inds}
    assert by_id["ssdp.st_echo"].triggered
    assert by_id["ssdp.st_echo"].fidelity in {"high", "decisive"}


def test_ssdp_response_clone_on_distinct_msearch():
    canned = _ok_response()
    inds, mock = _run([_reply(canned), _reply(canned), _timeout()])
    by_id = {i.id: i for i in inds}
    assert by_id["ssdp.response_clone"].triggered
    sts = []
    for call in mock.calls:
        if b"M-SEARCH" in call["payload"]:
            text = call["payload"].decode("latin-1", "replace")
            for line in text.split("\r\n"):
                if line.lower().startswith("st:"):
                    sts.append(line.split(":", 1)[1].strip())
    assert len(sts) >= 2
    assert sts[0] != sts[1]


def test_ssdp_stock_server_requires_corroboration():
    lure = _ok_response(server="Linux/5.10 UPnP/1.1 honeypot-ssdp/1.0")
    inds, _ = _run([_reply(lure), _timeout(), _timeout()])
    by_id = {i.id: i for i in inds}
    assert by_id["ssdp.stock_server"].triggered
    assert by_id["ssdp.stock_server"].requires_corroboration is True
    assert not by_id["ssdp.framing"].triggered
    assert not by_id["ssdp.st_echo"].triggered


def test_ssdp_location_loopback():
    loop = _ok_response(location="http://127.0.0.1:8080/rootDesc.xml")
    inds, _ = _run([_reply(loop), _timeout(), _timeout()])
    by_id = {i.id: i for i in inds}
    assert by_id["ssdp.location_loopback"].triggered
    assert by_id["ssdp.location_loopback"].fidelity in {"high", "decisive"}


def test_ssdp_location_localhost_hostname():
    loop = _ok_response(location="http://localhost:49152/desc.xml")
    inds, _ = _run([_reply(loop), _timeout(), _timeout()])
    by_id = {i.id: i for i in inds}
    assert by_id["ssdp.location_loopback"].triggered


def test_ssdp_method_stub_on_garbage_request():
    """Responds to non-M-SEARCH with a 200 OK SSDP body."""
    inds, mock = _run(
        [
            _reply(_ok_response()),
            _timeout(),
            _reply(_ok_response()),  # garbage method still 200 OK
        ]
    )
    by_id = {i.id: i for i in inds}
    assert by_id["ssdp.method_stub"].triggered
    assert any(
        not c["payload"].startswith(b"M-SEARCH") for c in mock.calls
    ), "expected a non-M-SEARCH probe exchange"


def test_ssdp_registry_and_strategies():
    assert "ssdp" in PROBE_BY_PROTOCOL
    assert PROBE_BY_PROTOCOL["ssdp"] is ssdp.probe_ssdp
    assert "ssdp" in PROTOCOL_STRATEGIES
    row = PROTOCOL_STRATEGIES["ssdp"]
    assert row["arbitrary_auth"] == ""
    assert row["state_nonpersist"] == ""
    assert "framing" in row["static_signature"].lower() or "M-SEARCH" in row["static_signature"]
    assert ssdp.UDP_ENGINE.name == "ssdp"
    assert ssdp.UDP_ENGINE.probe is ssdp.probe_ssdp


def test_ssdp_ports_in_presets():
    from honeypot_auditor.config import (
        PORT_PRESET_DOCKER_RESEARCH,
        PORT_PRESET_IANA,
        probe_port_map,
    )

    assert PORT_PRESET_IANA["ssdp"] == 1900
    assert PORT_PRESET_DOCKER_RESEARCH["ssdp"] == 11900
    both = probe_port_map("both")
    assert 1900 in both["ssdp"]
    assert 11900 in both["ssdp"]


def test_ssdp_packet_budget_at_most_four():
    inds, mock = _run(_conformant_replies())
    assert not any(i.triggered for i in inds)
    assert len(mock.calls) <= 4
