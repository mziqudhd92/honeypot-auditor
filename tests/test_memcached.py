"""Memcached ASCII protocol probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.memcached as mc
from honeypot_auditor.config import (
    PORT_PRESET_DOCKER_RESEARCH,
    PORT_PRESET_IANA,
    PROTOCOL_STRATEGIES,
)
from honeypot_auditor.settings import settings

_MC_IDS = {
    "memcached.version_framing",
    "memcached.stats_framing",
    "memcached.unknown_command",
    "memcached.get_miss",
    "memcached.stats_clone",
    "memcached.stock_version",
    "memcached.flush_stub",
    "memcached.noreply_facade",
}

_CANNED_STATS = (
    b"STAT pid 1\r\n"
    b"STAT uptime 100\r\n"
    b"STAT version 1.4.15\r\n"
    b"STAT curr_connections 1\r\n"
    b"STAT cmd_get 0\r\n"
    b"END\r\n"
)

_LIVE_STATS_1 = (
    b"STAT pid 4242\r\n"
    b"STAT uptime 3600\r\n"
    b"STAT version 1.6.23\r\n"
    b"STAT curr_connections 3\r\n"
    b"STAT cmd_get 10\r\n"
    b"END\r\n"
)

_LIVE_STATS_2 = (
    b"STAT pid 4242\r\n"
    b"STAT uptime 3601\r\n"
    b"STAT version 1.6.23\r\n"
    b"STAT curr_connections 4\r\n"
    b"STAT cmd_get 11\r\n"
    b"END\r\n"
)


def _version(ver: str = "1.6.23") -> bytes:
    return f"VERSION {ver}\r\n".encode()


def _calls(*replies: bytes):
    return [(r, "") for r in replies]


def test_memcached_ports_and_strategies():
    assert PORT_PRESET_IANA["memcached"] == 11211
    assert PORT_PRESET_DOCKER_RESEARCH["memcached"] == 21211
    row = PROTOCOL_STRATEGIES["memcached"]
    assert row["arbitrary_auth"] == ""
    assert row["state_nonpersist"] == ""
    assert "version" in row["static_signature"].lower()
    assert "stats" in row["static_signature"].lower()


@patch.object(mc, "tcp_transact")
def test_memcached_closed_port_skips_all(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = mc.probe_memcached("127.0.0.1", 11211)
    assert {i.id for i in inds} == _MC_IDS
    assert all(i.skipped for i in inds)


@patch.object(mc, "tcp_transact")
def test_memcached_non_speaker_skips_all(mock_tcp):
    mock_tcp.return_value = (b"HTTP/1.1 200 OK\r\n", "")
    inds = mc.probe_memcached("127.0.0.1", 11211)
    assert {i.id for i in inds} == _MC_IDS
    assert all(i.skipped for i in inds)
    assert any("not a Memcached ASCII speaker" in i.skip_reason for i in inds)


@patch.object(mc, "tcp_transact")
@patch.object(mc.secrets, "token_hex", return_value="deadbeef")
def test_memcached_compliant_server_triggers_nothing(mock_hex, mock_tcp):
    mock_tcp.side_effect = _calls(
        _version("1.6.23"),
        _LIVE_STATS_1,
        b"ERROR\r\n",  # foo
        b"END\r\n",  # get miss
        _LIVE_STATS_2,
        b"ERROR\r\n",  # verbosity without level (flush_stub stand-in)
        b"",  # noreply quiet
    )
    inds = mc.probe_memcached("127.0.0.1", 11211)
    by_id = {i.id: i for i in inds}
    assert {i.id for i in inds} == _MC_IDS
    assert not any(i.triggered for i in inds)
    assert not by_id["memcached.version_framing"].triggered
    assert not by_id["memcached.stats_clone"].triggered
    assert not by_id["memcached.stock_version"].triggered


@patch.object(mc, "tcp_transact")
@patch.object(mc.secrets, "token_hex", return_value="deadbeef")
def test_memcached_stub_signatures(mock_hex, mock_tcp):
    mock_tcp.side_effect = _calls(
        _version("1.4.15"),
        _CANNED_STATS,
        b"OK\r\n",  # unknown → OK
        b"VALUE hpaudit_deadbeef 0 3\r\nfoo\r\nEND\r\n",  # fake hit
        _CANNED_STATS,  # identical clone
        b"OK\r\n",  # verbosity bare → OK
        b"OK\r\n",  # noreply still answers
    )
    inds = mc.probe_memcached("127.0.0.1", 11211)
    by_id = {i.id: i for i in inds}
    assert by_id["memcached.unknown_command"].triggered
    assert by_id["memcached.get_miss"].triggered
    assert by_id["memcached.stats_clone"].triggered
    assert by_id["memcached.stats_clone"].fidelity == "decisive"
    assert by_id["memcached.stock_version"].triggered
    assert by_id["memcached.stock_version"].requires_corroboration
    assert by_id["memcached.flush_stub"].triggered
    assert by_id["memcached.noreply_facade"].triggered
    assert not by_id["memcached.version_framing"].triggered
    assert not by_id["memcached.stats_framing"].triggered


@patch.object(mc, "tcp_transact")
def test_memcached_version_framing_malformed(mock_tcp):
    mock_tcp.side_effect = _calls(
        b"OK\r\n",  # version should be VERSION …
        _LIVE_STATS_1,
        b"ERROR\r\n",
        b"END\r\n",
        _LIVE_STATS_2,
        b"ERROR\r\n",
        b"",
    )
    inds = mc.probe_memcached("127.0.0.1", 11211)
    by_id = {i.id: i for i in inds}
    assert by_id["memcached.version_framing"].triggered


@patch.object(mc, "tcp_transact")
@patch.object(mc.secrets, "token_hex", return_value="deadbeef")
def test_memcached_stats_framing_malformed(mock_hex, mock_tcp):
    mock_tcp.side_effect = _calls(
        _version("1.6.23"),
        b"VERSION 1.6.23\r\n",  # stats returned VERSION — malformed
        b"ERROR\r\n",
        b"END\r\n",
        _LIVE_STATS_2,
        b"ERROR\r\n",
        b"",
    )
    inds = mc.probe_memcached("127.0.0.1", 11211)
    by_id = {i.id: i for i in inds}
    assert by_id["memcached.stats_framing"].triggered


@patch.object(mc, "tcp_transact")
@patch.object(mc.secrets, "token_hex", return_value="deadbeef")
def test_memcached_decisive_stock_version(mock_hex, mock_tcp):
    mock_tcp.side_effect = _calls(
        _version("honeypot"),
        _LIVE_STATS_1,
        b"ERROR\r\n",
        b"END\r\n",
        _LIVE_STATS_2,
        b"ERROR\r\n",
        b"",
    )
    inds = mc.probe_memcached("127.0.0.1", 11211)
    stock = {i.id: i for i in inds}["memcached.stock_version"]
    assert stock.triggered
    assert not stock.requires_corroboration
    assert stock.fidelity in {"high", "decisive"}


@patch.object(mc, "tcp_transact")
def test_memcached_safe_mode_version_framing_only(mock_tcp):
    mock_tcp.return_value = (_version("1.6.23"), "")
    prev = settings.safe_mode
    settings.safe_mode = True
    try:
        inds = mc.probe_memcached("127.0.0.1", 11211)
    finally:
        settings.safe_mode = prev
    by_id = {i.id: i for i in inds}
    assert {i.id for i in inds} == _MC_IDS
    assert not by_id["memcached.version_framing"].skipped
    assert not by_id["memcached.version_framing"].triggered
    for iid in _MC_IDS - {"memcached.version_framing"}:
        assert by_id[iid].skipped
    assert mock_tcp.call_count == 1


@patch.object(mc, "tcp_transact")
def test_memcached_safe_mode_malformed_version(mock_tcp):
    mock_tcp.return_value = (b"STAT version 1.4.15\r\nEND\r\n", "")
    prev = settings.safe_mode
    settings.safe_mode = True
    try:
        inds = mc.probe_memcached("127.0.0.1", 11211)
    finally:
        settings.safe_mode = prev
    by_id = {i.id: i for i in inds}
    assert by_id["memcached.version_framing"].triggered
    for iid in _MC_IDS - {"memcached.version_framing"}:
        assert by_id[iid].skipped
