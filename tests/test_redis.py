"""Redis probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.redis as redis_probe
from honeypot_auditor.config import REDIS_PROBE_VALUE

_BEEHIVE_INFO = (
    "$180\r\n"
    "# Server\r\n"
    "redis_version:6.2.6\r\n"
    "server_time_usec:1644233854325059\r\n"
    "uptime_in_seconds:103028\r\n"
    "total_commands_processed:11\r\n"
)


def _ok() -> bytes:
    return b"+OK\r\n"


def _pong() -> bytes:
    return b"+PONG\r\n"


def _unknown(cmd: str) -> bytes:
    return f"-ERR unknown command `{cmd}`, with args beginning with: \r\n".encode()


def _bulk(value: str) -> bytes:
    return f"${len(value)}\r\n{value}\r\n".encode()


def _calls(*replies: bytes):
    return [(r, "") for r in replies]


@patch.object(redis_probe, "tcp_transact")
def test_redis_closed_port_skips_all_strategies(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    assert {i.id for i in inds} == {
        "redis.arbitrary_auth",
        "redis.persist",
        "redis.flush",
        "redis.signature",
    }
    assert all(i.skipped for i in inds)


@patch.object(redis_probe, "tcp_transact")
def test_redis_stub_auth_flush_and_signatures(mock_tcp):
    mock_tcp.side_effect = _calls(
        _pong(),
        _ok(),
        _ok(),
        _BEEHIVE_INFO.encode(),
        _BEEHIVE_INFO.encode(),
        b"*2\r\n$13\r\nredis-cli 7.0.5\r\n$20\r\nSet ~/.redisclirc\r\n",
        _unknown("ECHO"),
        _unknown("SELECT"),
        _ok(),
        _ok(),
        _ok(),
        _bulk(REDIS_PROBE_VALUE),
        b":1\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.arbitrary_auth"].triggered
    assert by_id["redis.flush"].skipped
    assert "non-destructive" in by_id["redis.flush"].skip_reason.lower()
    assert by_id["redis.signature"].triggered
    detail = by_id["redis.signature"].detail.lower()
    assert "command" in detail
    assert "frozen" in detail or "static" in detail
    assert "redis-cli" in detail
    assert "echo" in detail
    assert "eval" in detail
    assert not by_id["redis.persist"].triggered


@patch.object(redis_probe, "tcp_transact")
def test_redis_key_vanishes_after_reconnect(mock_tcp):
    import time

    now = int(time.time() * 1_000_000)
    info_a = f"$80\r\nserver_time_usec:{now}\r\ntotal_commands_processed:40\r\n".encode()
    info_b = f"$80\r\nserver_time_usec:{now + 1500}\r\ntotal_commands_processed:41\r\n".encode()
    mock_tcp.side_effect = _calls(
        _pong(),
        b"-ERR AUTH called without any password configured\r\n",
        b"*1\r\n*1\r\n$3\r\nget\r\n",
        info_a,
        info_b,
        b"*1\r\n$4\r\nECHO\r\n",
        _bulk("abcd"),
        _ok(),
        b":1\r\n",
        b"*0\r\n",
        _ok(),
        b"$-1\r\n",
        b":1\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.persist"].triggered
    assert not by_id["redis.arbitrary_auth"].triggered
    assert by_id["redis.flush"].skipped
    assert not by_id["redis.signature"].triggered


@patch.object(redis_probe, "tcp_transact")
def test_redis_set_rejected_skips_persist_and_flush(mock_tcp):
    import time

    now = int(time.time() * 1_000_000)
    mock_tcp.side_effect = _calls(
        _pong(),
        b"-WRONGPASS invalid password\r\n",
        b"*1\r\n$3\r\nget\r\n",
        f"server_time_usec:{now}\ntotal_commands_processed:1\n".encode(),
        f"server_time_usec:{now + 200}\ntotal_commands_processed:2\n".encode(),
        b"+OK\r\n",
        _bulk("x"),
        _ok(),
        b":1\r\n",
        b"*0\r\n",
        b"-NOAUTH Authentication required.\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.persist"].skipped
    assert by_id["redis.flush"].skipped


@patch.object(redis_probe, "tcp_transact")
def test_redis_flush_probe_skipped_after_set(mock_tcp):
    import time

    now = int(time.time() * 1_000_000)
    info_a = f"server_time_usec:{now}\ntotal_commands_processed:10\n".encode()
    info_b = f"server_time_usec:{now + 200}\ntotal_commands_processed:11\n".encode()
    mock_tcp.side_effect = _calls(
        _pong(),
        b"-ERR AUTH called without any password configured\r\n",
        b"*1\r\n$3\r\nget\r\n",
        info_a,
        info_b,
        b"+OK\r\n",
        _bulk("x"),
        _ok(),
        _ok(),
        _ok(),
        _ok(),
        _bulk(REDIS_PROBE_VALUE),
        b":1\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.flush"].skipped
    assert "non-destructive" in by_id["redis.flush"].skip_reason.lower()
    assert not by_id["redis.persist"].triggered


@patch.object(redis_probe, "tcp_transact")
def test_redis_auth_wall_is_signature(mock_tcp):
    noauth = b"-NOAUTH Authentication required.\r\n"
    mock_tcp.side_effect = _calls(
        noauth,
        b"-ERR invalid password\r\n",
        noauth,
        noauth,
        noauth,
        b"-ERR unknown command 'help'\r\n",
        noauth,
        noauth,
        noauth,
        noauth,
        noauth,
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.signature"].triggered
    assert "invalid password" in by_id["redis.signature"].detail.lower()
    assert "noauth" in by_id["redis.signature"].detail.lower()
    assert not by_id["redis.arbitrary_auth"].triggered
    assert by_id["redis.persist"].skipped
    assert by_id["redis.flush"].skipped
