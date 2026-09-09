"""Redis probe tests with mocks."""

from __future__ import annotations

import time
from unittest.mock import patch

import honeypot_auditor.probes.redis as redis_probe
from honeypot_auditor.config import PROTOCOL_STRATEGIES, REDIS_PROBE_VALUE

_BEEHIVE_INFO = (
    "$180\r\n"
    "# Server\r\n"
    "redis_version:6.2.6\r\n"
    "server_time_usec:1644233854325059\r\n"
    "uptime_in_seconds:103028\r\n"
    "total_commands_processed:11\r\n"
)

_REDIS_IDS = {
    "redis.arbitrary_auth",
    "redis.persist",
    "redis.dbsize",
    "redis.ping_stub",
    "redis.command_stub",
    "redis.info_frozen",
    "redis.help_client",
    "redis.core_missing",
    "redis.eval_stub",
    "redis.config_stub",
    "redis.auth_wall",
    "redis.echo_mismatch",
    "redis.incr_stub",
    "redis.type_stub",
    "redis.arity_facade",
    "redis.quit_zombie",
}


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


def _live_info(commands: int, *, skew_us: int = 0) -> bytes:
    usec = int(time.time() * 1_000_000) + skew_us
    body = f"server_time_usec:{usec}\r\ntotal_commands_processed:{commands}\r\n"
    return f"${len(body)}\r\n{body}".encode()


def _wrong_arity() -> bytes:
    return b"-ERR wrong number of arguments for 'get' command\r\n"


def _no_password() -> bytes:
    return b"-ERR AUTH called without any password configured\r\n"


def _compliant_catalog_flow(echo_token: str = "abcd") -> list[bytes]:
    """Replies for a well-behaved Redis through arity GET (before DBSIZE/SET)."""
    return [
        _pong(),
        _no_password(),
        _no_password(),
        b"*1\r\n*1\r\n$3\r\nget\r\n",
        _live_info(40),
        _live_info(41, skew_us=1500),
        b"*1\r\n$4\r\nECHO\r\n",
        _bulk(echo_token),
        _ok(),  # SELECT
        b":1\r\n",  # EVAL return 1
        b"*0\r\n",  # CONFIG GET empty-but-array ok for stub matcher
        _wrong_arity(),
    ]


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
def test_redis_closed_port_skips_all_strategies(mock_round, mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    assert {i.id for i in inds} == _REDIS_IDS
    assert len(inds) == 16
    assert all(i.skipped for i in inds)
    mock_round.assert_not_called()


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
def test_redis_non_resp_speaker_skips_all(mock_round, mock_tcp):
    mock_tcp.return_value = (b"HTTP/1.1 200 OK\r\n", "")
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    assert {i.id for i in inds} == _REDIS_IDS
    assert all(i.skipped for i in inds)
    assert any("not a Redis RESP speaker" in i.skip_reason for i in inds)
    mock_round.assert_not_called()


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
def test_redis_stub_auth_and_signatures(mock_round, mock_tcp):
    mock_round.return_value = ([_ok(), _pong()], "")
    mock_tcp.side_effect = _calls(
        _pong(),
        _ok(),
        _ok(),
        _ok(),
        _BEEHIVE_INFO.encode(),
        _BEEHIVE_INFO.encode(),
        b"*2\r\n$13\r\nredis-cli 7.0.5\r\n$20\r\nSet ~/.redisclirc\r\n",
        _unknown("ECHO"),
        _unknown("SELECT"),
        _ok(),
        _ok(),
        _ok(),  # arity GET → +OK
        b":0\r\n",
        _ok(),
        b":0\r\n",
        _ok(),
        _ok(),
        _bulk(REDIS_PROBE_VALUE),
        b":1\r\n",
        b":1\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert {i.id for i in inds} == _REDIS_IDS
    assert by_id["redis.arbitrary_auth"].triggered
    assert by_id["redis.arbitrary_auth"].fidelity == "decisive"
    assert by_id["redis.dbsize"].triggered
    assert by_id["redis.command_stub"].triggered
    assert by_id["redis.info_frozen"].triggered
    assert by_id["redis.help_client"].triggered
    assert by_id["redis.core_missing"].triggered
    assert by_id["redis.eval_stub"].triggered
    assert by_id["redis.config_stub"].triggered
    assert by_id["redis.arity_facade"].triggered
    assert by_id["redis.type_stub"].triggered
    assert by_id["redis.incr_stub"].triggered
    assert by_id["redis.quit_zombie"].triggered
    assert not by_id["redis.persist"].triggered
    assert not by_id["redis.auth_wall"].triggered


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
@patch.object(redis_probe.secrets, "token_hex", side_effect=["abcd", "key1", "ikey1"])
def test_redis_key_vanishes_after_reconnect(mock_hex, mock_round, mock_tcp):
    mock_round.return_value = ([_ok(), b""], "")
    mock_tcp.side_effect = _calls(
        *_compliant_catalog_flow("abcd"),
        b":5\r\n",
        _ok(),
        b":6\r\n",
        b"+string\r\n",
        b":1\r\n",
        b"$-1\r\n",
        b":1\r\n",
        b":1\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.persist"].triggered
    assert by_id["redis.persist"].fidelity == "high"
    assert not by_id["redis.arbitrary_auth"].triggered
    assert not by_id["redis.command_stub"].triggered
    assert not by_id["redis.info_frozen"].triggered
    assert not by_id["redis.echo_mismatch"].triggered
    assert not by_id["redis.quit_zombie"].triggered
    assert not by_id["redis.dbsize"].triggered


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
@patch.object(redis_probe.secrets, "token_hex", side_effect=["abcd", "key1", "ikey1"])
def test_redis_compliant_server_triggers_nothing(mock_hex, mock_round, mock_tcp):
    mock_round.return_value = ([_ok(), b""], "")
    mock_tcp.side_effect = _calls(
        *_compliant_catalog_flow("abcd"),
        b":5\r\n",
        _ok(),
        b":6\r\n",
        b"+string\r\n",
        b":1\r\n",
        _bulk(REDIS_PROBE_VALUE),
        b":1\r\n",
        b":1\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    assert {i.id for i in inds} == _REDIS_IDS
    triggered = [i.id for i in inds if i.triggered]
    assert triggered == [], triggered
    assert not any(i.skipped for i in inds)


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
def test_redis_single_auth_ok_does_not_trigger_arbitrary_auth(mock_round, mock_tcp):
    """Both passwords must succeed; one +OK is inconclusive."""
    mock_round.return_value = ([_ok(), b""], "")
    mock_tcp.side_effect = _calls(
        _pong(),
        _ok(),  # AUTH1 accepted
        b"-WRONGPASS invalid username-password pair\r\n",  # AUTH2 rejected
        b"*1\r\n$3\r\nget\r\n",
        _live_info(1),
        _live_info(2, skew_us=200),
        b"+OK\r\n",
        _bulk("x"),
        _ok(),
        b":1\r\n",
        b"*0\r\n",
        _wrong_arity(),
        b":0\r\n",
        b"-NOAUTH Authentication required.\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert not by_id["redis.arbitrary_auth"].triggered
    assert by_id["redis.persist"].skipped


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
def test_redis_set_rejected_skips_persist_and_dbsize(mock_round, mock_tcp):
    mock_round.return_value = ([_ok(), b""], "")
    mock_tcp.side_effect = _calls(
        _pong(),
        b"-WRONGPASS invalid password\r\n",
        b"-WRONGPASS invalid password\r\n",
        b"*1\r\n$3\r\nget\r\n",
        _live_info(1),
        _live_info(2, skew_us=200),
        b"+OK\r\n",
        _bulk("x"),
        _ok(),
        b":1\r\n",
        b"*0\r\n",
        _wrong_arity(),
        b":0\r\n",
        b"-NOAUTH Authentication required.\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.persist"].skipped
    assert by_id["redis.dbsize"].skipped
    assert by_id["redis.incr_stub"].skipped
    assert by_id["redis.type_stub"].skipped


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
def test_redis_auth_wall_is_signature(mock_round, mock_tcp):
    mock_round.return_value = ([b"-NOAUTH Authentication required.\r\n"], "closed")
    noauth = b"-NOAUTH Authentication required.\r\n"
    mock_tcp.side_effect = _calls(
        noauth,
        b"-ERR invalid password\r\n",
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
        noauth,
        noauth,
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.auth_wall"].triggered
    assert by_id["redis.auth_wall"].fidelity == "high"
    assert "invalid password" in by_id["redis.auth_wall"].detail.lower()
    assert not by_id["redis.arbitrary_auth"].triggered
    assert not by_id["redis.ping_stub"].triggered  # NOAUTH is not a PING stub
    assert by_id["redis.persist"].skipped
    assert by_id["redis.dbsize"].skipped


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
@patch.object(redis_probe.secrets, "token_hex", side_effect=["eeee", "k2", "ik2"])
def test_redis_ping_ok_and_echo_mismatch(mock_hex, mock_round, mock_tcp):
    mock_round.return_value = ([_ok(), b""], "")
    mock_tcp.side_effect = _calls(
        _ok(),  # PING +OK stub
        _no_password(),
        _no_password(),
        b"*1\r\n$3\r\nget\r\n",
        _live_info(1),
        _live_info(2, skew_us=200),
        b"+OK\r\n",
        _bulk("tok"),  # wrong echo
        _ok(),
        b":1\r\n",
        b"*0\r\n",
        _wrong_arity(),
        b":0\r\n",
        _ok(),
        b":1\r\n",
        b"+string\r\n",
        b":1\r\n",
        _bulk(REDIS_PROBE_VALUE),
        b":1\r\n",
        b":1\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.ping_stub"].triggered
    assert by_id["redis.echo_mismatch"].triggered
    assert not by_id["redis.core_missing"].triggered


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
@patch.object(redis_probe.secrets, "token_hex", side_effect=["tok1", "k3", "ik3"])
def test_redis_echo_ok_facade_and_type_hash(mock_hex, mock_round, mock_tcp):
    mock_round.return_value = ([_ok(), b""], "")
    mock_tcp.side_effect = _calls(
        _pong(),
        _no_password(),
        _no_password(),
        b"*1\r\n$3\r\nget\r\n",
        _live_info(10),
        _live_info(11, skew_us=300),
        b"+OK\r\n",
        _ok(),  # ECHO +OK facade
        _ok(),
        b":1\r\n",
        b"*0\r\n",
        _wrong_arity(),
        b":0\r\n",
        _ok(),
        b":1\r\n",
        b"+hash\r\n",  # TYPE wrong
        b":1\r\n",
        _bulk(REDIS_PROBE_VALUE),
        b":1\r\n",
        b":1\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.echo_mismatch"].triggered
    assert "ECHO returned +OK" in by_id["redis.echo_mismatch"].detail
    assert by_id["redis.type_stub"].triggered
    assert "+hash" in by_id["redis.type_stub"].detail


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
@patch.object(redis_probe.secrets, "token_hex", side_effect=["tok2", "k4", "ik4"])
def test_redis_dbsize_ok_stub_and_incr_unknown(mock_hex, mock_round, mock_tcp):
    mock_round.return_value = ([_ok(), b""], "")
    mock_tcp.side_effect = _calls(
        _pong(),
        _no_password(),
        _no_password(),
        b"*1\r\n$3\r\nget\r\n",
        _live_info(10),
        _live_info(11, skew_us=300),
        b"+OK\r\n",
        _bulk("tok2"),
        _ok(),
        b":1\r\n",
        b"*0\r\n",
        _wrong_arity(),
        b":0\r\n",
        _ok(),
        _ok(),  # DBSIZE +OK after SET
        b"+string\r\n",
        _unknown("INCR"),
        _bulk(REDIS_PROBE_VALUE),
        b":1\r\n",
        b":1\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.dbsize"].triggered
    assert "+OK" in by_id["redis.dbsize"].detail
    assert by_id["redis.incr_stub"].triggered
    assert "unimplemented" in by_id["redis.incr_stub"].detail.lower()


@patch.object(redis_probe, "tcp_transact")
@patch.object(redis_probe, "tcp_roundtrips")
@patch.object(redis_probe.secrets, "token_hex", side_effect=["tok3", "k5", "ik5"])
def test_redis_arity_returns_bulk_value(mock_hex, mock_round, mock_tcp):
    mock_round.return_value = ([_ok(), b""], "")
    mock_tcp.side_effect = _calls(
        *_compliant_catalog_flow("tok3")[:-1],
        _bulk("surprise"),  # GET no-args returns a value
        b":0\r\n",
        _ok(),
        b":1\r\n",
        b"+string\r\n",
        b":1\r\n",
        _bulk(REDIS_PROBE_VALUE),
        b":1\r\n",
        b":1\r\n",
    )
    inds = redis_probe.probe_redis("127.0.0.1", 6379)
    by_id = {i.id: i for i in inds}
    assert by_id["redis.arity_facade"].triggered
    assert "value" in by_id["redis.arity_facade"].detail.lower()


@patch.object(redis_probe, "tcp_transact")
def test_redis_safe_mode_handshake_only(mock_tcp):
    from honeypot_auditor.settings import settings

    mock_tcp.return_value = (_ok(), "")
    prev = settings.safe_mode
    settings.safe_mode = True
    try:
        inds = redis_probe.probe_redis("127.0.0.1", 6379)
    finally:
        settings.safe_mode = prev
    by_id = {i.id: i for i in inds}
    assert {i.id for i in inds} == _REDIS_IDS
    assert by_id["redis.ping_stub"].triggered
    assert all(i.skipped for i in inds if i.id != "redis.ping_stub")
    assert mock_tcp.call_count == 1


@patch.object(redis_probe, "tcp_transact")
def test_redis_safe_mode_pong_not_stub(mock_tcp):
    from honeypot_auditor.settings import settings

    mock_tcp.return_value = (_pong(), "")
    prev = settings.safe_mode
    settings.safe_mode = True
    try:
        inds = redis_probe.probe_redis("127.0.0.1", 6379)
    finally:
        settings.safe_mode = prev
    by_id = {i.id: i for i in inds}
    assert not by_id["redis.ping_stub"].triggered
    assert all(i.skipped for i in inds if i.id != "redis.ping_stub")


def test_redis_protocol_strategies_blurbs():
    catalog = PROTOCOL_STRATEGIES["redis"]
    assert "two random AUTH" in catalog["arbitrary_auth"]
    assert "DBSIZE" in catalog["state_nonpersist"]
    assert "QUIT zombie" in catalog["static_signature"]
