"""Redis fingerprint engine.

Strategies: arbitrary auth (AUTH any-password) · state non-persistence
(key vanishes after reconnect) · static signature (COMMAND stub,
frozen INFO, HELP redis-cli, missing ECHO/SELECT).
"""

from __future__ import annotations

import secrets

from honeypot_auditor.config import (
    REDIS_PROBE_KEY_PREFIX,
    REDIS_PROBE_VALUE,
    match_redis_auth_any,
    match_redis_auth_wall,
    match_redis_command_stub,
    match_redis_config_stub,
    match_redis_eval_stub,
    match_redis_help_client,
    match_redis_info_template,
    match_redis_unknown_core,
)
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import random_creds, skip_suite

_REDIS_SKIP = (
    ("redis.arbitrary_auth", "Redis AUTH accepts random credentials", "arbitrary_auth"),
    ("redis.persist", "Redis key does not persist across reconnect", "state_nonpersist"),
    ("redis.flush", "Redis FLUSHALL does not actually clear keys", "state_nonpersist"),
    ("redis.signature", "Redis COMMAND/INFO/HELP/ECHO look like a stub", "static_signature"),
)


def _resp(*args: str) -> bytes:
    chunks = [f"*{len(args)}\r\n".encode()]
    for arg in args:
        data = arg.encode("utf-8")
        chunks.append(f"${len(data)}\r\n".encode())
        chunks.append(data)
        chunks.append(b"\r\n")
    return b"".join(chunks)


def _redis_call(host: str, port: int, *args: str) -> tuple[str, str]:
    raw, err = tcp_transact(host, port, _resp(*args))
    return raw.decode("utf-8", "replace"), err


def _looks_like_redis(text: str) -> bool:
    return (text or "").lstrip().startswith(("+", "-", ":", "$", "*"))


def _resp_ok(text: str) -> bool:
    return (text or "").lstrip().startswith("+OK")


def probe_redis(host: str, port: int) -> list[Indicator]:
    ping, ping_err = _redis_call(host, port, "PING")
    if (ping_err and not ping) or not _looks_like_redis(ping):
        reason = closed_reason(ping_err) if ping_err else "not a Redis RESP speaker"
        return skip_suite(_REDIS_SKIP, reason, protocol="redis", error=ping_err)

    _user, password = random_creds()
    auth_reply, auth_err = _redis_call(host, port, "AUTH", password)
    auth_hit = match_redis_auth_any(auth_reply) if auth_reply else None

    command_reply, _ = _redis_call(host, port, "COMMAND")
    info1, _ = _redis_call(host, port, "INFO")
    info2, _ = _redis_call(host, port, "INFO")
    help_reply, _ = _redis_call(host, port, "HELP")
    echo_token = secrets.token_hex(4)
    echo_reply, _ = _redis_call(host, port, "ECHO", echo_token)
    select_reply, _ = _redis_call(host, port, "SELECT", "0")
    eval_reply, _ = _redis_call(host, port, "EVAL", "return 1", "0")
    config_reply, _ = _redis_call(host, port, "CONFIG", "GET", "*")

    sig_hits = [
        hit
        for hit in (
            match_redis_auth_wall(auth_reply, command_reply),
            match_redis_command_stub(command_reply),
            match_redis_info_template(info1, info2),
            match_redis_help_client(help_reply),
            match_redis_unknown_core("ECHO", echo_reply),
            match_redis_unknown_core("SELECT", select_reply),
            match_redis_eval_stub(eval_reply),
            match_redis_config_stub(config_reply),
        )
        if hit
    ]

    key = f"{REDIS_PROBE_KEY_PREFIX}{secrets.token_hex(4)}"
    set_reply, set_err = _redis_call(host, port, "SET", key, REDIS_PROBE_VALUE)
    persist_triggered = False
    persist_detail = ""
    persist_skipped = ""
    flush_skipped = ""

    if not _resp_ok(set_reply):
        persist_skipped = set_err or set_reply.strip()[:80] or "SET rejected"
        flush_skipped = persist_skipped
    else:
        got, get_err = _redis_call(host, port, "GET", key)
        if get_err and not got:
            persist_triggered = True
            persist_detail = f"GET after reconnect failed: {closed_reason(get_err)}"
        else:
            persist_triggered = REDIS_PROBE_VALUE not in got or got.lstrip().startswith("$-1")
            persist_detail = f"GET after reconnect: {got[:160]!r}"
        # FLUSHALL wipes real databases; stub flush behavior is covered by COMMAND/INFO tells.
        flush_skipped = "FLUSHALL probe omitted (non-destructive policy)"
        _redis_call(host, port, "DEL", key)

    return [
        Indicator(
            id="redis.arbitrary_auth",
            title="Redis AUTH accepts random credentials",
            category="arbitrary_auth",
            triggered=bool(auth_hit),
            skipped=bool(auth_err) and not auth_reply,
            skip_reason=closed_reason(auth_err) if auth_err and not auth_reply else "",
            protocol="redis",
            detail=auth_hit or (auth_reply.strip()[:160] or "AUTH not accepted with random credentials"),
            evidence=password,
        ),
        Indicator(
            id="redis.persist",
            title="Redis key does not persist across reconnect",
            category="state_nonpersist",
            triggered=persist_triggered,
            skipped=bool(persist_skipped),
            skip_reason=persist_skipped,
            protocol="redis",
            detail=persist_detail or persist_skipped or "key survived reconnect",
        ),
        Indicator(
            id="redis.flush",
            title="Redis FLUSHALL does not actually clear keys",
            category="state_nonpersist",
            triggered=False,
            skipped=bool(flush_skipped),
            skip_reason=flush_skipped,
            protocol="redis",
            detail=flush_skipped or "FLUSHALL probe omitted (non-destructive policy)",
        ),
        Indicator(
            id="redis.signature",
            title="Redis COMMAND/INFO/HELP/ECHO look like a stub",
            category="static_signature",
            triggered=bool(sig_hits),
            protocol="redis",
            detail="; ".join(sig_hits) if sig_hits else "COMMAND catalog, INFO clock, and ECHO look real",
            evidence=f"COMMAND {command_reply[:120]!r}\nINFO {info1[:200]!r}",
        ),
    ]
