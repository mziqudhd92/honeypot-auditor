"""Redis fingerprint engine.

Strategies: arbitrary auth (two random AUTH passwords) · state non-persistence
(key vanishes after reconnect / DBSIZE incoherent) · static signature (PING,
COMMAND, INFO, HELP, ECHO/SELECT, EVAL/CONFIG, AUTH wall, arity, TYPE/INCR,
QUIT zombie).

Never sends FLUSHALL/FLUSHDB/CONFIG SET/SCRIPT LOAD. Probe keys use a unique
``hpaudit_`` prefix and are DELeted after checks.
"""

from __future__ import annotations

import secrets

from honeypot_auditor.config import (
    REDIS_PROBE_KEY_PREFIX,
    REDIS_PROBE_VALUE,
    match_redis_arity_facade,
    match_redis_auth_any,
    match_redis_auth_wall,
    match_redis_command_stub,
    match_redis_config_stub,
    match_redis_dbsize_incoherent,
    match_redis_echo_mismatch,
    match_redis_eval_stub,
    match_redis_help_client,
    match_redis_incr_stub,
    match_redis_info_template,
    match_redis_ping_stub,
    match_redis_quit_zombie,
    match_redis_type_stub,
    match_redis_unknown_core,
)
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_roundtrips, tcp_transact
from honeypot_auditor.probes.common import is_safe_mode, random_creds, skip_suite

_REDIS_SKIP = (
    ("redis.arbitrary_auth", "Redis AUTH accepts two random passwords", "arbitrary_auth"),
    ("redis.persist", "Redis key does not persist across reconnect", "state_nonpersist"),
    ("redis.dbsize", "Redis DBSIZE does not reflect a successful SET", "state_nonpersist"),
    ("redis.ping_stub", "Redis PING does not return +PONG", "static_signature"),
    ("redis.command_stub", "Redis COMMAND is a stub instead of a catalog", "static_signature"),
    ("redis.info_frozen", "Redis INFO looks like a frozen dump", "static_signature"),
    ("redis.help_client", "Redis HELP returns redis-cli client text", "static_signature"),
    ("redis.core_missing", "Redis is missing core commands (ECHO/SELECT)", "static_signature"),
    ("redis.eval_stub", "Redis EVAL looks like a stub", "static_signature"),
    ("redis.config_stub", "Redis CONFIG GET looks like a stub", "static_signature"),
    ("redis.auth_wall", "Redis AUTH is always invalid and COMMAND is NOAUTH", "static_signature"),
    ("redis.echo_mismatch", "Redis ECHO does not return the probe token", "static_signature"),
    ("redis.incr_stub", "Redis INCR does not return an integer", "static_signature"),
    ("redis.type_stub", "Redis TYPE does not return +string for a string key", "static_signature"),
    ("redis.arity_facade", "Redis accepts GET with no arguments", "static_signature"),
    ("redis.quit_zombie", "Redis still answers after QUIT", "static_signature"),
)

_SAFE_ONLY = frozenset({"redis.ping_stub"})


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


def _ind(
    *,
    id: str,
    title: str,
    category: str,
    triggered: bool,
    detail: str,
    evidence: str = "",
    skipped: bool = False,
    skip_reason: str = "",
    error: str = "",
    fidelity: str = "medium",
    remediation: str = "",
) -> Indicator:
    return Indicator(
        id=id,
        title=title,
        category=category,
        triggered=triggered,
        skipped=skipped,
        skip_reason=skip_reason,
        error=error,
        protocol="redis",
        detail=detail,
        evidence=evidence,
        fidelity=fidelity,
        remediation=remediation,
    )


def probe_redis(host: str, port: int) -> list[Indicator]:
    ping, ping_err = _redis_call(host, port, "PING")
    if (ping_err and not ping) or not _looks_like_redis(ping):
        reason = closed_reason(ping_err) if ping_err else "not a Redis RESP speaker"
        return skip_suite(_REDIS_SKIP, reason, protocol="redis", error=ping_err)

    ping_hit = match_redis_ping_stub(ping)

    if is_safe_mode():
        out: list[Indicator] = []
        for iid, title, cat in _REDIS_SKIP:
            if iid in _SAFE_ONLY:
                out.append(
                    _ind(
                        id=iid,
                        title=title,
                        category=cat,
                        triggered=bool(ping_hit),
                        detail=ping_hit or "PING returned +PONG (or an error)",
                        evidence=ping[:160],
                        fidelity="high" if ping_hit else "medium",
                    )
                )
            else:
                out.extend(
                    skip_suite(
                        ((iid, title, cat),),
                        "safe-mode: handshake-only probe",
                        protocol="redis",
                    )
                )
        return out

    _user1, password1 = random_creds()
    _user2, password2 = random_creds()
    auth1, auth1_err = _redis_call(host, port, "AUTH", password1)
    auth2, auth2_err = _redis_call(host, port, "AUTH", password2)
    auth1_hit = match_redis_auth_any(auth1) if auth1 else None
    auth2_hit = match_redis_auth_any(auth2) if auth2 else None
    auth_hit = bool(auth1_hit and auth2_hit)
    auth_err = "; ".join(e for e in (auth1_err, auth2_err) if e)
    auth_reply_for_wall = auth1 or auth2

    command_reply, _ = _redis_call(host, port, "COMMAND")
    info1, _ = _redis_call(host, port, "INFO")
    info2, _ = _redis_call(host, port, "INFO")
    help_reply, _ = _redis_call(host, port, "HELP")
    echo_token = secrets.token_hex(4)
    echo_reply, _ = _redis_call(host, port, "ECHO", echo_token)
    select_reply, _ = _redis_call(host, port, "SELECT", "0")
    eval_reply, _ = _redis_call(host, port, "EVAL", "return 1", "0")
    config_reply, _ = _redis_call(host, port, "CONFIG", "GET", "*")
    arity_reply, _ = _redis_call(host, port, "GET")

    wall_hit = match_redis_auth_wall(auth_reply_for_wall, command_reply)
    command_hit = match_redis_command_stub(command_reply)
    info_hit = match_redis_info_template(info1, info2)
    help_hit = match_redis_help_client(help_reply)
    core_hits = [
        h
        for h in (
            match_redis_unknown_core("ECHO", echo_reply),
            match_redis_unknown_core("SELECT", select_reply),
        )
        if h
    ]
    eval_hit = match_redis_eval_stub(eval_reply)
    config_hit = match_redis_config_stub(config_reply)
    echo_hit = match_redis_echo_mismatch(echo_token, echo_reply)
    arity_hit = match_redis_arity_facade(arity_reply)

    quit_replies, quit_err = tcp_roundtrips(
        host, port, [_resp("QUIT"), _resp("PING")]
    )
    quit_text = quit_replies[0].decode("utf-8", "replace") if quit_replies else ""
    post_quit = quit_replies[1].decode("utf-8", "replace") if len(quit_replies) > 1 else ""
    quit_hit = match_redis_quit_zombie(quit_text, post_quit) if not quit_err or post_quit else None

    key = f"{REDIS_PROBE_KEY_PREFIX}{secrets.token_hex(4)}"
    incr_key = f"{REDIS_PROBE_KEY_PREFIX}i{secrets.token_hex(4)}"
    dbsize_before, _ = _redis_call(host, port, "DBSIZE")
    set_reply, set_err = _redis_call(host, port, "SET", key, REDIS_PROBE_VALUE)
    set_ok = _resp_ok(set_reply)
    persist_triggered = False
    persist_detail = ""
    persist_skipped = ""
    dbsize_hit = None
    type_hit = None
    incr_hit = None

    if not set_ok:
        persist_skipped = set_err or set_reply.strip()[:80] or "SET rejected"
    else:
        dbsize_after, _ = _redis_call(host, port, "DBSIZE")
        dbsize_hit = match_redis_dbsize_incoherent(True, dbsize_before, dbsize_after)
        type_reply, _ = _redis_call(host, port, "TYPE", key)
        type_hit = match_redis_type_stub(type_reply)
        incr_reply, _ = _redis_call(host, port, "INCR", incr_key)
        incr_hit = match_redis_incr_stub(incr_reply)
        got, get_err = _redis_call(host, port, "GET", key)
        if get_err and not got:
            persist_triggered = True
            persist_detail = f"GET after reconnect failed: {closed_reason(get_err)}"
        else:
            persist_triggered = REDIS_PROBE_VALUE not in got or got.lstrip().startswith("$-1")
            persist_detail = f"GET after reconnect: {got[:160]!r}"
        _redis_call(host, port, "DEL", key)
        _redis_call(host, port, "DEL", incr_key)

    auth_skipped = bool(auth_err) and not (auth1 or auth2)
    return [
        _ind(
            id="redis.arbitrary_auth",
            title="Redis AUTH accepts two random passwords",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason=closed_reason(auth_err) if auth_skipped else "",
            error=auth_err if auth_skipped else "",
            detail=(
                "two independent AUTH passwords both returned +OK"
                if auth_hit
                else (
                    (auth1 or auth2 or "").strip()[:160]
                    or "AUTH not accepted with two random passwords"
                )
            ),
            evidence=f"{password1},{password2}" if auth_hit else password1,
            fidelity="decisive" if auth_hit else "medium",
            remediation="Reject unknown AUTH passwords instead of always returning +OK",
        ),
        _ind(
            id="redis.persist",
            title="Redis key does not persist across reconnect",
            category="state_nonpersist",
            triggered=persist_triggered,
            skipped=bool(persist_skipped),
            skip_reason=persist_skipped,
            detail=persist_detail or persist_skipped or "key survived reconnect",
            fidelity="high" if persist_triggered else "medium",
        ),
        _ind(
            id="redis.dbsize",
            title="Redis DBSIZE does not reflect a successful SET",
            category="state_nonpersist",
            triggered=bool(dbsize_hit),
            skipped=bool(persist_skipped),
            skip_reason=persist_skipped,
            detail=dbsize_hit or persist_skipped or "DBSIZE increased after SET",
            fidelity="high" if dbsize_hit else "medium",
        ),
        _ind(
            id="redis.ping_stub",
            title="Redis PING does not return +PONG",
            category="static_signature",
            triggered=bool(ping_hit),
            detail=ping_hit or "PING returned +PONG (or an error)",
            evidence=ping[:160],
            fidelity="high" if ping_hit else "medium",
        ),
        _ind(
            id="redis.command_stub",
            title="Redis COMMAND is a stub instead of a catalog",
            category="static_signature",
            triggered=bool(command_hit),
            detail=command_hit or "COMMAND returned a catalog-shaped reply",
            evidence=command_reply[:160],
            fidelity="high" if command_hit else "medium",
        ),
        _ind(
            id="redis.info_frozen",
            title="Redis INFO looks like a frozen dump",
            category="static_signature",
            triggered=bool(info_hit),
            detail=info_hit or "INFO clock/stats advance between calls",
            evidence=info1[:200],
            fidelity="high" if info_hit else "medium",
        ),
        _ind(
            id="redis.help_client",
            title="Redis HELP returns redis-cli client text",
            category="static_signature",
            triggered=bool(help_hit),
            detail=help_hit or "HELP does not look like redis-cli client text",
            evidence=help_reply[:160],
            fidelity="high" if help_hit else "medium",
        ),
        _ind(
            id="redis.core_missing",
            title="Redis is missing core commands (ECHO/SELECT)",
            category="static_signature",
            triggered=bool(core_hits),
            detail="; ".join(core_hits) if core_hits else "ECHO and SELECT look implemented",
            fidelity="high" if core_hits else "medium",
        ),
        _ind(
            id="redis.eval_stub",
            title="Redis EVAL looks like a stub",
            category="static_signature",
            triggered=bool(eval_hit),
            detail=eval_hit or "EVAL did not look like a stub",
            evidence=eval_reply[:120],
            fidelity="high" if eval_hit else "medium",
        ),
        _ind(
            id="redis.config_stub",
            title="Redis CONFIG GET looks like a stub",
            category="static_signature",
            triggered=bool(config_hit),
            detail=config_hit or "CONFIG GET did not look like a stub",
            evidence=config_reply[:120],
            fidelity="high" if config_hit else "medium",
        ),
        _ind(
            id="redis.auth_wall",
            title="Redis AUTH is always invalid and COMMAND is NOAUTH",
            category="static_signature",
            triggered=bool(wall_hit),
            detail=wall_hit or "AUTH/COMMAND auth wall not observed",
            fidelity="high" if wall_hit else "medium",
            remediation="OpenCanary-class Redis stubs always reject AUTH and NOAUTH everything else",
        ),
        _ind(
            id="redis.echo_mismatch",
            title="Redis ECHO does not return the probe token",
            category="static_signature",
            triggered=bool(echo_hit),
            detail=echo_hit or "ECHO returned the probe token",
            evidence=echo_reply[:120],
            fidelity="high" if echo_hit else "medium",
        ),
        _ind(
            id="redis.incr_stub",
            title="Redis INCR does not return an integer",
            category="static_signature",
            triggered=bool(incr_hit),
            skipped=bool(persist_skipped),
            skip_reason=persist_skipped,
            detail=incr_hit or persist_skipped or "INCR returned an integer reply",
            fidelity="high" if incr_hit else "medium",
        ),
        _ind(
            id="redis.type_stub",
            title="Redis TYPE does not return +string for a string key",
            category="static_signature",
            triggered=bool(type_hit),
            skipped=bool(persist_skipped),
            skip_reason=persist_skipped,
            detail=type_hit or persist_skipped or "TYPE returned +string",
            fidelity="high" if type_hit else "medium",
        ),
        _ind(
            id="redis.arity_facade",
            title="Redis accepts GET with no arguments",
            category="static_signature",
            triggered=bool(arity_hit),
            detail=arity_hit or "GET with no arguments returned wrong-arity (or NOAUTH)",
            evidence=arity_reply[:120],
            fidelity="high" if arity_hit else "medium",
        ),
        _ind(
            id="redis.quit_zombie",
            title="Redis still answers after QUIT",
            category="static_signature",
            triggered=bool(quit_hit),
            skipped=bool(quit_err) and not post_quit,
            skip_reason=closed_reason(quit_err) if quit_err and not post_quit else "",
            detail=quit_hit or "session closed (or stayed quiet) after QUIT",
            evidence=f"QUIT {quit_text[:60]!r}; post {post_quit[:60]!r}",
            fidelity="high" if quit_hit else "medium",
        ),
    ]
