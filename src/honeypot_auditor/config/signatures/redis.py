from __future__ import annotations

import time


def match_redis_eval_stub(reply: str) -> str | None:
    """EVAL accepted but did not execute Lua (stub +OK or unknown command)."""
    text = (reply or "").lstrip()
    if not text:
        return None
    if text.startswith("+OK"):
        return "EVAL returned +OK without Lua execution"
    if "unknown command" in text.lower():
        return "EVAL unimplemented"
    return None


def match_redis_config_stub(reply: str) -> str | None:
    """CONFIG GET should return a bulk/array catalog, not +OK or NOAUTH wall."""
    text = (reply or "").lstrip()
    if not text:
        return None
    if text.startswith("+OK"):
        return "CONFIG GET returned +OK instead of parameters"
    if text.startswith("-ERR wrong number of arguments"):
        return "CONFIG GET wrong-arity stub"
    if "noauth" in text.lower():
        return None
    if text.startswith("-ERR unknown command"):
        return "CONFIG GET unimplemented"
    return None


def match_redis_auth_any(reply: str) -> str | None:
    """AUTH with random credentials returned +OK (real Redis rejects or WRONGPASS)."""
    if (reply or "").lstrip().startswith("+OK"):
        return "AUTH accepted random credentials"
    return None


def match_redis_auth_wall(auth_reply: str, command_reply: str) -> str | None:
    """AUTH is always invalid-password and COMMAND is NOAUTH (never a catalog)."""
    auth = (auth_reply or "").lower()
    cmd = (command_reply or "").lower()
    if "invalid password" in auth and "noauth" in cmd:
        return "AUTH always invalid password and COMMAND is NOAUTH"
    return None


def match_redis_command_stub(reply: str) -> str | None:
    """COMMAND is a catalog array on real Redis; stubs return +OK or unknown."""
    text = (reply or "").lstrip()
    if not text:
        return None
    if text.startswith("+OK"):
        return "COMMAND returned +OK instead of a command catalog"
    if "unknown command" in text.lower():
        return "COMMAND unimplemented"
    return None


def match_redis_help_client(reply: str) -> str | None:
    """HELP on the wire returns redis-cli client text instead of server command help."""
    low = (reply or "").lower()
    if "redis-cli" in low or "redisclirc" in low:
        return "HELP returns redis-cli client text"
    return None


def match_redis_unknown_core(cmd: str, reply: str) -> str | None:
    """A core command (ECHO, SELECT, …) is unimplemented."""
    if "unknown command" in (reply or "").lower():
        return f"{cmd} unimplemented (core command missing)"
    return None


def match_redis_ping_stub(reply: str) -> str | None:
    """PING must return +PONG (or an error); stubs often answer +OK."""
    text = (reply or "").lstrip()
    if not text:
        return None
    if text.upper().startswith("+PONG"):
        return None
    if text.startswith("-"):
        return None
    if text.startswith("+OK"):
        return "PING returned +OK instead of +PONG"
    if text.startswith(("+", "$", "*", ":")):
        return "PING did not return +PONG"
    return None


def match_redis_echo_mismatch(token: str, reply: str) -> str | None:
    """ECHO must return the bulk token; +OK / wrong payload is a facade."""
    if match_redis_unknown_core("ECHO", reply):
        return None
    text = (reply or "").lstrip()
    if not text or not token:
        return None
    if text.startswith("-"):
        return None
    if text.startswith("+OK"):
        return "ECHO returned +OK instead of bulk string"
    if text.startswith("$-1"):
        return "ECHO returned null bulk"
    if token not in reply:
        return "ECHO did not echo the probe token"
    return None


def match_redis_incr_stub(reply: str) -> str | None:
    """INCR must return an integer reply; stubs often return +OK."""
    text = (reply or "").lstrip()
    if not text:
        return None
    if text.startswith(":"):
        return None
    if "noauth" in text.lower() or "wrongtype" in text.lower():
        return None
    if text.startswith("+OK"):
        return "INCR returned +OK instead of an integer"
    if "unknown command" in text.lower():
        return "INCR unimplemented"
    if text.startswith("+"):
        return "INCR did not return an integer reply"
    return None


def match_redis_type_stub(reply: str) -> str | None:
    """TYPE on a string key must return +string."""
    text = (reply or "").lstrip()
    if not text:
        return None
    if text.lower().startswith("+string"):
        return None
    if "noauth" in text.lower():
        return None
    if text.startswith("+OK"):
        return "TYPE returned +OK instead of +string"
    if "unknown command" in text.lower():
        return "TYPE unimplemented"
    if text.startswith("+"):
        return f"TYPE returned {text.splitlines()[0][:40]!r} for a string key"
    return None


def match_redis_arity_facade(reply: str) -> str | None:
    """GET with zero args must be wrong-arity; +OK means the parser is a facade."""
    text = (reply or "").lstrip()
    if not text:
        return None
    if "wrong number of arguments" in text.lower():
        return None
    if "noauth" in text.lower():
        return None
    if "unknown command" in text.lower():
        return None
    if text.startswith("+OK"):
        return "GET with no arguments returned +OK"
    if text.startswith(("$", "*", ":")) and not text.startswith("-"):
        return "GET with no arguments returned a value instead of wrong-arity"
    return None


def match_redis_dbsize_incoherent(
    set_ok: bool, before: str, after: str
) -> str | None:
    """Successful SET should increase DBSIZE; stubs often stay at 0 or return +OK."""
    if not set_ok:
        return None
    after_text = (after or "").lstrip()
    if not after_text:
        return None
    if after_text.startswith("+OK"):
        return "DBSIZE returned +OK instead of an integer"
    if "unknown command" in after_text.lower():
        return "DBSIZE unimplemented"
    if "noauth" in after_text.lower():
        return None

    def _parse_int(blob: str) -> int | None:
        text = (blob or "").lstrip()
        if text.startswith(":"):
            try:
                return int(text[1:].splitlines()[0].strip())
            except ValueError:
                return None
        return None

    n_after = _parse_int(after)
    if n_after is None:
        return None
    n_before = _parse_int(before)
    if n_before is not None and n_after < n_before + 1:
        return f"DBSIZE did not increase after SET ({n_before} → {n_after})"
    if n_before is None and n_after == 0:
        return "DBSIZE is 0 after a successful SET"
    return None


def match_redis_quit_zombie(quit_reply: str, post_quit: str) -> str | None:
    """After QUIT +OK, real Redis closes; stubs often keep answering."""
    quit_text = (quit_reply or "").lstrip()
    post = (post_quit or "").lstrip()
    if not quit_text.startswith("+OK"):
        return None
    if not post:
        return None
    if post.startswith(("+", "-", ":", "$", "*")):
        return "connection still answers after QUIT"
    return None


def _redis_info_field(blob: str, key: str) -> str | None:
    prefix = f"{key}:"
    for line in (blob or "").replace("\r\n", "\n").splitlines():
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def match_redis_info_template(info1: str, info2: str = "") -> str | None:
    """INFO is a frozen dump: stale clock, or stats that do not move between calls."""
    usec = _redis_info_field(info1, "server_time_usec")
    if usec:
        try:
            stamp = int(usec)
            seconds = stamp / 1_000_000 if stamp > 10_000_000_000 else float(stamp)
            if abs(time.time() - seconds) > 7 * 86400:
                return "INFO server_time is a frozen snapshot"
        except ValueError:
            pass
    if info2:
        t1 = _redis_info_field(info1, "server_time_usec")
        t2 = _redis_info_field(info2, "server_time_usec")
        if t1 and t2 and t1 == t2:
            return "INFO server_time_usec identical across calls (static dump)"
        c1 = _redis_info_field(info1, "total_commands_processed")
        c2 = _redis_info_field(info2, "total_commands_processed")
        if c1 and c2 and c1 == c2:
            return "INFO stats do not change after commands (static dump)"
    return None


def match_redis_flush_stub(get_after_flush: str, expected: str) -> str | None:
    """FLUSHALL returned OK but the probe key is still there."""
    text = get_after_flush or ""
    if not expected or text.lstrip().startswith("$-1"):
        return None
    if expected in text:
        return "FLUSHALL returned OK but key still present"
    return None
