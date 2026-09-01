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
