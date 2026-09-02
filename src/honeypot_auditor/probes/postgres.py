"""PostgreSQL fingerprint engine.

Strategies: static signature (SSLRequest → N then cleartext-only) ·
state non-persistence (frozen auth.c:326 FATAL blob). Arbitrary auth is not on
the basic path (deny-all looks like a wrong password on a real server).
"""

from __future__ import annotations

import struct

from honeypot_auditor.config import match_postgres_auth_c_blob, match_postgres_cleartext_only
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_roundtrips
from honeypot_auditor.probes.common import random_creds, skip_suite

_POSTGRES_SKIP = (
    (
        "postgres.cleartext",
        "Postgres offers only cleartext password after SSL reject",
        "static_signature",
    ),
    ("postgres.auth_blob", "Postgres FATAL auth fail freezes auth.c:326", "state_nonpersist"),
)

_SSL_REQUEST = b"\x00\x00\x00\x08\x04\xd2\x16/"


def _pg_startup(user: str, database: str = "postgres") -> bytes:
    body = (
        struct.pack("!I", 196608)  # protocol 3.0
        + b"user\x00"
        + user.encode("utf-8", "replace")
        + b"\x00database\x00"
        + database.encode("utf-8", "replace")
        + b"\x00\x00"
    )
    return struct.pack("!I", len(body) + 4) + body


def _pg_password(password: str) -> bytes:
    inner = password.encode("utf-8", "replace") + b"\x00"
    return b"p" + struct.pack("!I", len(inner) + 4) + inner


def probe_postgres(host: str, port: int) -> list[Indicator]:
    user, password = random_creds()
    replies, err = tcp_roundtrips(
        host,
        port,
        [_SSL_REQUEST, _pg_startup(user), _pg_password(password)],
        recv_first=False,
    )
    if err and not replies:
        return skip_suite(_POSTGRES_SKIP, closed_reason(err), protocol="postgres", error=err)

    ssl_reply = replies[0] if replies else b""
    auth_reply = replies[1] if len(replies) > 1 else b""
    fail_reply = replies[2] if len(replies) > 2 else b""

    # Not a Postgres speaker if SSL path never answered with N/S/Error.
    if not ssl_reply and not auth_reply:
        return skip_suite(_POSTGRES_SKIP, "not a Postgres speaker", protocol="postgres", error=err)

    clear_hit = match_postgres_cleartext_only(ssl_reply, auth_reply)
    blob_hit = match_postgres_auth_c_blob(fail_reply)

    return [
        Indicator(
            id="postgres.cleartext",
            title="Postgres offers only cleartext password after SSL reject",
            category="static_signature",
            triggered=bool(clear_hit),
            skipped=not ssl_reply and not auth_reply,
            skip_reason=""
            if ssl_reply or auth_reply
            else (closed_reason(err) if err else "no reply"),
            protocol="postgres",
            detail=clear_hit or f"ssl={ssl_reply[:20]!r} auth={auth_reply[:40]!r}",
            evidence=(ssl_reply + auth_reply)[:200].hex(),
        ),
        Indicator(
            id="postgres.auth_blob",
            title="Postgres FATAL auth fail freezes auth.c:326",
            category="state_nonpersist",
            triggered=bool(blob_hit),
            skipped=not fail_reply and bool(err) and len(replies) < 3,
            skip_reason=closed_reason(err) if not fail_reply and err else "",
            protocol="postgres",
            detail=blob_hit or "auth fail blob is not the frozen auth.c:326 template",
            evidence=fail_reply[:240].hex() if fail_reply else "",
        ),
    ]
