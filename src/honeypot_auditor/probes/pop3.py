"""POP3 fingerprint engine.

Strategies: repeated arbitrary authentication · authorization/transaction state
separation · greeting and unknown-command conformance.  The probe never reads,
deletes, or otherwise modifies mail.
"""

from __future__ import annotations

from contextlib import closing

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason
from honeypot_auditor.probes.common import is_safe_mode, random_creds, skip_suite
from honeypot_auditor.proxy_transport import create_connection
from honeypot_auditor.settings import settings

_POP3_SKIP = (
    ("pop3.arbitrary_auth", "POP3 accepts two random credential pairs", "arbitrary_auth"),
    (
        "pop3.preauth_state",
        "POP3 accepts transaction commands before authentication",
        "state_nonpersist",
    ),
    ("pop3.greeting", "POP3 greeting violates response framing", "static_signature"),
    (
        "pop3.unknown_command",
        "POP3 accepts an unrecognized command",
        "static_signature",
    ),
)

_MAX_RESPONSE_BYTES = 512
_RECV_CHUNK = 256


class _LineReader:
    """Buffered CRLF reader — larger recv chunks with leftover carry across commands."""

    def __init__(self, sock) -> None:
        self._sock = sock
        self._buf = bytearray()

    def readline(self) -> str:
        while b"\r\n" not in self._buf and len(self._buf) < _MAX_RESPONSE_BYTES:
            need = min(_RECV_CHUNK, _MAX_RESPONSE_BYTES - len(self._buf))
            if need <= 0:
                break
            chunk = self._sock.recv(need)
            if not chunk:
                break
            self._buf.extend(chunk)
        nl = self._buf.find(b"\r\n")
        if nl == -1:
            line = bytes(self._buf[:_MAX_RESPONSE_BYTES])
            self._buf.clear()
            return line.decode("utf-8", "replace").rstrip("\r\n")
        line = bytes(self._buf[:nl])
        del self._buf[: nl + 2]
        return line.decode("utf-8", "replace")


def _read_line(sock) -> str:
    """Read one bounded POP3 response line (single-shot; no leftover reuse)."""
    return _LineReader(sock).readline()


def _send_command(reader: _LineReader, sock, command: str) -> str:
    sock.sendall(command.encode("ascii") + b"\r\n")
    return reader.readline()


def _is_positive(response: str) -> bool:
    return response.startswith("+OK")


def _single_command(host: str, port: int, command: str) -> tuple[str, str, str]:
    """Open a fresh authorization-state session and issue one command."""
    try:
        with closing(create_connection(host, port, settings.timeout_seconds)) as sock:
            reader = _LineReader(sock)
            greeting = reader.readline()
            if not _is_positive(greeting):
                return greeting, "", "server did not issue a positive POP3 greeting"
            return greeting, _send_command(reader, sock, command), ""
    except OSError as exc:
        return "", "", closed_reason(str(exc))


def _read_greeting(host: str, port: int) -> tuple[str, str]:
    try:
        with closing(create_connection(host, port, settings.timeout_seconds)) as sock:
            return _LineReader(sock).readline(), ""
    except OSError as exc:
        return "", closed_reason(str(exc))


def _try_login(host: str, port: int, username: str, password: str) -> tuple[bool, str, str]:
    """Try one synthetic account without accessing the resulting maildrop."""
    try:
        with closing(create_connection(host, port, settings.timeout_seconds)) as sock:
            reader = _LineReader(sock)
            greeting = reader.readline()
            if not _is_positive(greeting):
                return False, f"greeting={greeting!r}", ""
            user_reply = _send_command(reader, sock, f"USER {username}")
            credential_reply = ""
            if _is_positive(user_reply):
                credential_reply = _send_command(reader, sock, f"PASS {password}")
            accepted = _is_positive(credential_reply)
            if accepted:
                _send_command(reader, sock, "QUIT")
            return accepted, f"USER={user_reply!r}; PASS={credential_reply!r}", ""
    except OSError as exc:
        return False, "", closed_reason(str(exc))


def _greeting_indicator(greeting: str) -> Indicator:
    valid = _is_positive(greeting)
    return Indicator(
        id="pop3.greeting",
        title="POP3 greeting violates response framing",
        category="static_signature",
        triggered=not valid,
        protocol="pop3",
        detail=(
            "positive +OK greeting received"
            if valid
            else f"expected uppercase +OK greeting; received {greeting!r}"
        ),
        evidence=greeting[:_MAX_RESPONSE_BYTES],
        remediation="Emit a standards-conformant, service-specific POP3 greeting",
    )


def _preauth_state_triggered(state_replies: dict[str, str]) -> bool:
    """STAT is the decisive TRANSACTION-state tell; NOOP alone does not trigger.

    RFC 1939 lists both under TRANSACTION, but some stacks answer NOOP loosely
    in AUTHORIZATION. Require STAT +OK so odd servers are less likely to FP.
    """
    return _is_positive(state_replies.get("STAT", ""))


def probe_pop3(host: str, port: int) -> list[Indicator]:
    greeting, greeting_error = _read_greeting(host, port)
    if not greeting:
        reason = greeting_error or "no POP3 greeting"
        return skip_suite(_POP3_SKIP, reason, protocol="pop3", error=greeting_error)

    greeting_ind = _greeting_indicator(greeting)
    if greeting_ind.triggered:
        reason = "POP3 response checks skipped after malformed greeting"
        return [
            skipped_indicator(*_POP3_SKIP[0], reason, protocol="pop3"),
            skipped_indicator(*_POP3_SKIP[1], reason, protocol="pop3"),
            greeting_ind,
            skipped_indicator(*_POP3_SKIP[3], reason, protocol="pop3"),
        ]
    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        return [
            skipped_indicator(*_POP3_SKIP[0], reason, protocol="pop3"),
            skipped_indicator(*_POP3_SKIP[1], reason, protocol="pop3"),
            greeting_ind,
            skipped_indicator(*_POP3_SKIP[3], reason, protocol="pop3"),
        ]

    state_replies: dict[str, str] = {}
    state_errors: list[str] = []
    for command in ("STAT", "NOOP"):
        _, reply, error = _single_command(host, port, command)
        if reply:
            state_replies[command] = reply
        elif error:
            state_errors.append(f"{command}: {error}")
    state_hits = [name for name, reply in state_replies.items() if _is_positive(reply)]
    state_triggered = _preauth_state_triggered(state_replies)
    state_skipped = not state_replies

    _, unknown_reply, unknown_error = _single_command(host, port, "HPAU")
    unknown_skipped = not unknown_reply
    unknown_hit = _is_positive(unknown_reply)

    attempts = [random_creds(), random_creds()]
    accepted_users: list[str] = []
    auth_evidence: list[str] = []
    auth_errors: list[str] = []
    for username, password in attempts:
        accepted, transcript, error = _try_login(host, port, username, password)
        if accepted:
            accepted_users.append(username)
        if transcript:
            auth_evidence.append(f"{username}: {transcript}")
        if error:
            auth_errors.append(f"{username}: {error}")
    auth_hit = len(accepted_users) == len(attempts)
    auth_skipped = not auth_evidence and bool(auth_errors)

    if state_triggered:
        state_detail = f"authorization-state bypass: STAT returned +OK ({', '.join(state_hits)})"
    elif state_hits:
        state_detail = (
            f"NOOP returned +OK before auth but STAT did not "
            f"(not scored alone): {', '.join(state_hits)}"
        )
    else:
        state_detail = "STAT and NOOP were rejected before authentication"

    return [
        Indicator(
            id="pop3.arbitrary_auth",
            title="POP3 accepts two random credential pairs",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason="; ".join(auth_errors) if auth_skipped else "",
            error="; ".join(auth_errors),
            protocol="pop3",
            detail=(
                "two independent random USER/PASS pairs entered the transaction state"
                if auth_hit
                else "random USER/PASS pairs were not both accepted"
            ),
            evidence=",".join(accepted_users) if auth_hit else "; ".join(auth_evidence),
            remediation="Reject synthetic accounts before granting maildrop access",
        ),
        Indicator(
            id="pop3.preauth_state",
            title="POP3 accepts transaction commands before authentication",
            category="state_nonpersist",
            triggered=state_triggered,
            skipped=state_skipped,
            skip_reason="; ".join(state_errors) if state_skipped else "",
            error="; ".join(state_errors),
            protocol="pop3",
            detail=state_detail,
            evidence="; ".join(f"{name}={reply!r}" for name, reply in state_replies.items()),
            remediation="Enforce AUTHORIZATION and TRANSACTION state boundaries",
        ),
        greeting_ind,
        Indicator(
            id="pop3.unknown_command",
            title="POP3 accepts an unrecognized command",
            category="static_signature",
            triggered=unknown_hit,
            skipped=unknown_skipped,
            skip_reason=unknown_error if unknown_skipped else "",
            error=unknown_error,
            protocol="pop3",
            detail=(
                "unrecognized HPAU command returned +OK"
                if unknown_hit
                else "unrecognized HPAU command returned a negative response"
            ),
            evidence=unknown_reply,
            remediation="Return uppercase -ERR for unrecognized commands",
        ),
    ]


__all__ = ["probe_pop3"]
