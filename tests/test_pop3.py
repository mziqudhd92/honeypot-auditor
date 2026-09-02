"""POP3 probe tests with a scripted socket transport."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.pop3 as pop3
from honeypot_auditor.settings import settings


class ScriptedSocket:
    def __init__(self, *responses: str) -> None:
        self._wire = bytearray("".join(f"{line}\r\n" for line in responses).encode())
        self.sent: list[bytes] = []

    def recv(self, size: int) -> bytes:
        if not self._wire:
            return b""
        chunk = bytes(self._wire[:size])
        del self._wire[:size]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        return None


def _run_with_sessions(*sessions: ScriptedSocket):
    with patch.object(pop3, "create_connection", side_effect=sessions):
        return pop3.probe_pop3("127.0.0.1", 110)


def test_pop3_response_line_is_bounded():
    assert len(pop3._read_line(ScriptedSocket("x" * 600))) == pop3._MAX_RESPONSE_BYTES


def test_pop3_conformant_rejections_are_clean():
    sessions = [
        ScriptedSocket("+OK mail ready", "+OK bye"),
        ScriptedSocket("+OK mail ready", "-ERR authenticate first"),
        ScriptedSocket("+OK mail ready", "-ERR authenticate first"),
        ScriptedSocket("+OK mail ready", "-ERR unknown command"),
        ScriptedSocket("+OK mail ready", "+OK user", "-ERR invalid login"),
        ScriptedSocket("+OK mail ready", "-ERR no such user"),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert not any(ind.triggered for ind in inds)
    assert by_id["pop3.greeting"].evidence == "+OK mail ready"
    assert not by_id["pop3.preauth_state"].skipped


def test_pop3_repeated_any_password_and_state_bypass_trigger():
    sessions = [
        ScriptedSocket("+OK ready", "+OK bye"),
        ScriptedSocket("+OK ready", "+OK 0 0"),
        ScriptedSocket("+OK ready", "+OK"),
        ScriptedSocket("+OK ready", "+OK sure"),
        ScriptedSocket("+OK ready", "+OK user", "+OK maildrop", "+OK bye"),
        ScriptedSocket("+OK ready", "+OK user", "+OK maildrop", "+OK bye"),
    ]
    with patch.object(
        pop3, "random_creds", side_effect=[("user_a", "pass_a"), ("user_b", "pass_b")]
    ):
        inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["pop3.arbitrary_auth"].triggered
    assert by_id["pop3.arbitrary_auth"].evidence == "user_a,user_b"
    assert "pass_a" not in str([ind.as_dict() for ind in inds])
    assert by_id["pop3.preauth_state"].triggered
    assert by_id["pop3.unknown_command"].triggered


def test_pop3_malformed_greeting_is_static_tell():
    inds = _run_with_sessions(ScriptedSocket("pop server ready"))
    assert len(inds) == 4
    greeting = next(ind for ind in inds if ind.id == "pop3.greeting")
    assert greeting.triggered


def test_pop3_safe_mode_is_greeting_only():
    old_safe = settings.safe_mode
    settings.safe_mode = True
    try:
        inds = _run_with_sessions(ScriptedSocket("+OK ready", "+OK bye"))
    finally:
        settings.safe_mode = old_safe
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["pop3.greeting"].skipped
    assert by_id["pop3.arbitrary_auth"].skipped
    assert by_id["pop3.preauth_state"].skipped
    assert by_id["pop3.unknown_command"].skipped


def test_pop3_connection_error_skips_suite():
    with patch.object(pop3, "create_connection", side_effect=OSError("refused")):
        inds = pop3.probe_pop3("127.0.0.1", 110)
    assert len(inds) == 4
    assert all(ind.skipped for ind in inds)
