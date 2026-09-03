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
        ScriptedSocket("+OK mail ready", "-ERR authenticate first"),  # STAT
        ScriptedSocket("+OK mail ready", "-ERR authenticate first"),  # NOOP
        ScriptedSocket("+OK mail ready", "-ERR unknown capability command"),  # CAPA
        ScriptedSocket("+OK mail ready", "-ERR unknown command"),  # HPAU
        ScriptedSocket("+OK mail ready", "+OK user", "-ERR invalid login"),
        ScriptedSocket("+OK mail ready", "-ERR no such user"),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert not any(ind.triggered for ind in inds)
    assert by_id["pop3.greeting"].evidence == "+OK mail ready"
    assert not by_id["pop3.preauth_state"].skipped
    assert not by_id["pop3.auth_failed_blanket"].triggered
    assert not by_id["pop3.stock_banner"].triggered


def test_pop3_repeated_any_password_and_state_bypass_trigger():
    sessions = [
        ScriptedSocket("+OK ready", "+OK bye"),
        ScriptedSocket("+OK ready", "+OK 0 0"),  # STAT
        ScriptedSocket("+OK ready", "+OK"),  # NOOP
        ScriptedSocket("+OK ready", "+OK Capability list follows"),  # CAPA
        ScriptedSocket("+OK ready", "+OK sure"),  # HPAU
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


def test_pop3_qeeqbox_blanket_and_stock_banner():
    """qeeqbox/Twisted POP3: stock Exchange lure + identical Authentication failed."""
    err = "-ERR Authentication failed"
    greeting = "+OK Microsoft Exchange POP3 service is ready"
    sessions = [
        ScriptedSocket(greeting),
        ScriptedSocket(greeting, err),  # STAT
        ScriptedSocket(greeting, err),  # NOOP
        ScriptedSocket(greeting, err),  # CAPA
        ScriptedSocket(greeting, err),  # HPAU
        ScriptedSocket(greeting, "+OK USER Ok", err),
        ScriptedSocket(greeting, "+OK USER Ok", err),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["pop3.auth_failed_blanket"].triggered
    assert "CAPA" in by_id["pop3.auth_failed_blanket"].detail
    assert by_id["pop3.stock_banner"].triggered
    assert not by_id["pop3.preauth_state"].triggered
    assert not by_id["pop3.arbitrary_auth"].triggered
    assert not by_id["pop3.unknown_command"].triggered


def test_pop3_capa_auth_failed_with_stat_is_enough_for_blanket():
    err = "-ERR Authentication failed"
    sessions = [
        ScriptedSocket("+OK ready"),
        ScriptedSocket("+OK ready", err),  # STAT
        ScriptedSocket("+OK ready", "-ERR authenticate first"),  # NOOP different
        ScriptedSocket("+OK ready", err),  # CAPA same as STAT
        ScriptedSocket("+OK ready", "-ERR unknown command"),  # HPAU different
        ScriptedSocket("+OK ready", "-ERR no"),
        ScriptedSocket("+OK ready", "-ERR no"),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["pop3.auth_failed_blanket"].triggered
    assert "CAPA" in by_id["pop3.auth_failed_blanket"].detail
    assert "STAT" in by_id["pop3.auth_failed_blanket"].detail


def test_pop3_malformed_greeting_is_static_tell():
    inds = _run_with_sessions(ScriptedSocket("pop server ready"))
    assert len(inds) == 6
    greeting = next(ind for ind in inds if ind.id == "pop3.greeting")
    assert greeting.triggered


def test_pop3_safe_mode_is_greeting_only():
    old_safe = settings.safe_mode
    settings.safe_mode = True
    try:
        inds = _run_with_sessions(
            ScriptedSocket("+OK Microsoft Exchange POP3 service is ready", "+OK bye")
        )
    finally:
        settings.safe_mode = old_safe
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["pop3.greeting"].skipped
    assert by_id["pop3.stock_banner"].triggered
    assert by_id["pop3.arbitrary_auth"].skipped
    assert by_id["pop3.preauth_state"].skipped
    assert by_id["pop3.unknown_command"].skipped
    assert by_id["pop3.auth_failed_blanket"].skipped


def test_pop3_noop_alone_does_not_trigger_preauth_state():
    """NOOP +OK without STAT +OK is recorded but not scored (fewer FPs)."""
    sessions = [
        ScriptedSocket("+OK ready", "+OK bye"),
        ScriptedSocket("+OK ready", "-ERR auth required"),  # STAT
        ScriptedSocket("+OK ready", "+OK"),  # NOOP only
        ScriptedSocket("+OK ready", "-ERR CAPA not supported"),  # CAPA
        ScriptedSocket("+OK ready", "-ERR unknown command"),
        ScriptedSocket("+OK ready", "-ERR no"),
        ScriptedSocket("+OK ready", "-ERR no"),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["pop3.preauth_state"].triggered
    assert "NOOP" in by_id["pop3.preauth_state"].detail or "CAPA" in by_id[
        "pop3.preauth_state"
    ].detail
    assert not by_id["pop3.auth_failed_blanket"].triggered


def test_pop3_buffered_reader_handles_chunked_crlf():
    sock = ScriptedSocket("+OK ready")
    reader = pop3._LineReader(sock)
    assert reader.readline() == "+OK ready"
    assert reader.readline() == ""


def test_pop3_connection_error_skips_suite():
    with patch.object(pop3, "create_connection", side_effect=OSError("refused")):
        inds = pop3.probe_pop3("127.0.0.1", 110)
    assert len(inds) == 6
    assert all(ind.skipped for ind in inds)
