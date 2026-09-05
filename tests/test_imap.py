"""IMAP probe tests with a scripted socket transport."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.imap as imap
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


class _RawSocket:
    """Wire bytes without automatic CRLF (for length-bound tests)."""

    def __init__(self, data: bytes) -> None:
        self._wire = bytearray(data)

    def recv(self, size: int) -> bytes:
        if not self._wire:
            return b""
        chunk = bytes(self._wire[:size])
        del self._wire[:size]
        return chunk


def _run_with_sessions(*sessions: ScriptedSocket, port: int = 143):
    with patch.object(imap, "create_connection", side_effect=sessions):
        with patch.object(imap, "create_tls_connection", side_effect=sessions):
            return imap.probe_imap("127.0.0.1", port)


def test_imap_response_line_is_bounded():
    oversized = b"x" * (imap._MAX_RESPONSE_BYTES + 200)
    assert len(imap._read_line(_RawSocket(oversized))) == imap._MAX_RESPONSE_BYTES


def test_imap_conformant_rejections_are_clean():
    sessions = [
        ScriptedSocket("* OK IMAP4rev1 ready"),
        ScriptedSocket("* OK ready", "* CAPABILITY IMAP4rev1 AUTH=PLAIN", "A001 OK done"),
        ScriptedSocket("* OK ready", "A001 NO authenticate first"),  # LIST
        ScriptedSocket("* OK ready", "A001 NO authenticate first"),  # SELECT
        ScriptedSocket("* OK ready", "A001 BAD unknown command"),  # XZPQ
        ScriptedSocket("* OK ready", "A001 NO login failed"),
        ScriptedSocket("* OK ready", "A001 NO no such user"),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert not any(ind.triggered for ind in inds)
    assert by_id["imap.greeting"].evidence == "* OK IMAP4rev1 ready"
    assert not by_id["imap.preauth_state"].skipped
    assert not by_id["imap.auth_failed_blanket"].triggered
    assert not by_id["imap.stock_banner"].triggered


def test_imap_repeated_login_and_state_bypass_trigger():
    login_sock_a = ScriptedSocket("* OK ready", "A001 OK LOGIN completed", "* BYE", "A002 OK")
    login_sock_b = ScriptedSocket("* OK ready", "A001 OK LOGIN completed", "* BYE", "A002 OK")
    sessions = [
        ScriptedSocket("* OK ready"),
        ScriptedSocket("* OK ready", "* CAPABILITY IMAP4rev1", "A001 OK done"),
        ScriptedSocket("* OK ready", '* LIST (\\Noselect) "/" ""', "A001 OK LIST completed"),
        ScriptedSocket("* OK ready", "* 0 EXISTS", "A001 OK [READ-WRITE] SELECT completed"),
        ScriptedSocket("* OK ready", "A001 OK sure"),  # XZPQ
        login_sock_a,
        login_sock_b,
    ]
    with patch.object(
        imap, "random_creds", side_effect=[("user_a", "pass_a"), ("user_b", "pass_b")]
    ):
        inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["imap.arbitrary_auth"].triggered
    assert by_id["imap.arbitrary_auth"].evidence == "user_a,user_b"
    assert "pass_a" not in str([ind.as_dict() for ind in inds])
    assert by_id["imap.preauth_state"].triggered
    assert by_id["imap.unknown_command"].triggered
    assert any(b"LOGOUT" in chunk for chunk in login_sock_a.sent)


def test_imap_exchange_blanket_and_stock_banner():
    """qeeqbox/OpenCanary-class IMAP: stock Exchange lure + identical Authentication failed."""
    err = "A001 NO Authentication failed"
    greeting = "* OK The Microsoft Exchange IMAP4 service is ready"
    sessions = [
        ScriptedSocket(greeting),
        ScriptedSocket(greeting, err),  # CAPABILITY
        ScriptedSocket(greeting, err),  # LIST
        ScriptedSocket(greeting, err),  # SELECT
        ScriptedSocket(greeting, err),  # XZPQ
        ScriptedSocket(greeting, err),
        ScriptedSocket(greeting, err),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["imap.auth_failed_blanket"].triggered
    assert "CAPABILITY" in by_id["imap.auth_failed_blanket"].detail
    assert by_id["imap.stock_banner"].triggered
    assert not by_id["imap.preauth_state"].triggered
    assert not by_id["imap.arbitrary_auth"].triggered
    assert not by_id["imap.unknown_command"].triggered


def test_imap_capability_auth_failed_with_list_is_enough_for_blanket():
    err = "A001 NO Authentication failed"
    sessions = [
        ScriptedSocket("* OK ready"),
        ScriptedSocket("* OK ready", err),  # CAPABILITY
        ScriptedSocket("* OK ready", err),  # LIST same
        ScriptedSocket("* OK ready", "A001 NO Please login"),  # SELECT different
        ScriptedSocket("* OK ready", "A001 BAD Command Error"),  # XZPQ different
        ScriptedSocket("* OK ready", "A001 NO no"),
        ScriptedSocket("* OK ready", "A001 NO no"),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["imap.auth_failed_blanket"].triggered
    assert "CAPABILITY" in by_id["imap.auth_failed_blanket"].detail
    assert "LIST" in by_id["imap.auth_failed_blanket"].detail


def test_imap_authenticate_first_without_capability_lure_is_not_blanket():
    """Legitimate state-boundary NO text must not score without CAPABILITY lure."""
    sessions = [
        ScriptedSocket("* OK ready"),
        ScriptedSocket("* OK ready", "* CAPABILITY IMAP4rev1", "A001 OK done"),
        ScriptedSocket("* OK ready", "A001 NO authenticate first"),
        ScriptedSocket("* OK ready", "A001 NO authenticate first"),
        ScriptedSocket("* OK ready", "A001 NO authenticate first"),  # XZPQ same text
        ScriptedSocket("* OK ready", "A001 NO no"),
        ScriptedSocket("* OK ready", "A001 NO no"),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["imap.auth_failed_blanket"].triggered


def test_imap_list_xzpq_auth_failed_without_capability_is_not_blanket():
    err = "A001 NO Authentication failed"
    sessions = [
        ScriptedSocket("* OK ready"),
        ScriptedSocket("* OK ready", "* CAPABILITY IMAP4rev1", "A001 OK done"),
        ScriptedSocket("* OK ready", err),
        ScriptedSocket("* OK ready", "A001 NO Please login"),
        ScriptedSocket("* OK ready", err),
        ScriptedSocket("* OK ready", "A001 NO no"),
        ScriptedSocket("* OK ready", "A001 NO no"),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["imap.auth_failed_blanket"].triggered


def test_imap_malformed_greeting_is_static_tell():
    inds = _run_with_sessions(ScriptedSocket("imap server ready"))
    assert len(inds) == 6
    greeting = next(ind for ind in inds if ind.id == "imap.greeting")
    assert greeting.triggered


def test_imap_bye_greeting_is_valid_and_skips_suite():
    inds = _run_with_sessions(ScriptedSocket("* BYE Service not available"))
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["imap.greeting"].triggered
    assert "BYE" in by_id["imap.greeting"].detail
    assert by_id["imap.arbitrary_auth"].skipped
    assert by_id["imap.preauth_state"].skipped
    assert by_id["imap.unknown_command"].skipped


def test_imap_preauth_greeting_does_not_score_select_bypass():
    """PREAUTH = already Authenticated; SELECT OK must not fire preauth_state."""
    sessions = [
        ScriptedSocket("* PREAUTH IMAP4rev1 server logged in as user"),
        ScriptedSocket(
            "* PREAUTH ready", "* CAPABILITY IMAP4rev1", "A001 OK done"
        ),
        ScriptedSocket(
            "* PREAUTH ready", '* LIST () "/" INBOX', "A001 OK LIST completed"
        ),
        ScriptedSocket("* PREAUTH ready", "A001 BAD Command Error"),  # XZPQ
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["imap.greeting"].triggered
    assert by_id["imap.arbitrary_auth"].skipped
    assert by_id["imap.preauth_state"].skipped
    assert "PREAUTH" in by_id["imap.preauth_state"].skip_reason
    assert not by_id["imap.unknown_command"].triggered
    assert not any(ind.triggered for ind in inds)


def test_imap_preauth_exchange_blanket_still_detects():
    err = "A001 NO Authentication failed"
    greeting = "* PREAUTH The Microsoft Exchange IMAP4 service is ready"
    sessions = [
        ScriptedSocket(greeting),
        ScriptedSocket(greeting, err),  # CAPABILITY
        ScriptedSocket(greeting, err),  # LIST
        ScriptedSocket(greeting, err),  # XZPQ
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["imap.arbitrary_auth"].skipped
    assert by_id["imap.preauth_state"].skipped
    assert by_id["imap.auth_failed_blanket"].triggered
    assert by_id["imap.stock_banner"].triggered


def test_imap_safe_mode_is_greeting_only():
    old_safe = settings.safe_mode
    settings.safe_mode = True
    try:
        inds = _run_with_sessions(
            ScriptedSocket("* OK The Microsoft Exchange IMAP4 service is ready")
        )
    finally:
        settings.safe_mode = old_safe
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["imap.greeting"].skipped
    assert by_id["imap.stock_banner"].triggered
    assert by_id["imap.arbitrary_auth"].skipped
    assert by_id["imap.preauth_state"].skipped
    assert by_id["imap.unknown_command"].skipped
    assert by_id["imap.auth_failed_blanket"].skipped


def test_imap_list_alone_does_not_trigger_preauth_state():
    """LIST OK without SELECT OK is recorded but not scored (fewer FPs)."""
    sessions = [
        ScriptedSocket("* OK ready"),
        ScriptedSocket("* OK ready", "* CAPABILITY IMAP4rev1", "A001 OK done"),
        ScriptedSocket("* OK ready", '* LIST () "/" INBOX', "A001 OK LIST completed"),
        ScriptedSocket("* OK ready", "A001 NO authenticate first"),  # SELECT
        ScriptedSocket("* OK ready", "A001 BAD unknown"),
        ScriptedSocket("* OK ready", "A001 NO no"),
        ScriptedSocket("* OK ready", "A001 NO no"),
    ]
    inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["imap.preauth_state"].triggered
    assert "LIST" in by_id["imap.preauth_state"].detail
    assert not by_id["imap.auth_failed_blanket"].triggered


def test_imap_port_993_uses_tls_connection():
    sessions = [
        ScriptedSocket("* OK IMAP4rev1 ready"),
        ScriptedSocket("* OK ready", "* CAPABILITY IMAP4rev1", "A001 OK done"),
        ScriptedSocket("* OK ready", "A001 NO authenticate first"),
        ScriptedSocket("* OK ready", "A001 NO authenticate first"),
        ScriptedSocket("* OK ready", "A001 BAD unknown"),
        ScriptedSocket("* OK ready", "A001 NO no"),
        ScriptedSocket("* OK ready", "A001 NO no"),
    ]
    with patch.object(imap, "create_tls_connection", side_effect=sessions) as tls:
        with patch.object(imap, "create_connection") as plain:
            inds = imap.probe_imap("127.0.0.1", 993)
    assert tls.call_count == 7
    plain.assert_not_called()
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["imap.greeting"].triggered
    assert not any(ind.triggered for ind in inds)


def test_imap_connection_error_skips_suite():
    with patch.object(imap, "create_connection", side_effect=OSError("refused")):
        inds = imap.probe_imap("127.0.0.1", 143)
    assert len(inds) == 6
    assert all(ind.skipped for ind in inds)


def test_imap_wrap_tls_helper_exists():
    from honeypot_auditor.proxy_transport import create_tls_connection, wrap_tls

    assert callable(wrap_tls)
    assert callable(create_tls_connection)
