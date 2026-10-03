"""SMTP probe tests with mocks."""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

import honeypot_auditor.probes.smtp as smtp


@patch.object(smtp, "optional_import")
def test_smtp_banner_probe(mock_import):
    mock_import.return_value = None
    inds = smtp.probe_smtp("127.0.0.1", 25)
    assert any(i.protocol == "smtp" for i in inds)
    assert all(i.skipped for i in inds)
    assert {i.id for i in inds} == {
        "smtp.open_relay",
        "smtp.arbitrary_auth",
        "smtp.identity",
        "smtp.extensions",
        "smtp.starttls_lie",
        "smtp.envelope",
        "smtp.rset_envelope",
    }


@patch.object(smtp, "optional_import")
def test_smtp_any_password_auth_and_placeholder_identity(mock_import):
    lib = MagicMock()
    session = MagicMock()
    session.connect.return_value = (220, b"127.0.0.1 ESMTP")
    session.ehlo.return_value = (250, b"localhost\nAUTH PLAIN LOGIN")

    def docmd(cmd, arg=""):
        if cmd == "AUTH":
            return (235, b"2.7.0 Authentication successful")
        if cmd == "VRFY":
            return (252, b"Cannot VRFY")
        if cmd == "EXPN":
            return (502, b"not implemented")
        if cmd == "ETRN":
            return (500, b"no")
        if cmd == "STARTTLS":
            return (502, b"not available")
        return (250, b"ok")

    session.docmd.side_effect = docmd
    session.mail.return_value = (250, b"ok")
    session.rcpt.return_value = (550, b"relay denied")
    lib.SMTP.return_value = session
    mock_import.return_value = lib

    inds = smtp.probe_smtp("127.0.0.1", 25)
    by_id = {i.id: i for i in inds}
    assert by_id["smtp.arbitrary_auth"].triggered
    assert "AUTH PLAIN" in by_id["smtp.arbitrary_auth"].detail
    assert by_id["smtp.identity"].triggered
    assert "loopback" in by_id["smtp.identity"].detail.lower()
    assert not by_id["smtp.open_relay"].triggered
    assert not by_id["smtp.envelope"].triggered
    assert not by_id["smtp.extensions"].triggered


@patch.object(smtp, "optional_import")
def test_smtp_mail_accepted_then_rcpt_claims_no_sender(mock_import):
    lib = MagicMock()
    session = MagicMock()
    session.connect.return_value = (220, b"127.0.0.1 ESMTP")
    session.ehlo.return_value = (250, b"localhost")

    def docmd(cmd, arg=""):
        if cmd == "AUTH":
            return (235, b"ok")
        if cmd == "VRFY":
            return (252, b"Cannot VRFY")
        if cmd == "EXPN":
            return (502, b"not implemented")
        if cmd == "ETRN":
            return (500, b"no")
        if cmd == "STARTTLS":
            return (502, b"not available")
        return (250, b"ok")

    session.docmd.side_effect = docmd
    session.mail.return_value = (250, b"2.1.0 OK")
    session.rcpt.return_value = (503, b"Must have sender before recipient")
    lib.SMTP.return_value = session
    mock_import.return_value = lib

    inds = smtp.probe_smtp("127.0.0.1", 25)
    by_id = {i.id: i for i in inds}
    assert by_id["smtp.envelope"].triggered
    assert "envelope not stored" in by_id["smtp.envelope"].detail
    assert not by_id["smtp.open_relay"].triggered
    assert by_id["smtp.arbitrary_auth"].triggered
    assert by_id["smtp.identity"].triggered
    assert not by_id["smtp.extensions"].triggered


@patch.object(smtp, "optional_import")
def test_smtp_extension_monotone(mock_import):
    lib = MagicMock()
    session = MagicMock()
    session.connect.return_value = (220, b"mail ESMTP")
    session.ehlo.return_value = (250, b"mail.example.com")
    session.docmd.return_value = (250, b"ok")
    session.login.side_effect = OSError("535 auth failed")
    session.mail.return_value = (250, b"ok")
    session.rcpt.return_value = (550, b"relay denied")
    lib.SMTP.return_value = session
    mock_import.return_value = lib
    inds = smtp.probe_smtp("127.0.0.1", 25)
    by_id = {i.id: i for i in inds}
    assert by_id["smtp.extensions"].triggered
    assert "250" in by_id["smtp.extensions"].detail


@patch.object(smtp, "optional_import")
def test_smtp_rset_envelope_canned_state(mock_import):
    """MAIL 250 → RSET 250 → RCPT still 250: the transaction state is canned."""
    lib = MagicMock()
    session = MagicMock()
    session.connect.return_value = (220, b"mail ESMTP")
    session.ehlo.return_value = (250, b"mail.example.com")
    session.docmd.return_value = (250, b"ok")  # AUTH, VRFY, EXPN, ETRN, STARTTLS, RSET
    session.login.side_effect = OSError("535 auth failed")
    session.mail.return_value = (250, b"ok")
    session.rcpt.side_effect = [(250, b"ok"), (250, b"ok")]
    lib.SMTP.return_value = session
    mock_import.return_value = lib
    inds = smtp.probe_smtp("127.0.0.1", 25)
    by_id = {i.id: i for i in inds}
    assert by_id["smtp.rset_envelope"].triggered
    assert "RSET" in by_id["smtp.rset_envelope"].detail


@patch.object(smtp, "optional_import")
def test_smtp_rset_honored_is_clean(mock_import):
    """RSET 250 then RCPT 503 need-MAIL is correct MTA behavior — not a tell."""
    lib = MagicMock()
    session = MagicMock()
    session.connect.return_value = (220, b"mail ESMTP")
    session.ehlo.return_value = (250, b"mail.example.com")
    session.docmd.return_value = (250, b"ok")
    session.login.side_effect = OSError("535 auth failed")
    session.mail.return_value = (250, b"ok")
    session.rcpt.side_effect = [(550, b"relay denied"), (503, b"5.5.1 Error: need MAIL command")]
    lib.SMTP.return_value = session
    mock_import.return_value = lib
    inds = smtp.probe_smtp("127.0.0.1", 25)
    by_id = {i.id: i for i in inds}
    assert not by_id["smtp.rset_envelope"].triggered
    assert not by_id["smtp.envelope"].triggered


@patch.object(smtp, "_tls_wrap")
@patch.object(smtp, "optional_import")
def test_smtp_starttls_advertised_but_handshake_fails(mock_import, mock_wrap):
    """STARTTLS advertised + 220 + broken TLS handshake = capability lie."""
    mock_wrap.side_effect = ssl.SSLError("tlsv1 alert internal error")
    lib = MagicMock()
    session = MagicMock()
    session.connect.return_value = (220, b"mail ESMTP")
    session.ehlo.return_value = (250, b"mail.example.com\nPIPELINING\nSTARTTLS\nSIZE 10240000")

    def docmd(cmd, arg=""):
        if cmd == "AUTH":
            return (535, b"authentication failed")
        if cmd == "VRFY":
            return (252, b"Cannot VRFY")
        if cmd == "EXPN":
            return (502, b"not implemented")
        if cmd == "ETRN":
            return (500, b"no")
        if cmd == "STARTTLS":
            return (220, b"2.0.0 Ready to start TLS")
        return (250, b"ok")

    session.docmd.side_effect = docmd
    session.login.side_effect = OSError("535 auth failed")
    session.mail.return_value = (250, b"ok")
    session.rcpt.return_value = (550, b"relay denied")
    lib.SMTP.return_value = session
    mock_import.return_value = lib
    inds = smtp.probe_smtp("127.0.0.1", 25)
    by_id = {i.id: i for i in inds}
    assert by_id["smtp.starttls_lie"].triggered
    assert "handshake failed" in by_id["smtp.starttls_lie"].detail


@patch.object(smtp, "_tls_wrap")
@patch.object(smtp, "optional_import")
def test_smtp_starttls_handshake_completes_is_clean(mock_import, mock_wrap):
    """STARTTLS 220 + successful TLS wrap is a real service — no tell."""
    mock_wrap.return_value = MagicMock()
    lib = MagicMock()
    session = MagicMock()
    session.connect.return_value = (220, b"mail ESMTP")
    session.ehlo.return_value = (250, b"mail.example.com\nSTARTTLS")

    def docmd(cmd, arg=""):
        if cmd == "AUTH":
            return (535, b"authentication failed")
        if cmd == "STARTTLS":
            return (220, b"2.0.0 Ready to start TLS")
        return (250, b"ok")

    session.docmd.side_effect = docmd
    session.login.side_effect = OSError("535 auth failed")
    session.mail.return_value = (250, b"ok")
    session.rcpt.return_value = (550, b"relay denied")
    lib.SMTP.return_value = session
    mock_import.return_value = lib
    inds = smtp.probe_smtp("127.0.0.1", 25)
    by_id = {i.id: i for i in inds}
    assert not by_id["smtp.starttls_lie"].triggered
