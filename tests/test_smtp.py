"""SMTP probe tests with mocks."""

from __future__ import annotations

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
        "smtp.envelope",
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
