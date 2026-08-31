"""FTP probe tests with mocks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import honeypot_auditor.probes.ftp as ftp


def test_ftp_banner_diskstation():
    mock_ftplib = MagicMock()
    session = MagicMock()
    session.getwelcome.return_value = "220 DiskStation FTP server ready."
    session.storbinary.side_effect = OSError("connection refused")
    mock_ftplib.FTP.return_value = session

    with patch.object(ftp, "optional_import", return_value=mock_ftplib):
        inds = ftp.probe_ftp("127.0.0.1", 8021)

    banner = next(i for i in inds if i.id == "ftp.banner")
    assert banner.triggered
    assert "DiskStation" in banner.detail


def test_ftp_reconnect_failure_still_returns_banner():
    mock_ftplib = MagicMock()
    ftp_upload = MagicMock()
    ftp_upload.getwelcome.return_value = "220 DiskStation FTP server ready."

    def sendcmd(cmd: str) -> str:
        key = cmd.split()[0]
        if key == "NLST" or key == "MLSD":
            raise OSError("502 Command not implemented")
        return {
            "PASV": "227 Entering Passive Mode (172,18,0,2,182,77).",
            "SYST": "215 UNIX Type: L8",
            "TYPE": "200 Type set to I",
        }.get(key, "200 OK")

    ftp_upload.sendcmd.side_effect = sendcmd
    ftp_upload.storbinary.side_effect = TimeoutError("timed out")
    ftp_verify = MagicMock()
    ftp_verify.login.side_effect = OSError("connection refused")

    mock_ftplib.FTP.side_effect = [ftp_upload, ftp_verify]

    with patch.object(ftp, "optional_import", return_value=mock_ftplib):
        inds = ftp.probe_ftp("127.0.0.1", 8021)

    assert len(inds) == 6
    persist = next(i for i in inds if i.id == "ftp.persist")
    banner = next(i for i in inds if i.id == "ftp.banner")
    lure = next(i for i in inds if i.id == "ftp.auth_lure")
    auth = next(i for i in inds if i.id == "ftp.arbitrary_auth")
    bounce = next(i for i in inds if i.id == "ftp.bounce")
    desert = next(i for i in inds if i.id == "ftp.desert")
    assert persist.triggered
    assert banner.triggered
    assert not lure.triggered
    assert not auth.triggered
    assert bounce.triggered or not bounce.skipped
    assert not desert.triggered


def test_ftp_command_desert_pre_auth():
    mock_ftplib = MagicMock()
    session = MagicMock()
    session.getwelcome.return_value = "220 Microsoft FTP Service"

    def sendcmd(cmd: str) -> str:
        key = cmd.split()[0]
        if key in {"FEAT", "PWD", "PASV", "NOOP"}:
            raise OSError("500 Unknown Command.")
        if cmd.startswith("USER"):
            return "331 User OK. Password required"
        if cmd.startswith("PASS"):
            raise OSError("530 User cannot log in.")
        if key == "SYST":
            return "215 Windows_NT"
        return "200 OK"

    session.sendcmd.side_effect = sendcmd
    session.login.side_effect = OSError("530 User cannot log in.")
    mock_ftplib.FTP.return_value = session

    with patch.object(ftp, "optional_import", return_value=mock_ftplib):
        inds = ftp.probe_ftp("127.0.0.1", 21)

    by_id = {i.id: i for i in inds}
    assert by_id["ftp.desert"].triggered
    assert "500 Unknown Command" in by_id["ftp.desert"].detail
    assert by_id["ftp.banner"].triggered
    assert by_id["ftp.auth_lure"].triggered
    assert not by_id["ftp.arbitrary_auth"].triggered


def test_ftp_login_fail_still_scores_stale_banner_and_canned_reject():
    mock_ftplib = MagicMock()
    session = MagicMock()
    session.getwelcome.return_value = "220 ProFTPD 1.2.10 Server (Debian) [::ffff:127.0.0.1]"

    def sendcmd(cmd: str) -> str:
        if cmd.startswith("USER"):
            return "331 Guest login ok, send your complete e-mail address as password."
        if cmd.startswith("PASS"):
            raise OSError("530 Sorry, Authentication failed.")
        return "200 OK"

    session.sendcmd.side_effect = sendcmd
    session.login.side_effect = OSError("530 Sorry, Authentication failed.")
    mock_ftplib.FTP.return_value = session

    with patch.object(ftp, "optional_import", return_value=mock_ftplib):
        inds = ftp.probe_ftp("127.0.0.1", 21)

    by_id = {i.id: i for i in inds}
    assert by_id["ftp.persist"].skipped
    assert by_id["ftp.banner"].triggered
    assert "stale FTP banner" in by_id["ftp.banner"].evidence or "stock default 220" in by_id["ftp.banner"].evidence
    assert by_id["ftp.auth_lure"].triggered
    assert "guest" in by_id["ftp.auth_lure"].detail.lower()
    assert not by_id["ftp.arbitrary_auth"].triggered


def test_ftp_stock_test_account_pasv_mismatch_and_broken_quit():
    mock_ftplib = MagicMock()
    state = {"user": ""}

    def sendcmd(cmd: str) -> str:
        if cmd.startswith("USER"):
            state["user"] = cmd.split(maxsplit=1)[1]
            return f"331 Password required for {state['user']}."
        if cmd == "PASS" or cmd.startswith("PASS "):
            pw = cmd[5:] if cmd.startswith("PASS ") else ""
            if state["user"] == "test" and pw == "":
                return "230 User logged in, proceed"
            raise OSError("530 Sorry, Authentication failed.")
        if cmd.startswith("PASV"):
            return "227 Entering Passive Mode (172,31,91,21,181,45)."
        if cmd.startswith("SYST"):
            return "215 UNIX Type: L8"
        if cmd.startswith("PORT"):
            return "200 PORT command successful"
        if cmd.startswith("FEAT"):
            return "211 End"
        raise OSError("550 Requested action not taken: internal server error")

    session = MagicMock()
    session.getwelcome.return_value = "220 ProFTPD 1.2.10"
    session.sendcmd.side_effect = sendcmd
    session.storbinary.side_effect = OSError("Passive mode address mismatch")
    session.quit.side_effect = OSError("550 Requested action not taken: internal server error")
    mock_ftplib.FTP.return_value = session

    with patch.object(ftp, "optional_import", return_value=mock_ftplib):
        inds = ftp.probe_ftp("52.90.78.48", 21)

    by_id = {i.id: i for i in inds}
    assert by_id["ftp.arbitrary_auth"].triggered
    assert "test" in by_id["ftp.arbitrary_auth"].detail
    assert "empty password" in by_id["ftp.arbitrary_auth"].detail
    assert by_id["ftp.persist"].triggered
    assert "PASV address mismatch" in (by_id["ftp.persist"].detail + by_id["ftp.persist"].evidence)
    assert by_id["ftp.banner"].triggered
    assert by_id["ftp.bounce"].triggered
    assert not by_id["ftp.desert"].triggered


