"""Core probe tests with mocks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import honeypot_auditor.probes.core as core


def test_ssh_skipped_without_paramiko():
    with patch.object(core, "optional_import", return_value=None):
        inds = core.probe_ssh("127.0.0.1", 22)
    assert len(inds) == 3
    assert all(i.skipped for i in inds)


@patch.object(
    core,
    "_ssh_exec",
    side_effect=[
        "Linux myhost 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:08 UTC 2009 i686 GNU/Linux",
        "Intel(R) Core(TM)2 Duo CPU     T7300  @ 2.00GHz",
    ],
)
@patch.object(core, "optional_import")
def test_ssh_arbitrary_auth_and_banner(mock_import, mock_exec):
    paramiko = MagicMock()
    mock_import.return_value = paramiko
    client = MagicMock()
    paramiko.SSHClient.return_value = client
    paramiko.AutoAddPolicy.return_value = MagicMock()
    transport = MagicMock()
    transport.remote_version = "SSH-2.0-OpenSSH_5.1p1 Debian-5"
    client.get_transport.return_value = transport

    inds = core.probe_ssh("127.0.0.1", 22)
    by_id = {i.id: i for i in inds}
    assert by_id["ssh.arbitrary_auth"].triggered
    assert by_id["ssh.banner"].triggered
    assert by_id["ssh.uname"].triggered


@patch.object(core, "optional_import")
def test_ssh_connection_error(mock_import):
    paramiko = MagicMock()
    mock_import.return_value = paramiko
    client = MagicMock()
    paramiko.SSHClient.return_value = client
    paramiko.AutoAddPolicy.return_value = MagicMock()
    client.connect.side_effect = OSError("Connection refused")
    client.get_transport.return_value = None

    inds = core.probe_ssh("127.0.0.1", 22)
    assert all(i.skipped for i in inds)


@patch.object(core, "_telnet_login_and_probe", return_value=(False, "", "auth failed"))
@patch.object(core, "tcp_transact", return_value=(b"Welcome telnet\r\n", ""))
def test_telnet_auth_rejected(mock_tcp, mock_login):
    inds = core.probe_telnet("127.0.0.1", 23)
    auth = next(i for i in inds if i.id == "telnet.arbitrary_auth")
    assert not auth.triggered


@patch.object(core, "_telnet_login_and_probe", return_value=(True, "Linux myhost 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:08 UTC 2009 i686 GNU/Linux", ""))
@patch.object(core, "tcp_transact", return_value=(b"Welcome telnet\r\n", ""))
def test_telnet_auth_accepted(mock_tcp, mock_login):
    inds = core.probe_telnet("127.0.0.1", 23)
    auth = next(i for i in inds if i.id == "telnet.arbitrary_auth")
    assert auth.triggered


def test_smb_skipped_without_impacket():
    with patch.dict("sys.modules", {"impacket": None, "impacket.smbconnection": None}):
        inds = core.probe_smb("127.0.0.1", 445)
    assert len(inds) == 1
    assert inds[0].skipped


def test_smb_emulator_native_os():
    mock_conn = MagicMock()
    mock_smb_cls = MagicMock(return_value=mock_conn)
    mock_conn.getDialect.return_value = "SMB 1"
    mock_conn.getServerOS.return_value = "Windows 5.1"
    mock_conn.listShares.return_value = [{"shi1_netname": b"PUBLIC"}]

    fake_smb = MagicMock()
    fake_smb.SMBConnection = mock_smb_cls
    fake_pkg = MagicMock()
    fake_pkg.smbconnection = fake_smb

    with patch.dict("sys.modules", {"impacket": fake_pkg, "impacket.smbconnection": fake_smb}):
        inds = core.probe_smb("127.0.0.1", 445)

    assert inds[0].triggered


def test_ftp_banner_diskstation():
    mock_ftplib = MagicMock()
    ftp = MagicMock()
    ftp.getwelcome.return_value = "220 DiskStation FTP server ready."
    ftp.storbinary.side_effect = OSError("connection refused")
    mock_ftplib.FTP.return_value = ftp

    with patch.object(core, "optional_import", return_value=mock_ftplib):
        inds = core.probe_ftp("127.0.0.1", 8021)

    banner = next(i for i in inds if i.id == "ftp.banner")
    assert banner.triggered
    assert "DiskStation" in banner.detail


def test_ftp_reconnect_failure_still_returns_banner():
    mock_ftplib = MagicMock()
    ftp_upload = MagicMock()
    ftp_upload.getwelcome.return_value = "220 DiskStation FTP server ready."
    ftp_verify = MagicMock()
    ftp_verify.login.side_effect = OSError("connection refused")

    mock_ftplib.FTP.side_effect = [ftp_upload, ftp_verify]

    with patch.object(core, "optional_import", return_value=mock_ftplib):
        inds = core.probe_ftp("127.0.0.1", 8021)

    assert len(inds) == 2
    persist = next(i for i in inds if i.id == "ftp.persist")
    banner = next(i for i in inds if i.id == "ftp.banner")
    assert persist.skipped
    assert banner.triggered
