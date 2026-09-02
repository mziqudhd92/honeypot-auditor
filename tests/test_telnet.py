"""Telnet probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.telnet as telnet
from honeypot_auditor.settings import settings

KIPPO_UNAME = "Linux myhost 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:08 UTC 2009 i686 GNU/Linux"
COWRIE_SHELL = (
    "The programs included with the Debian GNU/Linux system are free software\r\n"
    "user_a15@svr04:~$ whoami\r\nuser_a15\r\n"
    "user_a15@svr04:~$ ls\r\ncowrie.txt\r\n"
    "user_a15@svr04:~$ echo $((7*9))\r\necho $((7*9))\r\n"
    "user_a15@svr04:~$ uname -a\r\nLinux svr04 6.1.0-21-amd64 #1 SMP Debian x86_64 GNU/Linux\r\n"
)


@patch.object(telnet, "_telnet_login_and_probe", return_value=(False, "", "auth failed"))
@patch.object(telnet, "tcp_transact", return_value=(b"Welcome telnet\r\n", ""))
def test_telnet_auth_rejected(mock_tcp, mock_login):
    inds = telnet.probe_telnet("127.0.0.1", 23)
    by_id = {i.id: i for i in inds}
    assert not by_id["telnet.arbitrary_auth"].triggered
    assert not by_id["telnet.banner"].triggered
    assert not by_id["telnet.auth_lure"].triggered
    assert by_id["telnet.uname"].skipped
    assert by_id["telnet.whoami"].skipped
    assert by_id["telnet.session_persist"].skipped


@patch.object(
    telnet,
    "_telnet_login_and_probe",
    side_effect=[(True, KIPPO_UNAME, ""), (False, "", "auth failed")],
)
@patch.object(telnet, "tcp_transact", return_value=(b"Welcome telnet\r\n", ""))
def test_telnet_single_login_not_arbitrary_auth(mock_tcp, mock_login):
    inds = telnet.probe_telnet("127.0.0.1", 23)
    by_id = {i.id: i for i in inds}
    assert not by_id["telnet.arbitrary_auth"].triggered
    assert "2nd random login not accepted" in by_id["telnet.arbitrary_auth"].detail
    assert by_id["telnet.uname"].triggered


@patch.object(
    telnet,
    "_telnet_login_and_probe",
    side_effect=[(True, KIPPO_UNAME, ""), (True, KIPPO_UNAME, "")],
)
@patch.object(telnet, "tcp_transact", return_value=(b"Welcome telnet\r\n", ""))
def test_telnet_auth_accepted(mock_tcp, mock_login):
    inds = telnet.probe_telnet("127.0.0.1", 23)
    by_id = {i.id: i for i in inds}
    assert by_id["telnet.arbitrary_auth"].triggered
    assert by_id["telnet.uname"].triggered
    assert by_id["telnet.session_persist"].triggered


@patch.object(telnet, "random_creds", side_effect=[("user_a15", "pw1"), ("user_a99", "pw2")])
@patch.object(
    telnet,
    "_telnet_login_and_probe",
    side_effect=[
        (True, COWRIE_SHELL, ""),
        (True, "user_a99@svr04:~$ cat /tmp/hpaudit_dead\r\ncat: No such file\r\n", ""),
    ],
)
@patch.object(telnet, "tcp_transact", return_value=(b"login: ", ""))
def test_telnet_cowrie_hostname(mock_tcp, mock_login, mock_creds):
    inds = telnet.probe_telnet("127.0.0.1", 23)
    by_id = {i.id: i for i in inds}
    assert by_id["telnet.uname"].triggered
    assert "svr04" in by_id["telnet.uname"].detail
    assert by_id["telnet.whoami"].triggered
    assert by_id["telnet.session_persist"].triggered
    assert by_id["telnet.arbitrary_auth"].triggered
    assert "2nd login user_a99" in by_id["telnet.arbitrary_auth"].detail


CISCO_IAC_BANNER = b"\xff\xfb\x03\xff\xfb\x00\r\nUser Access Verification\r\n\xff\xfc\x01Username: "
CISCO_REJECT = "User Access Verification\r\nUsername: Password: Wrong password.\r\nUsername: "


def test_strip_telnet_iac_keeps_printable_banner():
    text = telnet.strip_telnet_iac(CISCO_IAC_BANNER).decode()
    assert "User Access Verification" in text
    assert "Username:" in text
    assert "\xff" not in text


@patch.object(telnet, "_telnet_login_and_probe", return_value=(False, CISCO_REJECT, ""))
@patch.object(telnet, "tcp_transact", return_value=(CISCO_IAC_BANNER, ""))
def test_telnet_cisco_lure_without_any_password(mock_tcp, mock_login):
    inds = telnet.probe_telnet("127.0.0.1", 23)
    by_id = {i.id: i for i in inds}
    assert not by_id["telnet.arbitrary_auth"].triggered
    assert by_id["telnet.banner"].triggered
    assert "User Access Verification" in by_id["telnet.banner"].detail
    assert by_id["telnet.auth_lure"].triggered
    assert "Wrong password" in by_id["telnet.auth_lure"].detail
    assert by_id["telnet.uname"].skipped


IAC_COWRIE_PREAMBLE = b"\xff\xfd\x1flogin: "


@patch.object(telnet, "_telnet_login_and_probe", return_value=(False, "login: ", ""))
@patch.object(telnet, "tcp_transact", return_value=(IAC_COWRIE_PREAMBLE, ""))
def test_telnet_cowrie_preamble(mock_tcp, mock_login):
    inds = telnet.probe_telnet("127.0.0.1", 23)
    by_id = {i.id: i for i in inds}
    assert by_id["telnet.banner"].triggered
    assert by_id["telnet.iac_negotiate"].triggered
    assert "NAWS" in by_id["telnet.banner"].detail
    assert "login:" in by_id["telnet.banner"].detail.lower()


IAC_OPTION_SPRAY = bytes.fromhex("fffb03fffb00fffd00fffd1ffffd18fffd27fffd22") + b"\r\nUsername: "


@patch.object(
    telnet, "_telnet_login_and_probe", return_value=(False, "Password: Login incorrect\r\n", "")
)
@patch.object(telnet, "tcp_transact", return_value=(IAC_OPTION_SPRAY, ""))
def test_telnet_option_spray_then_username_prompt(mock_tcp, mock_login):
    inds = telnet.probe_telnet("127.0.0.1", 23)
    by_id = {i.id: i for i in inds}
    assert by_id["telnet.banner"].triggered
    assert "option spray" in by_id["telnet.banner"].detail.lower()
    assert not by_id["telnet.auth_lure"].triggered
    assert not by_id["telnet.iac_negotiate"].triggered


IAC_BLIND = bytes.fromhex("fffb03fffb63") + b"\r\nUsername: "


@patch.object(telnet, "_telnet_login_and_probe", return_value=(False, "", ""))
@patch.object(telnet, "tcp_transact", return_value=(IAC_BLIND, ""))
def test_telnet_blind_unknown_option(mock_tcp, mock_login):
    inds = telnet.probe_telnet("127.0.0.1", 23)
    by_id = {i.id: i for i in inds}
    assert by_id["telnet.iac_negotiate"].triggered
    mock_tcp.assert_called()
    assert mock_tcp.call_args[0][2] == telnet._IAC_PROBE


@patch.object(settings, "safe_mode", True)
@patch.object(telnet, "tcp_transact")
def test_telnet_safe_mode_accepts_bytes_iac(mock_tcp):
    mock_tcp.side_effect = [
        (b"login: ", ""),
        (IAC_BLIND, ""),
    ]
    inds = telnet.probe_telnet("127.0.0.1", 23)
    by_id = {i.id: i for i in inds}
    assert "telnet.banner" in by_id
    assert "telnet.iac_negotiate" in by_id
    assert by_id["telnet.iac_negotiate"].triggered
    assert not by_id["telnet.banner"].error
    assert by_id["telnet.arbitrary_auth"].skipped
