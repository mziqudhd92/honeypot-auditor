"""SSH probe tests with mocks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import honeypot_auditor.probes.ssh as ssh

KIPPO_UNAME = "Linux myhost 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:08 UTC 2009 i686 GNU/Linux"
KIPPO_CPU = "Intel(R) Core(TM)2 Duo CPU     T7300  @ 2.00GHz"
COWRIE_SHELL = (
    "The programs included with the Debian GNU/Linux system are free software\r\n"
    "user_a15@svr04:~$ whoami\r\nuser_a15\r\n"
    "user_a15@svr04:~$ ls\r\ncowrie.txt\r\n"
    "user_a15@svr04:~$ echo $((7*9))\r\necho $((7*9))\r\n"
    "user_a15@svr04:~$ uname -a\r\nLinux svr04 6.1.0-21-amd64 #1 SMP Debian x86_64 GNU/Linux\r\n"
)


def _ssh_exec_dispatch(_client, cmd: str) -> str:
    if cmd == "uname -a":
        return KIPPO_UNAME
    if "cpuinfo" in cmd:
        return KIPPO_CPU
    if cmd == "whoami":
        return "root"
    if cmd in {"hostname", "cat /etc/hostname"}:
        return "myhost"
    if "7*9" in cmd:
        return "63"
    if cmd.startswith("echo ") and ">" in cmd:
        return ""
    if cmd.startswith("cat /tmp/hpaudit"):
        return "cat: No such file or directory"
    if cmd == "ls":
        return "bin\nboot\netc"
    if cmd == "id":
        return "uid=0(root) gid=0(root)"
    return ""


def test_ssh_skipped_without_paramiko():
    with patch.object(ssh, "optional_import", return_value=None):
        inds = ssh.probe_ssh("127.0.0.1", 22)
    assert len(inds) == 6
    assert all(i.skipped for i in inds)
    assert {i.id for i in inds} == {
        "ssh.banner",
        "ssh.arbitrary_auth",
        "ssh.exec_denied",
        "ssh.uname",
        "ssh.whoami",
        "ssh.session_persist",
    }


@patch.object(ssh, "try_ssh_auth", return_value=(None, "auth failed"))
@patch.object(ssh, "_ssh_exec", side_effect=_ssh_exec_dispatch)
@patch.object(ssh, "optional_import")
def test_ssh_arbitrary_auth_and_banner(mock_import, mock_exec, mock_auth2):
    paramiko = MagicMock()
    mock_import.return_value = paramiko
    client = MagicMock()
    paramiko.SSHClient.return_value = client
    paramiko.AutoAddPolicy.return_value = MagicMock()
    transport = MagicMock()
    transport.remote_version = "SSH-2.0-OpenSSH_5.1p1 Debian-5"
    client.get_transport.return_value = transport

    inds = ssh.probe_ssh("127.0.0.1", 22)
    by_id = {i.id: i for i in inds}
    assert not by_id["ssh.arbitrary_auth"].triggered
    assert "2nd random login not accepted" in by_id["ssh.arbitrary_auth"].detail
    assert by_id["ssh.banner"].triggered
    assert by_id["ssh.uname"].triggered
    assert not by_id["ssh.exec_denied"].triggered
    assert by_id["ssh.session_persist"].skipped


@patch.object(ssh, "optional_import")
def test_ssh_connection_error(mock_import):
    paramiko = MagicMock()
    mock_import.return_value = paramiko
    client = MagicMock()
    paramiko.SSHClient.return_value = client
    paramiko.AutoAddPolicy.return_value = MagicMock()
    client.connect.side_effect = OSError("Connection refused")
    client.get_transport.return_value = None

    inds = ssh.probe_ssh("127.0.0.1", 22)
    assert len(inds) == 6
    assert all(i.skipped for i in inds)


@patch.object(ssh, "random_creds", side_effect=[("user_a15", "pw1"), ("user_a99", "pw2")])
@patch.object(ssh, "try_ssh_auth", return_value=(None, "auth failed"))
@patch.object(ssh, "_ssh_interactive", return_value=COWRIE_SHELL)
@patch.object(ssh, "_ssh_exec", return_value="(exec failed: Channel closed.)")
@patch.object(ssh, "optional_import")
def test_ssh_exec_denied_and_cowrie_hostname(mock_import, mock_exec, mock_shell, mock_auth2, mock_creds):
    paramiko = MagicMock()
    mock_import.return_value = paramiko
    client = MagicMock()
    paramiko.SSHClient.return_value = client
    paramiko.AutoAddPolicy.return_value = MagicMock()
    transport = MagicMock()
    transport.remote_version = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
    client.get_transport.return_value = transport

    inds = ssh.probe_ssh("127.0.0.1", 22)
    by_id = {i.id: i for i in inds}
    assert not by_id["ssh.arbitrary_auth"].triggered
    assert by_id["ssh.exec_denied"].triggered
    assert by_id["ssh.uname"].triggered
    assert "svr04" in by_id["ssh.uname"].detail
    assert "honeyfs=cowrie.txt" in by_id["ssh.uname"].detail
    assert by_id["ssh.whoami"].triggered
    assert "user_a15" in by_id["ssh.whoami"].detail
    assert not by_id["ssh.banner"].triggered
    assert by_id["ssh.session_persist"].skipped


@patch.object(ssh, "try_ssh_auth")
@patch.object(ssh, "_ssh_exec", side_effect=_ssh_exec_dispatch)
@patch.object(ssh, "optional_import")
def test_ssh_session_does_not_persist(mock_import, mock_exec, mock_auth2):
    paramiko = MagicMock()
    mock_import.return_value = paramiko
    client = MagicMock()
    paramiko.SSHClient.return_value = client
    paramiko.AutoAddPolicy.return_value = MagicMock()
    transport = MagicMock()
    transport.remote_version = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
    client.get_transport.return_value = transport
    mock_auth2.return_value = (MagicMock(), "")

    inds = ssh.probe_ssh("127.0.0.1", 22)
    by_id = {i.id: i for i in inds}
    assert by_id["ssh.arbitrary_auth"].triggered
    persist = next(i for i in inds if i.id == "ssh.session_persist")
    assert persist.triggered
    assert "could not read" in persist.detail
