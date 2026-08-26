"""SSH helper tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from honeypot_auditor import sshutil


def test_random_creds_format():
    user, password = sshutil.random_creds()
    assert user.startswith("user_a")
    assert password.startswith("pass_z")


@patch.object(sshutil, "optional_import", return_value=None)
def test_try_ssh_auth_without_paramiko(mock_import):
    client, err = sshutil.try_ssh_auth("127.0.0.1", 22, "u", "p")
    assert client is None
    assert "paramiko" in err


@patch.object(sshutil, "optional_import")
def test_try_ssh_auth_success(mock_import):
    paramiko = MagicMock()
    mock_import.return_value = paramiko
    client = MagicMock()
    paramiko.SSHClient.return_value = client
    paramiko.AutoAddPolicy.return_value = MagicMock()

    got, err = sshutil.try_ssh_auth("127.0.0.1", 22, "u", "p")
    assert got is client
    assert err == ""


@patch.object(sshutil, "optional_import")
def test_try_ssh_auth_rejected(mock_import):
    paramiko = MagicMock()
    mock_import.return_value = paramiko
    client = MagicMock()
    paramiko.SSHClient.return_value = client
    paramiko.AutoAddPolicy.return_value = MagicMock()
    paramiko.AuthenticationException = type("AuthenticationException", (Exception,), {})
    client.connect.side_effect = paramiko.AuthenticationException("bad creds")

    got, err = sshutil.try_ssh_auth("127.0.0.1", 22, "u", "p")
    assert got is None
    assert "bad creds" in err


def test_ssh_exec_success():
    client = MagicMock()
    stdout = MagicMock()
    stdout.read.return_value = b"ok\n"
    stderr = MagicMock()
    stderr.read.return_value = b""
    client.exec_command.return_value = (None, stdout, stderr)

    out, err, elapsed = sshutil.ssh_exec(client, "echo ok")
    assert out == "ok"
    assert err == ""
    assert elapsed >= 0


def test_ssh_exec_error():
    client = MagicMock()
    client.exec_command.side_effect = OSError("channel closed")

    out, err, elapsed = sshutil.ssh_exec(client, "echo ok")
    assert out == ""
    assert "channel closed" in err


def test_ssh_banner():
    client = MagicMock()
    transport = MagicMock()
    transport.remote_version = "SSH-2.0-test"
    client.get_transport.return_value = transport
    assert sshutil.ssh_banner(client) == "SSH-2.0-test"
