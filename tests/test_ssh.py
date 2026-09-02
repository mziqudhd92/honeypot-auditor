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
    assert len(inds) == 8
    assert all(i.skipped for i in inds)
    assert {i.id for i in inds} == {
        "ssh.banner",
        "ssh.kex_facade",
        "ssh.password_only",
        "ssh.arbitrary_auth",
        "ssh.exec_denied",
        "ssh.uname",
        "ssh.whoami",
        "ssh.session_persist",
    }


def _handshake_ok(banner="SSH-2.0-OpenSSH_9.2p1 Debian"):
    return banner, None, banner.encode() + b"\r\n", ""


@patch.object(
    ssh,
    "probe_ssh_auth_methods",
    return_value=(["publickey", "password"], "SSH-2.0-OpenSSH_5.1p1 Debian-5", ""),
)
@patch.object(
    ssh, "_capture_ssh_handshake", return_value=_handshake_ok("SSH-2.0-OpenSSH_5.1p1 Debian-5")
)
@patch.object(ssh, "try_ssh_auth", return_value=(None, "auth failed"))
@patch.object(ssh, "_ssh_exec", side_effect=_ssh_exec_dispatch)
@patch.object(ssh, "optional_import")
def test_ssh_arbitrary_auth_and_banner(mock_import, mock_exec, mock_auth2, mock_hs, mock_methods):
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
    assert "ssh.kex_facade" in by_id


@patch.object(ssh, "probe_ssh_auth_methods", return_value=([], "", "Connection refused"))
@patch.object(ssh, "_capture_ssh_handshake", return_value=("", None, b"", "Connection refused"))
@patch.object(ssh, "optional_import")
def test_ssh_connection_error(mock_import, mock_hs, mock_methods):
    paramiko = MagicMock()
    mock_import.return_value = paramiko
    client = MagicMock()
    paramiko.SSHClient.return_value = client
    paramiko.AutoAddPolicy.return_value = MagicMock()
    client.connect.side_effect = OSError("Connection refused")
    client.get_transport.return_value = None

    inds = ssh.probe_ssh("127.0.0.1", 22)
    assert len(inds) == 8
    assert all(i.skipped for i in inds)


@patch.object(
    ssh, "probe_ssh_auth_methods", return_value=(["password"], "SSH-2.0-OpenSSH_8.9p1", "")
)
@patch.object(ssh, "_capture_ssh_handshake", return_value=_handshake_ok("SSH-2.0-OpenSSH_8.9p1"))
@patch.object(ssh, "try_ssh_auth", return_value=(None, "auth failed"))
@patch.object(ssh, "_ssh_exec", side_effect=_ssh_exec_dispatch)
@patch.object(ssh, "optional_import")
def test_ssh_password_only_auth_tell(mock_import, mock_exec, mock_auth2, mock_hs, mock_methods):
    paramiko = MagicMock()
    mock_import.return_value = paramiko
    client = MagicMock()
    paramiko.SSHClient.return_value = client
    paramiko.AutoAddPolicy.return_value = MagicMock()
    paramiko.AuthenticationException = type("AuthenticationException", (Exception,), {})
    client.connect.side_effect = paramiko.AuthenticationException("bad")
    client.get_transport.return_value = None

    inds = ssh.probe_ssh("127.0.0.1", 22)
    by_id = {i.id: i for i in inds}
    assert by_id["ssh.password_only"].triggered
    assert (
        "password-only" in by_id["ssh.password_only"].detail.lower()
        or "only password" in by_id["ssh.password_only"].detail.lower()
    )


@patch.object(
    ssh,
    "probe_ssh_auth_methods",
    return_value=(["publickey", "password"], "SSH-2.0-OpenSSH_9.2p1", ""),
)
@patch.object(ssh, "_capture_ssh_handshake", return_value=_handshake_ok())
@patch.object(ssh, "random_creds", side_effect=[("user_a15", "pw1"), ("user_a99", "pw2")])
@patch.object(ssh, "try_ssh_auth", return_value=(None, "auth failed"))
@patch.object(ssh, "_ssh_interactive", return_value=COWRIE_SHELL)
@patch.object(ssh, "_ssh_exec", return_value="(exec failed: Channel closed.)")
@patch.object(ssh, "optional_import")
def test_ssh_exec_denied_and_cowrie_hostname(
    mock_import, mock_exec, mock_shell, mock_auth2, mock_creds, mock_hs, mock_methods
):
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


@patch.object(
    ssh,
    "probe_ssh_auth_methods",
    return_value=(["publickey", "password"], "SSH-2.0-OpenSSH_9.2p1", ""),
)
@patch.object(ssh, "_capture_ssh_handshake", return_value=_handshake_ok())
@patch.object(ssh, "try_ssh_auth")
@patch.object(ssh, "_ssh_exec", side_effect=_ssh_exec_dispatch)
@patch.object(ssh, "optional_import")
def test_ssh_session_does_not_persist(mock_import, mock_exec, mock_auth2, mock_hs, mock_methods):
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


def test_cowrie_facade_kex_mismatch():
    from honeypot_auditor.hassh import SSHKexInit, hassh_algo_mismatch

    kex = SSHKexInit(
        kex="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha1,ext-info-s",
        host_key="ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519",
        enc_c2s="aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc",
        enc_s2c="aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc",
        mac_c2s="hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        mac_s2c="hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        comp_c2s="none,zlib@openssh.com",
        comp_s2c="none,zlib@openssh.com",
    )
    triggered, detail = hassh_algo_mismatch("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", kex)
    assert triggered
    assert "Twisted/Cowrie KEX facade" in detail
    assert "ssh-rsa" in detail


def test_find_kexinit_skips_banner_prefix():
    import struct

    from honeypot_auditor.hassh import capture_server_kexinit, find_kexinit_payload

    # Build a minimal valid KEXINIT-ish packet after a banner.
    lists = [
        b"curve25519-sha256",
        b"ssh-rsa",
        b"aes128-ctr",
        b"aes128-ctr",
        b"hmac-sha2-256",
        b"hmac-sha2-256",
        b"none",
        b"none",
    ]
    body = bytearray([20]) + b"\x00" * 16
    for item in lists:
        body += struct.pack(">I", len(item)) + item
    body += b"\x00"  # first_kex_packet_follows
    body += b"\x00\x00\x00\x00"  # reserved
    pad = 4
    payload = bytes(body) + (b"\x00" * pad)
    pkt = struct.pack(">I", len(payload) + 1) + bytes([pad]) + payload
    raw = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n" + pkt
    assert find_kexinit_payload(raw) is not None
    banner, kex = capture_server_kexinit(raw)
    assert "OpenSSH_8.9" in banner
    assert kex is not None
    assert kex.host_key.startswith("ssh-rsa")
