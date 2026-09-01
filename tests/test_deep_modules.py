"""Unit tests for deep behavior/fsm/coherence/temporal/stack modules."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from honeypot_auditor.probes.deep.behavior import probe_shell_semantics
from honeypot_auditor.probes.deep.coherence import probe_os_coherence
from honeypot_auditor.probes.deep.fsm import probe_ftp_fsm, probe_http_fsm, probe_smtp_fsm
from honeypot_auditor.probes.deep.stack import probe_hassh, probe_tcp_stack, probe_tls_ja4s
from honeypot_auditor.probes.deep.temporal import probe_egress_silence, probe_latency_distribution


@patch("honeypot_auditor.probes.deep.behavior.ssh_exec")
@patch("honeypot_auditor.probes.deep.behavior.try_ssh_auth")
def test_shell_semantics_instant_sleep(mock_auth, mock_exec):
    client = MagicMock()
    mock_auth.return_value = (client, "")
    mock_exec.side_effect = [
        ("2993\n", "", 0.01),
        ("1 2 3\n", "", 0.01),
        ("12345\n", "", 0.01),
        ("999\n", "", 0.01),
        ("", "", 0.05),
        ("", "", 0.01),
        ("deadbeef\n", "", 0.01),
    ]

    inds = probe_shell_semantics("127.0.0.1", 22)
    assert inds[0].id == "deep.shell_semantics"
    assert inds[0].triggered


@patch("honeypot_auditor.probes.deep.behavior.try_ssh_auth", return_value=(None, "Connection refused"))
def test_shell_semantics_skipped_on_auth_fail(mock_auth):
    inds = probe_shell_semantics("127.0.0.1", 22)
    assert inds[0].skipped


@patch("honeypot_auditor.probes.deep.coherence.ssh_exec")
@patch("honeypot_auditor.probes.deep.coherence.try_ssh_auth")
def test_os_coherence_kernel_mismatch(mock_auth, mock_exec):
    client = MagicMock()
    mock_auth.return_value = (client, "")

    def exec_side(cmd, *_a, **_k):
        mapping = {
            "uname -a": ("Linux host 5.15.0-1-amd64 #1 SMP Debian 3.2", "", 0.01),
            "cat /proc/version 2>/dev/null": ("Linux version 3.2.0 old", "", 0.01),
            "cat /etc/os-release 2>/dev/null | head -5": ("NAME=Alpine", "", 0.01),
            "grep -E 'model name|hypervisor|vendor_id' /proc/cpuinfo 2>/dev/null | head -6": (
                "model name : Intel",
                "",
                0.01,
            ),
            "readlink /proc/self/exe 2>/dev/null": ("/bin/bash", "", 0.01),
        }
        return mapping.get(cmd, ("", "", 0.0))

    mock_exec.side_effect = lambda client, cmd, timeout=None: exec_side(cmd)

    inds = probe_os_coherence("127.0.0.1", 22)
    assert inds[0].id == "deep.os_coherence"
    assert inds[0].triggered


@patch("honeypot_auditor.probes.deep.fsm.tcp_transact")
def test_http_fsm_duplicate_static_200(mock_tcp):
    body = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    mock_tcp.return_value = (body, "")
    inds = probe_http_fsm("127.0.0.1", 8080)
    assert inds[0].triggered


@patch("honeypot_auditor.probes.deep.fsm.tcp_transact", return_value=(b"", "Connection refused"))
def test_http_fsm_skipped_closed(mock_tcp):
    inds = probe_http_fsm("127.0.0.1", 8080)
    assert inds[0].skipped


@patch("honeypot_auditor.probes.deep.fsm.optional_import")
def test_ftp_fsm_pasv_non_routable(mock_import):
    mock_ftplib = MagicMock()
    mock_import.return_value = mock_ftplib
    ftp = MagicMock()
    mock_ftplib.FTP.return_value = ftp
    ftp.sendcmd.side_effect = [
        "211 end",
        "350 Restarting at 0",
        "227 Entering Passive Mode (127,0,0,1,31,144)",
    ]
    ftp.storbinary.side_effect = OSError("connection refused")

    inds = probe_ftp_fsm("127.0.0.1", 21)
    assert inds[0].triggered
    assert "127." in inds[0].detail or "PASV" in inds[0].detail


@patch("honeypot_auditor.probes.deep.fsm.optional_import", return_value=None)
def test_smtp_fsm_skipped_without_smtplib(mock_import):
    inds = probe_smtp_fsm("127.0.0.1", 25)
    assert inds[0].skipped


@patch("honeypot_auditor.probes.deep.fsm.optional_import")
def test_smtp_fsm_open_relay_tell(mock_import):
    smtplib = MagicMock()
    mock_import.return_value = smtplib

    class SMTPException(Exception):
        pass

    smtplib.SMTPException = SMTPException
    smtp = MagicMock()
    smtplib.SMTP.return_value = smtp
    smtp.ehlo.return_value = (250, b"ok")

    def docmd(cmd, arg=""):
        if cmd == "VRFY":
            return (252, b"ok")
        if cmd == "RSET":
            return (250, b"reset")
        if cmd.startswith("RCPT"):
            return (250, b"accepted")
        return (250, b"ok")

    smtp.docmd.side_effect = docmd

    inds = probe_smtp_fsm("127.0.0.1", 25)
    assert inds[0].triggered
    assert isinstance(inds[0].evidence, str)
    assert "ok" in inds[0].evidence


@patch("honeypot_auditor.probes.deep.temporal.time.sleep")
@patch("honeypot_auditor.probes.deep.temporal.time.monotonic")
@patch("honeypot_auditor.probes.deep.temporal.tcp_transact")
def test_latency_uniform_fast_responses(mock_tcp, mock_mono, mock_sleep):
    mock_tcp.return_value = (b"banner\r\n", "")
    tick = iter([0.0, 0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009, 0.010, 0.011, 0.012])
    mock_mono.side_effect = lambda: next(tick)

    inds = probe_latency_distribution("127.0.0.1", 22, samples=6)
    assert inds[0].id == "deep.latency"
    assert inds[0].triggered


@patch("honeypot_auditor.probes.deep.temporal.tcp_transact", return_value=(b"", "refused"))
def test_latency_insufficient_samples(mock_tcp):
    inds = probe_latency_distribution("127.0.0.1", 22, samples=6)
    assert inds[0].skipped


@patch("honeypot_auditor.sshutil.ssh_exec")
@patch("honeypot_auditor.sshutil.try_ssh_auth")
def test_egress_unreachable(mock_auth, mock_exec):
    client = MagicMock()
    mock_auth.return_value = (client, "")
    mock_exec.return_value = ("network is unreachable", "", 0.1)

    inds = probe_egress_silence("127.0.0.1", 22)
    assert inds[0].triggered


@patch("honeypot_auditor.probes.deep.stack.capture_server_kexinit")
@patch("honeypot_auditor.probes.deep.stack.tcp_transact", return_value=(b"", "refused"))
def test_hassh_skipped_closed(mock_tcp, mock_capture):
    inds = probe_hassh("127.0.0.1", 22)
    assert inds[0].skipped


@patch("honeypot_auditor.probes.deep.stack.hassh_algo_mismatch", return_value=(True, "twisted"))
@patch("honeypot_auditor.probes.deep.stack.capture_server_kexinit")
@patch("honeypot_auditor.probes.deep.stack.tcp_transact")
def test_hassh_mismatch(mock_tcp, mock_capture, mock_mismatch):
    mock_tcp.return_value = (b"SSH-2.0-OpenSSH\r\n", "")
    kex = MagicMock()
    kex.kex = "diffie-hellman-group1-sha1"
    kex.hassh_server = "abc"
    mock_capture.return_value = ("SSH-2.0-OpenSSH", kex)

    inds = probe_hassh("127.0.0.1", 22)
    assert inds[0].triggered


@patch("honeypot_auditor.probes.deep.stack.socket.create_connection", side_effect=OSError("refused"))
def test_tcp_stack_skipped(mock_connect):
    inds = probe_tcp_stack("127.0.0.1", 22)
    assert inds[0].skipped


@patch("honeypot_auditor.probes.deep.stack.socket.create_connection")
def test_tcp_stack_scapy_missing(mock_connect):
    mock_connect.return_value.__enter__.return_value = MagicMock()
    with patch.dict("sys.modules", {"scapy": None, "scapy.all": None}):
        with patch.object(
            __import__("honeypot_auditor.settings", fromlist=["settings"]).settings.capabilities,
            "raw_sockets",
            False,
        ):
            inds = probe_tcp_stack("127.0.0.1", 22, claimed_os="windows")
    assert not inds[0].skipped
    assert any(i.id == "deep.tcp_synack_options" and i.skipped for i in inds)


@patch("honeypot_auditor.probes.deep.stack.socket.create_connection", side_effect=OSError("refused"))
def test_tls_skipped(mock_connect):
    inds = probe_tls_ja4s("127.0.0.1", 443)
    assert inds[0].skipped


@patch("honeypot_auditor.probes.deep.fsm.tcp_transact")
def test_telnet_fsm_blind_option(mock_tcp):
    from honeypot_auditor.probes.deep.fsm import probe_telnet_fsm

    mock_tcp.side_effect = [(b"\xff\xfb\x63Username: ", ""), (b"login: ", "")]
    inds = probe_telnet_fsm("127.0.0.1", 23)
    assert inds[0].triggered
    assert "option 99" in inds[0].detail
