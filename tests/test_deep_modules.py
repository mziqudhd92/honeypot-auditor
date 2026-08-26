"""Unit tests for deep behavior/fsm modules."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from honeypot_auditor.probes.deep.behavior import probe_shell_semantics
from honeypot_auditor.probes.deep.fsm import probe_http_fsm


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
    assert "sleep" in inds[0].detail.lower() or "2993" in inds[0].detail.lower()


@patch("honeypot_auditor.probes.deep.behavior.try_ssh_auth", return_value=(None, "Connection refused"))
def test_shell_semantics_skipped_on_auth_fail(mock_auth):
    inds = probe_shell_semantics("127.0.0.1", 22)
    assert inds[0].skipped


@patch("honeypot_auditor.probes.deep.fsm.tcp_transact")
def test_http_fsm_duplicate_static_200(mock_tcp):
    body = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    mock_tcp.return_value = (body, "")
    inds = probe_http_fsm("127.0.0.1", 8080)
    assert inds[0].triggered
    assert "200" in inds[0].detail


@patch("honeypot_auditor.probes.deep.fsm.tcp_transact", return_value=(b"", "Connection refused"))
def test_http_fsm_skipped_closed(mock_tcp):
    inds = probe_http_fsm("127.0.0.1", 8080)
    assert inds[0].skipped
