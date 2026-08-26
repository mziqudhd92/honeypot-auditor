"""Deep probe module tests."""

from __future__ import annotations

from unittest.mock import patch

from honeypot_auditor.probes.deep import run_deep_probes
from honeypot_auditor.probes.deep.cotenancy import probe_cotenancy


@patch("honeypot_auditor.probes.deep.cotenancy._has_service_banner", return_value=True)
@patch("honeypot_auditor.probes.deep.cotenancy._port_open", return_value=True)
def test_cotenancy_threshold(mock_open, mock_banner):
    ports = {"ssh": 22, "telnet": 23, "ftp": 21, "http": 80, "smb": 445}
    inds = probe_cotenancy("127.0.0.1", ports, corroboration=False)
    assert inds[0].id == "deep.cotenancy"
    assert "responsive IT lures" in inds[0].detail


@patch("honeypot_auditor.probes.deep.probe_egress_silence", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_latency_distribution", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_cotenancy", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_smtp_fsm", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_ftp_fsm", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_http_fsm", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_tcp_stack", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_hassh", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_os_coherence", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_auth_curve", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_telnet_shell_semantics", return_value=[])
@patch("honeypot_auditor.probes.deep.probe_shell_semantics", return_value=[])
def test_run_deep_probes_orchestrates(*_mocks):
    out = run_deep_probes("127.0.0.1", {"ssh": 22, "telnet": 23, "http": 80})
    assert out == []
