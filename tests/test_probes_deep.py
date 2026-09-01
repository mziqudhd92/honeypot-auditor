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


_DEEP_PATCHES = [
    "probe_state_continuity",
    "probe_clock_drift",
    "probe_tls_wildcard_sni",
    "probe_ssh_state_continuity",
    "probe_ssh_fsm",
    "probe_llm_hallucination",
    "probe_mtime_uniformity",
    "probe_shell_entropy",
    "probe_egress_silence",
    "probe_latency_distribution",
    "probe_latency_under_load",
    "probe_idle_accept",
    "probe_cotenancy",
    "probe_smtp_fsm",
    "probe_ftp_fsm",
    "probe_http_fsm",
    "probe_tcp_stack",
    "probe_banner_vs_stack",
    "probe_hassh",
    "probe_os_coherence",
    "probe_auth_curve",
    "probe_telnet_fsm",
    "probe_telnet_shell_semantics",
    "probe_shell_semantics",
]


def _patch_all_deep(fn):
    for name in _DEEP_PATCHES:
        fn = patch(f"honeypot_auditor.probes.deep.{name}", return_value=[])(fn)
    return fn


@_patch_all_deep
def test_run_deep_probes_orchestrates(*_mocks):
    out = run_deep_probes("127.0.0.1", {"ssh": 22, "telnet": 23, "http": 80})
    assert out == []


@_patch_all_deep
def test_run_deep_probes_skips_unlisted_protocols(*_mocks):
    # Loop applies patches first→last; innermost (first list item) is first mock arg
    by_name = dict(zip(_DEEP_PATCHES, _mocks, strict=True))
    run_deep_probes("127.0.0.1", {"ssh": 22})
    by_name["probe_shell_semantics"].assert_called()
    by_name["probe_telnet_shell_semantics"].assert_not_called()
    by_name["probe_http_fsm"].assert_not_called()
