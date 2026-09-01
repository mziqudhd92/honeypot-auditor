"""Tests for plan gap fills: clock drift, FSM fuzz, SSH continuity, jitter, SNI."""

from __future__ import annotations

from email.utils import formatdate
from unittest.mock import MagicMock, patch

from honeypot_auditor.cli import _apply_cli_settings, build_parser
from honeypot_auditor.probes.deep.fsm import (
    probe_http_fsm,
    probe_ssh_fsm,
    probe_ssh_state_continuity,
)
from honeypot_auditor.probes.deep.stack import probe_tls_wildcard_sni
from honeypot_auditor.probes.deep.temporal import probe_clock_drift, probe_latency_under_load
from honeypot_auditor.settings import settings
from honeypot_auditor.transport import _apply_jitter


def test_clock_drift_frozen_date():
    frozen = formatdate(timeval=1_700_000_000, usegmt=True)
    with (
        patch(
            "honeypot_auditor.probes.deep.temporal._sample_http_dates",
            return_value=[frozen, frozen, frozen],
        ),
        patch("honeypot_auditor.probes.deep.temporal.time.time", return_value=1_800_000_000.0),
    ):
        inds = probe_clock_drift("127.0.0.1", 80)
    assert inds[0].id == "deep.clock_drift"
    assert inds[0].triggered
    assert inds[0].requires_corroboration


def test_http_fsm_invalid_chunked_200():
    pipe = b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
    chunk = b"HTTP/1.1 200 OK\r\n\r\n"
    with patch(
        "honeypot_auditor.probes.deep.fsm.tcp_transact",
        side_effect=[(pipe, ""), (chunk, "")],
    ):
        with patch("honeypot_auditor.probes.deep.fsm.optional_import", return_value=None):
            inds = probe_http_fsm("127.0.0.1", 80)
    assert inds[0].id == "deep.http_fsm"
    assert inds[0].triggered
    assert "chunked" in inds[0].detail.lower() or "pipelined" in inds[0].detail.lower()


def test_ssh_fsm_flags_non_ssh_preface():
    banner = b"SSH-2.0-OpenSSH\r\n" + b"\x00" * 80 + b"diffie-hellman-group14-sha1"
    with patch(
        "honeypot_auditor.probes.deep.fsm.tcp_transact",
        side_effect=[(banner, ""), (banner, "")],
    ):
        fsm = probe_ssh_fsm("127.0.0.1", 22)
    assert fsm[0].id == "deep.ssh_fsm"
    assert fsm[0].triggered


def test_ssh_continuity_identical_handshake():
    banner = b"SSH-2.0-OpenSSH\r\n" + b"\x00" * 80 + b"diffie-hellman-group14-sha1"
    with (
        patch(
            "honeypot_auditor.probes.deep.fsm.tcp_transact",
            side_effect=[(banner, ""), (banner, "")],
        ),
        patch("time.monotonic", side_effect=[0.0, 0.005, 0.005, 0.009]),
    ):
        cont = probe_ssh_state_continuity("127.0.0.1", 22)
    assert cont[0].id == "fsm.stateless_trap_behavior"
    assert cont[0].protocol == "ssh"
    assert cont[0].triggered


def test_latency_under_load_uniform_trap():
    # Fast identical RTTs: baseline then concurrent workers
    rtts = [0.01] * 20

    def fake_rtt(*_a, **_k):
        return rtts.pop(0) if rtts else 0.01

    with (
        patch("honeypot_auditor.probes.deep.temporal._service_rtt", side_effect=fake_rtt),
        patch("honeypot_auditor.probes.deep.temporal.time.sleep"),
    ):
        inds = probe_latency_under_load("127.0.0.1", 22, workers=4)
    assert inds[0].id == "deep.latency_under_load"
    assert inds[0].triggered
    assert inds[0].requires_corroboration


def test_latency_under_load_stretches_like_real():
    calls = {"n": 0}

    def fake_rtt(*_a, **_k):
        calls["n"] += 1
        # baseline ~10ms; under "load" (later calls) stretch to ~40ms with variance
        if calls["n"] <= 3:
            return 0.010
        return 0.035 + (calls["n"] % 3) * 0.008

    with (
        patch("honeypot_auditor.probes.deep.temporal._service_rtt", side_effect=fake_rtt),
        patch("honeypot_auditor.probes.deep.temporal.time.sleep"),
    ):
        inds = probe_latency_under_load("127.0.0.1", 22, workers=4)
    assert inds[0].id == "deep.latency_under_load"
    assert not inds[0].triggered


def test_latency_under_load_safe_mode():
    settings.safe_mode = True
    try:
        inds = probe_latency_under_load("127.0.0.1", 22)
        assert inds[0].skipped
    finally:
        settings.safe_mode = False
    args = build_parser().parse_args(["--target", "127.0.0.1", "--jitter", "0.25"])
    _apply_cli_settings(args)
    assert settings.jitter_fraction == 0.25
    with patch("honeypot_auditor.transport.random.uniform", return_value=0.1) as uni:
        with patch("honeypot_auditor.transport.time.sleep") as sleep:
            settings.jitter_ms_range = None
            settings.timeout_seconds = 4.0
            _apply_jitter()
            uni.assert_called()
            sleep.assert_called_once_with(0.1)
    settings.jitter_fraction = 0.0


def test_tls_wildcard_sni_200():
    tls = MagicMock()
    tls.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
    ctx = MagicMock()
    ctx.wrap_socket.return_value = tls
    with (
        patch("ssl.create_default_context", return_value=ctx),
        patch(
            "honeypot_auditor.proxy_transport.create_connection",
            return_value=MagicMock(),
        ),
    ):
        inds = probe_tls_wildcard_sni("127.0.0.1", 443)
    assert inds[0].id == "tls.wildcard_sni"
    assert inds[0].triggered
    assert inds[0].tell_tier == "edge"
