"""TDD: LLM honeypot extends — latency cadence + dual-hash consistency."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from honeypot_auditor.probes.deep.behavior import probe_llm_hallucination
from honeypot_auditor.settings import settings


def _enable_deep():
    prev = (settings.deep, settings.safe_mode)
    settings.deep = True
    settings.safe_mode = False
    return prev


def _restore(prev):
    settings.deep, settings.safe_mode = prev


def test_llm_latency_cadence_triggers_on_consistently_slow_trivial():
    prev = _enable_deep()
    client = MagicMock()

    def slow_exec(_client, cmd, timeout=None):
        # Trivial commands always take >1.5s (LLM cadence)
        if "sha256sum" in cmd or "md5sum" in cmd:
            return ("deadbeef" * 8 + "  /etc/hostname\n", "", 0.05)
        return ("ok\n", "", 1.8)

    try:
        with (
            patch("honeypot_auditor.probes.deep.behavior.try_ssh_auth", return_value=(client, "")),
            patch("honeypot_auditor.probes.deep.behavior.random_creds", return_value=("u", "p")),
            patch("honeypot_auditor.probes.deep.behavior.ssh_exec", side_effect=slow_exec),
        ):
            ind = probe_llm_hallucination("127.0.0.1", 22)[0]
    finally:
        _restore(prev)

    assert ind.id == "deep.llm_hallucination"
    assert ind.triggered is True
    assert ind.requires_corroboration is True
    assert "latency" in ind.detail.lower() or "slow" in ind.detail.lower()


def test_llm_dual_hash_drift_triggers():
    prev = _enable_deep()
    client = MagicMock()
    calls = {"n": 0}

    def hash_drift(_client, cmd, timeout=None):
        calls["n"] += 1
        if "sha256sum" in cmd or "md5sum" in cmd:
            # Different digests for the same path across calls
            digest = ("aaaa" if calls["n"] % 2 else "bbbb") * 16
            return (f"{digest}  /etc/hostname\n", "", 0.05)
        # Fast trivial commands
        if "no such" in cmd or "fake-flag" in cmd or "nonexistent" in cmd:
            return ("No such file or directory\n", "", 0.02)
        return ("ok\n", "", 0.02)

    try:
        with (
            patch("honeypot_auditor.probes.deep.behavior.try_ssh_auth", return_value=(client, "")),
            patch("honeypot_auditor.probes.deep.behavior.random_creds", return_value=("u", "p")),
            patch("honeypot_auditor.probes.deep.behavior.ssh_exec", side_effect=hash_drift),
        ):
            ind = probe_llm_hallucination("127.0.0.1", 22)[0]
    finally:
        _restore(prev)

    assert ind.triggered is True
    assert "hash" in ind.detail.lower() or "drift" in ind.detail.lower()


def test_llm_identical_hashes_clear_when_errors_standard():
    prev = _enable_deep()
    client = MagicMock()

    def stable(_client, cmd, timeout=None):
        if "sha256sum" in cmd or "md5sum" in cmd:
            return ("c" * 64 + "  /etc/hostname\n", "", 0.04)
        if "nonexistent" in cmd or "fake-flag" in cmd:
            return ("No such file or directory\n", "", 0.03)
        return ("ok\n", "", 0.03)

    try:
        with (
            patch("honeypot_auditor.probes.deep.behavior.try_ssh_auth", return_value=(client, "")),
            patch("honeypot_auditor.probes.deep.behavior.random_creds", return_value=("u", "p")),
            patch("honeypot_auditor.probes.deep.behavior.ssh_exec", side_effect=stable),
        ):
            ind = probe_llm_hallucination("127.0.0.1", 22)[0]
    finally:
        _restore(prev)

    assert ind.triggered is False
