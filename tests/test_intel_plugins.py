"""Explicit opt-in passive-intelligence plugin tests."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from honeypot_auditor.cli import _parse_intel_keys, _probe_jobs, build_parser
from honeypot_auditor.models import Indicator
from honeypot_auditor.plugins import intel
from honeypot_auditor.settings import settings


def _finding() -> list[Indicator]:
    return [
        Indicator(
            id="honeypot_tag",
            title="Provider reports a honeypot tag",
            category="shodan",
            triggered=True,
        )
    ]


def test_named_provider_is_loaded_without_importing_unrelated_entry_points():
    wanted = MagicMock()
    wanted.name = "example"
    wanted.load.return_value = lambda ip, key: _finding()
    unrelated = MagicMock()
    unrelated.name = "unrelated"

    with (
        patch.object(intel, "_registry", {}),
        patch.object(intel, "_entry_points", return_value=[unrelated, wanted]),
    ):
        rows = intel.run_intel_provider("example", "203.0.113.10", "secret")

    assert rows[0].id == "intel.example.honeypot_tag"
    assert rows[0].protocol == "intel:example"
    wanted.load.assert_called_once()
    unrelated.load.assert_not_called()


def test_provider_failure_redacts_its_key():
    def failing_provider(ip, key):
        raise RuntimeError(f"request rejected for key={key}")

    with patch.object(intel, "_registry", {"example": failing_provider}):
        rows = intel.run_intel_provider("example", "203.0.113.10", "very-secret-key")

    assert rows[0].skipped
    assert "very-secret-key" not in rows[0].detail
    assert "[REDACTED]" in rows[0].detail


def test_provider_contract_rejects_scoring_category_escalation():
    def invalid_provider(ip, key):
        return [Indicator(id="bad", title="bad", category="arbitrary_auth", triggered=True)]

    with patch.object(intel, "_registry", {"example": invalid_provider}):
        rows = intel.run_intel_provider("example", "203.0.113.10")
    assert rows[0].skipped
    assert "must use" in rows[0].detail


def test_provider_name_and_key_validation():
    assert intel.validate_intel_provider_name("Demo-Feed") == "demo-feed"
    assert _parse_intel_keys(["demo-feed=abc", "other=xyz"]) == {
        "demo-feed": "abc",
        "other": "xyz",
    }
    with pytest.raises(ValueError):
        intel.validate_intel_provider_name("../plugin")
    with pytest.raises(ValueError):
        _parse_intel_keys(["missing-separator"])


def test_cli_provider_is_explicit_opt_in():
    args = build_parser().parse_args(["--target", "127.0.0.1"])
    assert args.intel_provider == []
    opted_in = build_parser().parse_args(["--target", "127.0.0.1", "--intel-provider", "example"])
    assert opted_in.intel_provider == ["example"]


def test_probe_jobs_runs_selected_provider_once():
    args = build_parser().parse_args(
        [
            "--target",
            "203.0.113.10",
            "--intel-provider",
            "example",
            "--intel-key",
            "example=secret",
        ]
    )
    old_osint = settings.osint_only
    settings.osint_only = True
    try:
        with (
            patch("honeypot_auditor.cli.shodan_lookup", return_value=[]),
            patch("honeypot_auditor.cli.run_intel_provider", return_value=_finding()) as run,
        ):
            jobs = _probe_jobs("203.0.113.10", {}, args, include_shodan=True)
    finally:
        settings.osint_only = old_osint
    assert [name for name, _ in jobs] == ["shodan", "intel:example"]
    run.assert_called_once_with("example", "203.0.113.10", "secret")
    emitted = [ind.id for _, job in jobs for ind in job()]
    assert emitted.count("honeypot_tag") == 1


def test_invalid_intel_key_is_reported_as_cli_input_error():
    args = build_parser().parse_args(["--target", "127.0.0.1", "--intel-key", "missing-separator"])
    from honeypot_auditor.cli import run_audit

    assert asyncio.run(run_audit(args)) == 2
