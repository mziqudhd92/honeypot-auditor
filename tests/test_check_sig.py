"""check-sig CLI tests."""

from __future__ import annotations

from pathlib import Path

from honeypot_auditor.cli import run_check_sig

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "signatures"


def test_check_sig_valid_core_pack():
    core = Path(__file__).resolve().parents[1] / "src/honeypot_auditor/signatures/core"
    paths = [str(p) for p in core.glob("*.json")]
    assert run_check_sig(paths) == 0


def test_check_sig_fixture_valid():
    assert run_check_sig([str(FIXTURES / "valid_minimal.json")]) == 0


def test_check_sig_fixture_rejects_banned_keys():
    assert run_check_sig([str(FIXTURES / "invalid_banned.yaml")]) == 1


def test_check_sig_missing_file():
    assert run_check_sig(["/nonexistent/sig.json"]) == 1
