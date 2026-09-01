"""check-sig CLI tests."""

from __future__ import annotations

from pathlib import Path

from honeypot_auditor.cli import run_check_sig


def test_check_sig_valid_core_pack():
    core = Path(__file__).resolve().parents[1] / "src/honeypot_auditor/signatures/core"
    paths = [str(p) for p in core.glob("*.json")]
    assert run_check_sig(paths) == 0


def test_check_sig_missing_file():
    assert run_check_sig(["/nonexistent/sig.json"]) == 1
