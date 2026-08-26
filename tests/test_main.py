"""Entry point smoke test."""

from __future__ import annotations

import runpy


def test_main_module_runs_help():
    runpy.run_module("honeypot_auditor.__main__", run_name="__not_main__")
