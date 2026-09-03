"""Entry point smoke test."""

from __future__ import annotations

import subprocess
import sys

from honeypot_auditor import __version__


def test_module_version():
    proc = subprocess.run(
        [sys.executable, "-m", "honeypot_auditor", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert __version__ in proc.stdout
