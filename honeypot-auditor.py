#!/usr/bin/env python3
"""Run honeypot-auditor from a git checkout (no pip install required)."""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir():
    sys.path.insert(0, str(_SRC))

try:
    from honeypot_auditor.cli import main  # noqa: E402
except ModuleNotFoundError as exc:
    print(
        f"Missing dependency {exc.name!r}. Install once:\n"
        "  pip install -r requirements.txt\n"
        "Or: pip install rich paramiko requests\n"
        'Or from this repo: pip install -e ".[full]"',
        file=sys.stderr,
    )
    raise SystemExit(1) from exc

if __name__ == "__main__":
    raise SystemExit(main())
