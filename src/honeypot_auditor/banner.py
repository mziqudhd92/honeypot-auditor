"""ANSI figlet header for the CLI."""

from __future__ import annotations

from contextlib import suppress

from rich.console import Console
from rich.text import Text

from honeypot_auditor import __version__

HEADER_TEXT = "H-AUDITOR"
TAGLINE = "authorized targets only · banner/state probes · no exploits · no SMTP DATA"
# Compact fonts first — keep the banner to a few lines in normal terminals.
FIGLET_FONTS = ("small", "standard", "slant", "digital")

_PLAIN_HEADER = """\
┌─────────────────┐
│   H-AUDITOR     │
└─────────────────┘"""


def render_header_text() -> str:
    try:
        from pyfiglet import Figlet
    except ImportError:
        return _PLAIN_HEADER

    for font in FIGLET_FONTS:
        with suppress(Exception):
            art = Figlet(font=font, width=120).renderText(HEADER_TEXT).rstrip("\n")
            # Reject layouts that wrap into a tall block (old H0N3YP0T-AUD1T0R problem).
            if art.count("\n") <= 6:
                return art
    return HEADER_TEXT


def print_cli_header(console: Console | None = None) -> None:
    console = console or Console()
    console.print(Text(render_header_text(), style="bold bright_cyan"))
    console.print(f"[dim]honeypot-auditor v{__version__}[/dim]\n")
