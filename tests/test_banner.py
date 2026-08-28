"""Tests for CLI figlet header."""

from __future__ import annotations

from honeypot_auditor.banner import HEADER_TEXT, render_header_text


def test_render_header_text_contains_title():
    art = render_header_text()
    assert HEADER_TEXT in art or len(art) > len(HEADER_TEXT)
