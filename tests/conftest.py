"""Shared pytest fixtures."""

from __future__ import annotations

from honeypot_auditor.models import Indicator


def indicator(**kwargs) -> Indicator:
    defaults = {
        "id": "test.ind",
        "title": "test",
        "category": "static_signature",
        "triggered": False,
        "skipped": False,
    }
    defaults.update(kwargs)
    return Indicator(**defaults)
