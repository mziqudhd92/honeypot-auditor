"""Engine SDK tests."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from honeypot_auditor.engine import Auditor
from honeypot_auditor.models import AuditReport
from honeypot_auditor.settings import ProbeProfile


def test_auditor_run_async_mock():
    mock_report = AuditReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        score=75.0,
        threat_level="Confirmed Honeypot",
        category_hits={},
        tactical_action="SKIP_TARGET",
    )

    async def _run():
        with patch("honeypot_auditor.engine._audit_host", new=AsyncMock(return_value=mock_report)):
            auditor = Auditor(
                target="127.0.0.1",
                safe_mode=True,
                profile=ProbeProfile.SAFE,
                shodan_history=False,
                output_format="json",
            )
            return await auditor.run_async()

    report = asyncio.run(_run())
    assert report.tactical_action == "SKIP_TARGET"


def test_auditor_resolves_shodan_key_from_env(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "env-shodan-key")
    auditor = Auditor(target="127.0.0.1", shodan_history=True)
    assert auditor._resolve_shodan_key() == "env-shodan-key"
    args = auditor._args_namespace()
    assert args.shodan_key == "env-shodan-key"
    assert args.shodan_history is True


def test_auditor_explicit_shodan_key_beats_env(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "env-shodan-key")
    auditor = Auditor(target="127.0.0.1", shodan_key="explicit-key")
    assert auditor._resolve_shodan_key() == "explicit-key"


def test_auditor_requires_auth_for_public():
    auditor = Auditor(target="8.8.8.8", confirm_authorized=False)
    with pytest.raises(PermissionError):
        auditor.run()
