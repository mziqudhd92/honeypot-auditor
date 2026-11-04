"""TDD: deep probes must receive corroboration= from the audit host orchestrator."""

from __future__ import annotations

import argparse
import asyncio
from unittest.mock import patch

from honeypot_auditor.analyzer import has_ungated_corroboration
from honeypot_auditor.cli import _audit_host
from honeypot_auditor.models import Indicator
from honeypot_auditor.settings import settings


def test_has_ungated_corroboration_ignores_gated_and_info():
    assert not has_ungated_corroboration(
        [
            Indicator(
                id="gated",
                title="g",
                category="behavior",
                triggered=True,
                requires_corroboration=True,
            )
        ]
    )
    assert has_ungated_corroboration(
        [
            Indicator(
                id="ssh.auth",
                title="a",
                category="arbitrary_auth",
                triggered=True,
            )
        ]
    )


def test_audit_host_passes_corroboration_into_deep_probes():
    args = argparse.Namespace(
        with_nmap=False,
        intel_provider=[],
        intel_key=[],
        shodan_key="",
        deep=True,
        confirm_authorized=True,
        preset="iana",
        timeout=3.0,
        extra_ports=[],
        ports="",
        safe_mode=False,
    )
    captured: dict = {}

    def fake_deep(host, ports, *, corroboration: bool = False):
        captured["corroboration"] = corroboration
        return [
            Indicator(
                id="deep.llm_hallucination",
                title="LLM",
                category="behavior",
                triggered=True,
                requires_corroboration=True,
                protocol="ssh",
            )
        ]

    basic = [
        Indicator(
            id="ssh.arbitrary_auth",
            title="auth",
            category="arbitrary_auth",
            triggered=True,
            protocol="ssh",
        )
    ]

    prev_deep = settings.deep
    settings.deep = True
    try:
        with (
            patch("honeypot_auditor.cli.run_deep_probes", side_effect=fake_deep),
            patch(
                "honeypot_auditor.cli._probe_jobs",
                return_value=[
                    ("ssh:22", lambda: basic),
                    ("deep", lambda: []),  # placeholder removed by orchestrator
                ],
            ),
        ):
            report = asyncio.run(
                _audit_host(
                    "127.0.0.1",
                    args,
                    {"ssh": [22]},
                    include_shodan=False,
                )
            )
    finally:
        settings.deep = prev_deep

    assert captured.get("corroboration") is True
    llm = {i.id: i for i in report.indicators}["deep.llm_hallucination"]
    assert llm.triggered is True
