"""Wizard helper tests (input validation and plan building)."""

from __future__ import annotations

import pytest

from honeypot_auditor import wizard
from honeypot_auditor.engine import Auditor


def test_parse_ports_accepts_lists_and_dedupes():
    assert wizard.parse_ports("22, 23") == ["22,23"]
    assert wizard.parse_ports("22,22,8081") == ["22,8081"]
    assert wizard.parse_ports("") == []
    assert wizard.parse_ports("  9  ") == ["9"]


@pytest.mark.parametrize("bad", ["abc", "22;23", "70000", "0", "22,-1"])
def test_parse_ports_rejects_garbage(bad):
    with pytest.raises(ValueError):
        wizard.parse_ports(bad)


def test_build_auditor_maps_answers():
    auditor = wizard._build_auditor(
        target="127.0.0.1",
        preset="iana",
        ports="22,23",
        deep=True,
        timeout=5,
        confirm_authorized=False,
    )
    assert isinstance(auditor, Auditor)
    assert auditor.target == "127.0.0.1"
    assert auditor.preset == "iana"
    assert auditor.extra_ports == ["22,23"]
    assert auditor.deep is True
    assert auditor.timeout == 5.0
    assert auditor.confirm_authorized is False


def test_resolve_target_rejects_garbage():
    with pytest.raises(ValueError):
        wizard._resolve_target("   ")
    with pytest.raises(OSError):
        wizard._resolve_target("this-host-does-not-exist-hpaudit.invalid")


def test_resolve_target_resolves_loopback():
    assert wizard._resolve_target("localhost") == "127.0.0.1"


def test_resolve_target_accepts_private_cidr():
    assert wizard._resolve_target("192.168.1.0/24") == "192.168.1.1"


def test_target_needs_authorization_for_public_hosts():
    assert wizard._target_needs_authorization("1.1.1.1") is True
    assert wizard._target_needs_authorization("127.0.0.1") is False
    assert wizard._target_needs_authorization("10.0.0.0/24") is False


def test_run_one_sets_confirm_authorized_after_public_yes(monkeypatch):
    """Public-target confirmation must flip confirm_authorized before Auditor.run."""
    answers = iter(
        [
            "1.1.1.1",  # target
            "iana",  # preset
            "",  # ports
            False,  # deep
            3,  # timeout
            True,  # authorized
            "skip",  # export report file as
            False,  # audit another?
            False,  # show history?
        ]
    )
    captured: dict = {}

    class _FakeAuditor:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self):
            from honeypot_auditor.models import AuditReport

            return AuditReport(
                target="1.1.1.1",
                resolved_ip="1.1.1.1",
                score=0.0,
                threat_level="CLEAN",
                category_hits={},
                confidence="low",
                indicators=[],
            )

    monkeypatch.setattr(wizard.Prompt, "ask", lambda *a, **k: next(answers))
    monkeypatch.setattr(wizard.Confirm, "ask", lambda *a, **k: next(answers))
    monkeypatch.setattr(wizard.IntPrompt, "ask", lambda *a, **k: next(answers))
    monkeypatch.setattr(wizard, "Auditor", _FakeAuditor)
    monkeypatch.setattr(wizard, "render", lambda *a, **k: None)
    monkeypatch.setattr(wizard.storage, "save_report", lambda *a, **k: 1)
    monkeypatch.setattr(wizard, "print_cli_header", lambda: None)

    assert wizard.run_wizard() == 0
    assert captured.get("confirm_authorized") is True
