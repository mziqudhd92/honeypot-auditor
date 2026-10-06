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
