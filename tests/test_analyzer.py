from __future__ import annotations

import pytest

from honeypot_auditor.analyzer import build_report, compute_score, threat_level
from honeypot_auditor.config import (
    match_ssh_banner,
    match_uname_signature,
    merge_ports,
    parse_port_overrides,
)
from honeypot_auditor.models import Indicator


def _ind(category: str, triggered: bool, skipped: bool = False) -> Indicator:
    return Indicator(
        id=f"{category}.t",
        title=category,
        category=category,
        triggered=triggered,
        skipped=skipped,
        skip_reason="x" if skipped else "",
    )


def test_all_categories_sum_to_100():
    inds = [_ind("shodan", True), _ind("arbitrary_auth", True), _ind("state_nonpersist", True), _ind("static_signature", True)]
    score, hits = compute_score(inds)
    assert score == 100.0
    assert threat_level(score, inds) == "Confirmed Honeypot"
    assert all(h["triggered"] for h in hits.values())


def test_shodan_only_is_25():
    inds = [_ind("shodan", True), _ind("arbitrary_auth", False)]
    score, _ = compute_score(inds)
    assert score == 25.0
    assert threat_level(score, inds) == "Likely Real Host"


def test_skipped_does_not_count():
    inds = [_ind("shodan", True, skipped=True), _ind("arbitrary_auth", False)]
    score, hits = compute_score(inds)
    assert score == 0.0
    assert not hits["shodan"]["triggered"]
    assert not hits["shodan"]["attempted"]


def test_all_skipped_inconclusive():
    inds = [_ind("shodan", False, skipped=True)]
    report = build_report(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        ports={},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    assert report.threat_level == "Inconclusive"
    assert report.score == 0.0


def test_ssh_banner_signature():
    assert match_ssh_banner("SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2")
    assert match_ssh_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3") is None


def test_uname_signature():
    raw = "Linux decoy 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux"
    assert match_uname_signature(raw)
    assert match_uname_signature("Linux host 6.1.0-18-amd64 #1 SMP Debian 6.1.76-1 x86_64 GNU/Linux") is None


def test_docker_research_ports():
    ports = merge_ports("docker-research", parse_port_overrides("http=8081"))
    assert ports["ssh"] == 2222
    assert ports["http"] == 8081


def test_invalid_port_override():
    with pytest.raises(ValueError):
        parse_port_overrides("ssh=99999")
