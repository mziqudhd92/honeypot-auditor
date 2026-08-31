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


def test_cowrie_basic_tells_are_confirmed():
    inds = [
        _ind("arbitrary_auth", True),
        _ind("state_nonpersist", True),
        _ind("static_signature", True),
    ]
    score, _ = compute_score(inds)
    assert score == 75.0
    assert threat_level(score, inds) == "Confirmed Honeypot"
    inds = [_ind("shodan", True), _ind("arbitrary_auth", True), _ind("state_nonpersist", True), _ind("static_signature", True)]
    score, hits = compute_score(inds)
    assert score == 100.0
    assert threat_level(score, inds) == "Confirmed Honeypot"
    assert hits["shodan"]["triggered"]
    assert hits["arbitrary_auth"]["triggered"]
    assert not hits["cotenancy"]["triggered"]


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


def test_multi_user_arbitrary_auth_scores_100():
    inds = [
        Indicator(
            id="ssh.arbitrary_auth",
            title="SSH arbitrary credential acceptance",
            category="arbitrary_auth",
            triggered=True,
            protocol="ssh",
            evidence="user_a15,user_a99",
            detail="random user_a15:**** accepted; 2nd login user_a99:**** also accepted",
        ),
        _ind("state_nonpersist", False),
        _ind("static_signature", False),
    ]
    report = build_report(
        target="203.0.113.1",
        resolved_ip="203.0.113.1",
        ports={"ssh": [22]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    assert report.score == 100.0
    assert report.threat_level == "Confirmed Honeypot"
    assert report.category_hits["arbitrary_auth"]["contribution"] == 100.0
    assert report.category_hits["arbitrary_auth"]["dynamic"] is True


def test_buffet_cotenancy_confirms_deny_all_stack():
    """Deny-all multi-lure stacks: ≥5 protocol hits → buffet; corroboration from 2nd protocol."""
    protos = ("ftp", "http", "vnc", "git", "rdp", "mongodb")
    inds = [_ind("state_nonpersist", True), _ind("static_signature", True)]
    for i, proto in enumerate(protos):
        inds.append(
            Indicator(
                id=f"{proto}.tell",
                title="tell",
                category="static_signature" if i % 2 else "state_nonpersist",
                triggered=True,
                protocol=f"{proto}:1",
            )
        )
    report = build_report(
        target="203.0.113.1",
        resolved_ip="203.0.113.1",
        ports={p: [1] for p in protos},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    # state 25 + static 20 + buffet 15 + corroboration (6-1)*5 = 25 → 85
    assert report.score == 85.0
    assert report.threat_level == "Confirmed Honeypot"
    assert any(i.id == "cotenancy.buffet" for i in report.indicators)
    assert any(i.id == "corroboration.protocol_buffet" for i in report.indicators)
    assert report.category_hits["corroboration"]["contribution"] == 25.0


def test_buffet_lab_scale_scores_95_without_shodan():
    """OpenCanary-class deny-all buffet: 11 protocol lures → 60% base + 35% corroboration cap."""
    protos = (
        "ftp",
        "http",
        "httpproxy",
        "vnc",
        "git",
        "rdp",
        "mongodb",
        "mssql",
        "mysql",
        "redis",
        "telnet",
    )
    inds = [_ind("state_nonpersist", True), _ind("static_signature", True)]
    for i, proto in enumerate(protos):
        inds.append(
            Indicator(
                id=f"{proto}.tell",
                title="tell",
                category="static_signature" if i % 2 else "state_nonpersist",
                triggered=True,
                protocol=f"{proto}:1",
            )
        )
    report = build_report(
        target="203.0.113.1",
        resolved_ip="203.0.113.1",
        ports={p: [1] for p in protos},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    assert report.score == 95.0
    assert report.category_hits["corroboration"]["contribution"] == 35.0


def test_trapster_class_two_protocol_fsm_stacks():
    """Deny-all: UAV static + FTP desert state stack; 2nd protocol adds corroboration."""
    inds = [
        Indicator(
            id="telnet.banner",
            title="Telnet pre-auth banner",
            category="static_signature",
            triggered=True,
            protocol="telnet:23",
            detail="User Access Verification",
        ),
        Indicator(
            id="ftp.desert",
            title="FTP command desert",
            category="state_nonpersist",
            triggered=True,
            protocol="ftp:21",
            detail="4 common verbs return 500 Unknown Command",
        ),
    ]
    report = build_report(
        target="203.0.113.50",
        resolved_ip="203.0.113.50",
        ports={"telnet": [23], "ftp": [21]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    # static 20 + state 25 + corroboration +5 = 50
    assert report.score == 50.0
    assert report.category_hits["static_signature"]["contribution"] == 20.0
    assert report.category_hits["state_nonpersist"]["contribution"] == 25.0
    assert report.category_hits["corroboration"]["contribution"] == 5.0
    assert not any(i.id == "cotenancy.buffet" for i in report.indicators)


def test_protocol_strategy_matrix_statuses():
    from honeypot_auditor.analyzer import protocol_strategy_matrix

    inds = [
        Indicator(
            id="ssh.arbitrary_auth",
            title="a",
            category="arbitrary_auth",
            triggered=True,
            protocol="ssh:22",
        ),
        Indicator(
            id="ssh.exec_denied",
            title="s",
            category="state_nonpersist",
            triggered=False,
            protocol="ssh:22",
        ),
        Indicator(
            id="ssh.banner",
            title="b",
            category="static_signature",
            skipped=True,
            skip_reason="no session",
            protocol="ssh:22",
        ),
        Indicator(
            id="http.malformed_200",
            title="h",
            category="static_signature",
            triggered=True,
            protocol="http:80",
        ),
    ]
    rows = {r["protocol"]: r for r in protocol_strategy_matrix(inds, {"ssh": [22], "http": [80]})}
    assert rows["ssh"]["arbitrary_auth"]["status"] == "hit"
    assert rows["ssh"]["state_nonpersist"]["status"] == "clean"
    assert rows["ssh"]["static_signature"]["status"] == "skip"
    assert rows["http"]["arbitrary_auth"]["status"] == "n/a"
    assert rows["http"]["static_signature"]["status"] == "hit"


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
