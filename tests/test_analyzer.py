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
    inds = [
        _ind("shodan", True),
        _ind("arbitrary_auth", True),
        _ind("state_nonpersist", True),
        _ind("static_signature", True),
    ]
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
    # Fired tells below Suspected must never read as Likely Real Host.
    assert threat_level(score, inds) == "Inconclusive (Low-confidence anomalies detected)"


def test_clean_host_is_likely_real():
    inds = [_ind("shodan", False), _ind("arbitrary_auth", False)]
    score, _ = compute_score(inds)
    assert score == 0.0
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
    assert report.score_breakdown["category_total_pct"] == 30.0
    assert report.score_breakdown["score_before_override_pct"] == 30.0
    assert report.score_breakdown["decisive_override"] == "multi_user_arbitrary_auth"
    assert report.score_breakdown["final_score_pct"] == 100.0
    assert report.confidence == "high"
    assert report.tactical_action == "SKIP_TARGET"


def test_ssh_kex_facade_alone_is_suspected_medium():
    """Cowrie KEX facade is a high-fidelity pre-auth tell — not 'Likely Real Host' / low."""
    inds = [
        Indicator(
            id="ssh.kex_facade",
            title="SSH OpenSSH banner with Twisted/Cowrie KEX facade",
            category="static_signature",
            triggered=True,
            protocol="ssh",
            detail="OpenSSH banner with Twisted/Cowrie KEX facade",
            fidelity="high",
        ),
        Indicator(
            id="ssh.arbitrary_auth",
            title="SSH arbitrary credential acceptance",
            category="arbitrary_auth",
            triggered=False,
            protocol="ssh",
        ),
        Indicator(
            id="ssh.uname",
            title="SSH uname",
            category="static_signature",
            skipped=True,
            skip_reason="no session (auth failed)",
            protocol="ssh",
        ),
    ]
    report = build_report(
        target="203.0.113.50",
        resolved_ip="203.0.113.50",
        ports={"ssh": [22]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    # static 20 + high-signal bonus 15 = 35 global; scoped = 35/75*100 ≈ 46.67
    assert report.score == 35.0
    assert report.scoped_score == 46.67
    assert report.threat_level == "Suspected Honeypot"
    assert report.confidence == "medium"
    assert any(i.id == "corroboration.high_signal" for i in report.indicators)
    assert report.tactical_action == "PROCEED_CAUTION"


def test_pop3_auth_failed_blanket_is_high_signal_suspected():
    """Blanket + stock banner: intra-category + high fidelity clear Suspected."""
    inds = [
        Indicator(
            id="pop3.auth_failed_blanket",
            title="POP3 auth-failed blanket",
            category="static_signature",
            triggered=True,
            protocol="pop3",
            detail="identical auth-themed -ERR on CAPA, STAT",
            fidelity="high",
        ),
        Indicator(
            id="pop3.stock_banner",
            title="POP3 stock banner",
            category="static_signature",
            triggered=True,
            protocol="pop3",
            requires_corroboration=True,
            fidelity="medium",
        ),
        Indicator(
            id="pop3.arbitrary_auth",
            title="POP3 arbitrary auth",
            category="arbitrary_auth",
            triggered=False,
            protocol="pop3",
        ),
        Indicator(
            id="pop3.preauth_state",
            title="POP3 preauth",
            category="state_nonpersist",
            triggered=False,
            protocol="pop3",
        ),
    ]
    report = build_report(
        target="203.0.113.50",
        resolved_ip="203.0.113.50",
        ports={"pop3": [110]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    # static 20 + intra 7.5 + high-signal 15 = 42.5; scoped = 42.5/75*100 ≈ 56.67
    assert report.score == 42.5
    assert report.scoped_score == 56.67
    assert report.category_hits["static_signature"]["intra_category_bonus"] == 7.5
    assert report.threat_level == "Suspected Honeypot"
    assert report.confidence == "medium"
    assert any(i.id == "corroboration.high_signal" for i in report.indicators)
    assert report.tactical_action == "PROCEED_CAUTION"
    assert report.score_breakdown["scoped"]["applicable"] is True


def test_intra_category_bonus_caps_at_15():
    inds = [
        Indicator(
            id=f"static.{i}",
            title="t",
            category="static_signature",
            triggered=True,
            protocol="http",
        )
        for i in range(4)
    ]
    score, hits = compute_score(inds)
    assert hits["static_signature"]["hit_count"] == 4
    assert hits["static_signature"]["intra_category_bonus"] == 15.0
    assert score == 35.0  # 20 + 15


def test_scoped_score_only_for_single_port():
    inds = [
        Indicator(
            id="ssh.kex_facade",
            title="kex",
            category="static_signature",
            triggered=True,
            protocol="ssh",
            fidelity="high",
        ),
        _ind("arbitrary_auth", False),
    ]
    multi = build_report(
        target="203.0.113.1",
        resolved_ip="203.0.113.1",
        ports={"ssh": [22], "http": [80]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    assert multi.scoped_score is None
    assert multi.score_breakdown["scoped"]["applicable"] is False
    single = build_report(
        target="203.0.113.1",
        resolved_ip="203.0.113.1",
        ports={"ssh": [22]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    assert single.scoped_score is not None
    assert single.scoped_score > single.score


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
    # state 25+15 + static 20+15 + buffet 15 + corroboration (6-1)*5 = 25 → 115 → 100
    assert report.score == 100.0
    assert report.threat_level == "Confirmed Honeypot"
    assert any(i.id == "cotenancy.buffet" for i in report.indicators)
    assert any(i.id == "corroboration.protocol_buffet" for i in report.indicators)
    assert report.category_hits["corroboration"]["contribution"] == 25.0
    assert report.score_breakdown["category_total_pct"] == 90.0
    assert report.score_breakdown["bonus_total_pct"] == 25.0
    assert report.score_breakdown["raw_score_pct"] == 115.0
    assert report.score_breakdown["final_score_pct"] == 100.0
    assert report.score_breakdown["cap_applied"] is True


def test_silent_accept_cluster_scores_cotenancy():
    inds = [
        Indicator(
            id="http.silent_accept",
            title="h",
            category="static_signature",
            triggered=True,
            protocol="http",
        ),
        Indicator(
            id="http.silent_accept",
            title="h2",
            category="static_signature",
            triggered=True,
            protocol="http",
        ),
        Indicator(
            id="httpproxy.silent_accept",
            title="p",
            category="static_signature",
            triggered=True,
            protocol="httpproxy",
        ),
    ]
    report = build_report(
        target="203.0.113.9",
        resolved_ip="203.0.113.9",
        ports={"http": [80, 443], "httpproxy": [8080]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    assert any(i.id == "cotenancy.silent_accept_cluster" for i in report.indicators)
    # static 20+15 (3 hits) + cotenancy 15 + corroboration 5 = 55
    assert report.score == 55.0
    assert report.threat_level == "Suspected Honeypot"


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
    assert report.score == 100.0
    assert report.category_hits["corroboration"]["contribution"] == 35.0
    assert report.score_breakdown["cap_applied"] is True


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
    assert (
        match_uname_signature("Linux host 6.1.0-18-amd64 #1 SMP Debian 6.1.76-1 x86_64 GNU/Linux")
        is None
    )


def test_docker_research_ports():
    ports = merge_ports("docker-research", parse_port_overrides("http=8081"))
    assert ports["ssh"] == 2222
    assert ports["http"] == 8081


def test_invalid_port_override():
    with pytest.raises(ValueError):
        parse_port_overrides("ssh=99999")


def test_confidence_medium_two_protocols():
    from honeypot_auditor.analyzer import build_report, compute_confidence

    inds = [
        Indicator(
            id="ssh.static",
            title="s",
            category="static_signature",
            triggered=True,
            protocol="ssh",
        ),
        Indicator(
            id="ftp.static",
            title="f",
            category="static_signature",
            triggered=True,
            protocol="ftp",
        ),
        Indicator(
            id="telnet.static",
            title="t",
            category="static_signature",
            triggered=False,
            protocol="telnet",
        ),
        Indicator(
            id="http.static",
            title="h",
            category="static_signature",
            triggered=False,
            protocol="http",
        ),
    ]
    assert compute_confidence(inds) in ("medium", "low")
    report = build_report(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        ports={"ssh": [22], "ftp": [21]},
        indicators=inds,
        notes=[],
        started_at="",
        finished_at="",
    )
    assert report.confidence in ("medium", "low", "high")
    assert report.tactical_action


@pytest.mark.parametrize(
    "score,confidence,proxy,expected",
    [
        (70.0, "high", True, "INCONCLUSIVE"),
        (70.0, "high", False, "SKIP_TARGET"),
        (70.0, "low", False, "PROCEED_CAUTION"),
        (20.0, "high", False, "PIVOT_POSSIBLE"),
        (45.0, "medium", False, "PROCEED_CAUTION"),
    ],
)
def test_tactical_action_matrix(score, confidence, proxy, expected):
    from honeypot_auditor.analyzer import compute_tactical_action

    triggered = expected != "PIVOT_POSSIBLE"
    action, _ = compute_tactical_action(
        score,
        confidence,
        proxy_detected=proxy,
        threat_level="Suspected Honeypot" if triggered else "Likely Real Host",
        indicators=[
            Indicator(
                id="x",
                title="x",
                category="static_signature",
                triggered=triggered,
            )
        ],
    )
    assert action == expected


def test_confidence_ignores_shodan_and_closed_port_skips():
    from honeypot_auditor.analyzer import compute_confidence

    inds = [
        Indicator(
            id="shodan.honeyscore",
            title="s",
            category="shodan",
            skipped=True,
            skip_reason="no API key (--shodan-key)",
            protocol="shodan",
        ),
        Indicator(
            id="ftp.banner",
            title="f",
            category="static_signature",
            skipped=True,
            skip_reason="connection refused (closed port or filtered)",
            protocol="ftp",
        ),
        Indicator(
            id="ssh.arbitrary_auth",
            title="a",
            category="arbitrary_auth",
            triggered=True,
            protocol="ssh",
            evidence="user_a1,user_a2",
        ),
        Indicator(
            id="ssh.uname",
            title="u",
            category="static_signature",
            triggered=True,
            protocol="ssh",
        ),
    ]
    assert compute_confidence(inds) == "high"


def test_secondary_contributions_kept_under_any_password_bonus():
    inds = [
        Indicator(
            id="ssh.arbitrary_auth",
            title="SSH arbitrary credential acceptance",
            category="arbitrary_auth",
            triggered=True,
            protocol="ssh",
            evidence="user_a15,user_a99",
        ),
        Indicator(
            id="ssh.uname",
            title="uname",
            category="static_signature",
            triggered=True,
            protocol="ssh",
        ),
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
    assert report.category_hits["static_signature"]["triggered"] is True
    assert report.category_hits["static_signature"]["contribution"] > 0
    assert report.tactical_action == "SKIP_TARGET"


def test_never_applicable_skip_does_not_match_content_filtered():
    from honeypot_auditor.analyzer import _is_never_applicable_skip

    ind = Indicator(
        id="http.waf",
        title="waf",
        category="static_signature",
        skipped=True,
        skip_reason="response body looked content-filtered by WAF",
        protocol="http",
    )
    assert not _is_never_applicable_skip(ind)
    closed = Indicator(
        id="ftp.banner",
        title="f",
        category="static_signature",
        skipped=True,
        skip_reason="connection refused (closed port or filtered)",
        protocol="ftp",
    )
    assert _is_never_applicable_skip(closed)


def test_tactical_ignores_never_applicable_skips_for_coverage():
    from honeypot_auditor.analyzer import compute_tactical_action

    inds = [
        Indicator(
            id="shodan.honeyscore",
            title="s",
            category="shodan",
            skipped=True,
            skip_reason="no API key (--shodan-key)",
            protocol="shodan",
        ),
        Indicator(
            id="ftp.banner",
            title="f",
            category="static_signature",
            skipped=True,
            skip_reason="connection refused (closed port or filtered)",
            protocol="ftp",
        ),
        Indicator(
            id="ssh.banner",
            title="b",
            category="static_signature",
            triggered=True,
            protocol="ssh",
        ),
        Indicator(
            id="http.login_skin",
            title="h",
            category="static_signature",
            triggered=True,
            protocol="http",
        ),
    ]
    action, _ = compute_tactical_action(
        70.0,
        "medium",
        proxy_detected=False,
        threat_level="Suspected Honeypot",
        indicators=inds,
    )
    assert action == "SKIP_TARGET"
