"""Git-daemon probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.git as git

_CREDS = (("user_low", "pass_low"), ("user_HIGH_entropy_xx", "pass_HIGH_entropy_yy"))
_AD = (
    b"001e# service=git-upload-pack\n"
    b"003b1111111111111111111111111111111111111111 refs/heads/master\x00"
    b"multi_ack thin-pack side-band-64k\n"
    b"0000"
)
_ERR = b"003dERR no such repository: /hpaudit.git\n"


@patch.object(git, "tcp_transact")
def test_git_always_missing(mock_tcp):
    mock_tcp.return_value = (_ERR, "")
    with (
        patch.object(git, "entropy_varied_creds", return_value=_CREDS),
        patch.object(git, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = git.probe_git("127.0.0.1", 9418)
    by_id = {i.id: i for i in inds}
    assert by_id["git.signature"].triggered
    assert not by_id["git.arbitrary_auth"].triggered


@patch.object(git, "tcp_transact")
def test_git_ref_advertisement_clean(mock_tcp):
    # Signature path advertises (not always-missing); auth repos both ERR → no auth hit.
    mock_tcp.side_effect = [
        (_AD, ""),  # signature baseline
        (_ERR, ""),  # auth repo a
        (_ERR, ""),  # auth repo b
    ]
    with (
        patch.object(git, "entropy_varied_creds", return_value=_CREDS),
        patch.object(git, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = git.probe_git("127.0.0.1", 9418)
    by_id = {i.id: i for i in inds}
    assert not by_id["git.signature"].triggered
    assert not by_id["git.arbitrary_auth"].triggered


@patch.object(git, "tcp_transact")
def test_git_closed_port(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = git.probe_git("127.0.0.1", 9418)
    assert all(i.skipped for i in inds)
    assert {i.id for i in inds} == {
        "git.arbitrary_auth",
        "git.state_nonpersist",
        "git.signature",
    }


@patch.object(git, "tcp_transact")
def test_git_arbitrary_auth_any_repo_facade(mock_tcp):
    mock_tcp.side_effect = [
        (_ERR, ""),  # signature
        (_AD, ""),  # auth a
        (_AD, ""),  # auth b
        (_ERR, ""),  # capability negotiation follow-up
    ]
    with (
        patch.object(git, "entropy_varied_creds", return_value=_CREDS),
        patch.object(git, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = git.probe_git("127.0.0.1", 9418)
    by_id = {i.id: i for i in inds}
    assert by_id["git.arbitrary_auth"].triggered
    assert by_id["git.state_nonpersist"].triggered  # caps claimed then ERR


@patch.object(git, "tcp_transact")
def test_git_state_ad_then_err_inconsistent(mock_tcp):
    mock_tcp.side_effect = [
        (_ERR, ""),  # signature
        (_AD, ""),  # auth a (ad)
        (_ERR, ""),  # auth b (err) — mixed, no auth hit
        (_ERR, ""),  # re-check after jitter → ERR (inconsistent with prior ad)
    ]
    with (
        patch.object(git, "entropy_varied_creds", return_value=_CREDS),
        patch.object(git, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = git.probe_git("127.0.0.1", 9418)
    by_id = {i.id: i for i in inds}
    assert not by_id["git.arbitrary_auth"].triggered
    assert by_id["git.state_nonpersist"].triggered
