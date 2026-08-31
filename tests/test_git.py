"""Git-daemon probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.git as git


@patch.object(git, "tcp_transact")
def test_git_always_missing(mock_tcp):
    mock_tcp.return_value = (b"003dERR no such repository: /hpaudit.git\n", "")
    inds = git.probe_git("127.0.0.1", 9418)
    assert inds[0].triggered


@patch.object(git, "tcp_transact")
def test_git_ref_advertisement_clean(mock_tcp):
    mock_tcp.return_value = (b"001e# service=git-upload-pack\n0000", "")
    inds = git.probe_git("127.0.0.1", 9418)
    assert not inds[0].triggered


@patch.object(git, "tcp_transact")
def test_git_closed_port(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = git.probe_git("127.0.0.1", 9418)
    assert all(i.skipped for i in inds)
