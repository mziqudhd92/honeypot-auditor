"""Offline socket replay tests (no network)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from honeypot_auditor.httpwire import parse_header_names
from honeypot_auditor.probes import ftp, pop3
from honeypot_auditor.probes.deep.stack import probe_hassh
from honeypot_auditor.settings import settings
from honeypot_auditor.tls_fingerprint import compute_ja3s, read_server_hello, tls_handshake


@pytest.mark.replay
def test_replay_tls_server_hello_ja3s(replay_socket):
    replay_socket("tls_server_hello.json")
    raw, err = tls_handshake("127.0.0.1", 443)
    assert not err
    parsed = read_server_hello(raw)
    assert parsed is not None
    ja3s = compute_ja3s(parsed)
    assert len(ja3s) == 32


@pytest.mark.replay
def test_replay_http_header_order(replay_socket):
    replay_socket("http_nginx.json")
    from honeypot_auditor.netutil import tcp_transact

    raw, err = tcp_transact("127.0.0.1", 80, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", recv_first=False)
    assert not err
    names = parse_header_names(raw.decode("latin-1", "replace"))
    assert "Server" in names or "server".lower() in [n.lower() for n in names]


@pytest.mark.replay
def test_replay_pop3_conformant_state_machine(replay_socket):
    replay_socket("pop3_conformant.json")
    with patch.object(pop3, "random_creds", return_value=("replay_user", "replay_credential")):
        indicators = pop3.probe_pop3("127.0.0.1", 110)
    assert not any(ind.triggered for ind in indicators)
    assert not any(ind.skipped for ind in indicators)


@pytest.mark.replay
def test_replay_ftp_dionaea_banner_safe_mode(replay_socket):
    replay_socket("ftp_dionaea_banner.json")
    old_safe = settings.safe_mode
    settings.safe_mode = True
    try:
        inds = ftp.probe_ftp("127.0.0.1", 21)
    finally:
        settings.safe_mode = old_safe
    by_id = {i.id: i for i in inds}
    assert by_id["ftp.banner"].triggered
    assert "dionaea" in by_id["ftp.banner"].detail.lower()


@pytest.mark.replay
def test_replay_ssh_kexinit_cowrie(replay_socket):
    replay_socket("ssh_kexinit_cowrie.json")
    inds = probe_hassh("127.0.0.1", 22)
    by_id = {i.id: i for i in inds}
    assert by_id["deep.hassh"].triggered
    # Rigid template overlaps hassh for OpenSSH-claimed Cowrie — suppress double score.
    assert not by_id["deep.kexinit_rigid"].triggered
    assert "covered by deep.hassh" in by_id["deep.kexinit_rigid"].detail
    assert "raw_kexinit" in by_id["deep.hassh"].evidence
