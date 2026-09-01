"""Offline socket replay tests (no network)."""

from __future__ import annotations

import pytest

from honeypot_auditor.httpwire import parse_header_names
from honeypot_auditor.tls_fingerprint import compute_ja3s, read_server_hello


@pytest.mark.replay
def test_replay_tls_server_hello_ja3s():
    body = (
        b"\x02\x00\x00\x2e"
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\xc0\x2f"
        + b"\x00"
    )
    record = b"\x16\x03\x03" + len(body).to_bytes(2, "big") + body
    parsed = read_server_hello(record)
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
