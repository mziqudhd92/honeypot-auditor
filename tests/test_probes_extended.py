"""Extended probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.extended as extended


@patch("honeypot_auditor.probes.extended.tcp_transact")
def test_http_malformed_200(mock_tcp):
    mock_tcp.return_value = (
        b"HTTP/1.1 200 OK\r\nDate: Wed, 26 Aug 2026 00:00:00 GMT\r\n\r\n",
        "",
    )
    inds = extended.probe_http("127.0.0.1", 8080)
    by_id = {i.id: i for i in inds}
    assert by_id["http.malformed_200"].triggered
    assert not by_id["http.dynamic_headers"].triggered


@patch("honeypot_auditor.probes.extended.tcp_transact")
def test_http_skipped_on_closed_port(mock_tcp):
    mock_tcp.return_value = (b"", "Connection refused")
    inds = extended.probe_http("127.0.0.1", 8080)
    assert all(i.skipped for i in inds)


@patch("honeypot_auditor.probes.extended.tcp_transact")
@patch("honeypot_auditor.probes.extended.optional_import", return_value=None)
def test_redis_fallback_tcp_non_persist(mock_import, mock_tcp):
    mock_tcp.side_effect = [
        (b"+OK\r\n", ""),
        (b"$-1\r\n", ""),
        (b":1\r\n", ""),
    ]
    inds = extended.probe_redis("127.0.0.1", 6379)
    assert len(inds) == 1
    assert inds[0].triggered


@patch("honeypot_auditor.probes.extended.tcp_transact")
def test_smtp_banner_probe(mock_tcp):
    mock_tcp.return_value = (
        b"220 mail.example.com ESMTP\r\n250 OK\r\n",
        "",
    )
    inds = extended.probe_smtp("127.0.0.1", 25)
    assert any(i.protocol == "smtp" for i in inds)


@patch("honeypot_auditor.probes.extended.udp_transact")
def test_sip_probe(mock_udp):
    mock_udp.return_value = (
        b"SIP/2.0 200 OK\r\nServer: Asterisk PBX\r\n\r\n",
        "",
    )
    inds = extended.probe_sip("127.0.0.1", 5060)
    assert len(inds) >= 1
