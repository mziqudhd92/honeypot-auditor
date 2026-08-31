"""SIP probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.sip as sip


@patch.object(sip, "udp_transact")
def test_sip_probe(mock_udp):
    mock_udp.return_value = (
        b"SIP/2.0 200 OK\r\nServer: Asterisk PBX\r\n\r\n",
        "",
    )
    inds = sip.probe_sip("127.0.0.1", 5060)
    assert len(inds) >= 1
