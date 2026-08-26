"""Extended probe tests."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.extended as extended


@patch("honeypot_auditor.probes.extended.tcp_transact")
def test_vnc_single_session_handshake(mock_tcp):
    mock_tcp.return_value = (
        b"RFB 003.008\n"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"qemu raspberrypi localhost.localdomain",
        "",
    )
    inds = extended.probe_vnc("127.0.0.1", 5900)
    assert inds[0].triggered
    mock_tcp.assert_called_once_with(
        "127.0.0.1",
        5900,
        b"RFB 003.008\n",
        recv_first=True,
    )
