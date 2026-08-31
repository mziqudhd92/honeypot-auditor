"""VNC probe tests."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.vnc as vnc

_CANNED_FAIL = b"\x00\x00\x00\x01\x00\x00\x00\x16Authentication failure"


@patch.object(vnc, "tcp_roundtrips")
def test_vnc_canned_auth_fail(mock_rt):
    mock_rt.return_value = (
        [b"RFB 003.008\n", b"\x01\x02", b"\x00" * 16, _CANNED_FAIL],
        "",
    )
    inds = vnc.probe_vnc("127.0.0.1", 5000)
    by_id = {i.id: i for i in inds}
    assert by_id["vnc.handshake"].triggered
    assert "VNC-auth" in by_id["vnc.handshake"].detail or "Authentication failure" in by_id["vnc.handshake"].detail
    assert by_id["vnc.persist"].triggered
    assert by_id["vnc.security"].triggered
    assert mock_rt.call_count == 2
    mock_rt.assert_any_call(
        "127.0.0.1",
        5000,
        [b"RFB 003.008\n", b"\x02", b"\x00" * 16],
        recv_first=True,
    )


@patch.object(vnc, "tcp_roundtrips")
def test_vnc_desktop_name_still_static(mock_rt):
    mock_rt.return_value = (
        [b"RFB 003.008\nqemu raspberrypi localhost.localdomain", b"", b"", b""],
        "",
    )
    inds = vnc.probe_vnc("127.0.0.1", 5900)
    by_id = {i.id: i for i in inds}
    assert by_id["vnc.handshake"].triggered
    assert not by_id["vnc.persist"].triggered
    assert not by_id["vnc.security"].triggered


@patch.object(vnc, "tcp_roundtrips")
def test_vnc_closed_port(mock_rt):
    mock_rt.return_value = ([], "Connection refused")
    inds = vnc.probe_vnc("127.0.0.1", 5900)
    assert all(i.skipped for i in inds)
