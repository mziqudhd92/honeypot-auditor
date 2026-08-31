"""RDP probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.rdp as rdp
from honeypot_auditor.config import RDP_CANNED_FAIL, RDP_CANNED_NLA


@patch.object(rdp, "tcp_roundtrips")
def test_rdp_canned_nla_and_neg_fail(mock_rt):
    mock_rt.return_value = ([RDP_CANNED_NLA, RDP_CANNED_FAIL], "")
    inds = rdp.probe_rdp("127.0.0.1", 3389)
    by_id = {i.id: i for i in inds}
    assert by_id["rdp.signature"].triggered
    assert by_id["rdp.persist"].triggered


@patch.object(rdp, "tcp_roundtrips")
def test_rdp_generic_x224_clean(mock_rt):
    mock_rt.return_value = ([bytes.fromhex("0300000b06d00000123400"), b""], "")
    inds = rdp.probe_rdp("127.0.0.1", 3389)
    by_id = {i.id: i for i in inds}
    assert not by_id["rdp.signature"].triggered
    assert not by_id["rdp.persist"].triggered


@patch.object(rdp, "tcp_roundtrips")
def test_rdp_closed_port(mock_rt):
    mock_rt.return_value = ([], "Connection refused")
    inds = rdp.probe_rdp("127.0.0.1", 3389)
    assert all(i.skipped for i in inds)
