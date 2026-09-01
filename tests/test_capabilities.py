"""Capability probing tests."""

from __future__ import annotations

from unittest.mock import patch

from honeypot_auditor.capabilities import probe_capabilities


def test_probe_capabilities_returns_dataclass():
    caps = probe_capabilities()
    assert hasattr(caps, "raw_sockets")
    assert hasattr(caps, "scapy_tls")
    assert hasattr(caps, "pysocks")
    assert isinstance(caps.as_dict(), dict)


def test_unprivileged_no_crash():
    with patch("honeypot_auditor.capabilities._probe_raw_socket", return_value=False):
        caps = probe_capabilities()
    assert caps.raw_sockets is False
    assert "raw_sockets_disabled" in caps.warnings
