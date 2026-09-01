"""Plugin API tests."""

from __future__ import annotations

from honeypot_auditor.plugins.api import get_registered_probes, register_probe


def test_register_probe():
    def dummy_probe(host, port):
        return []

    register_probe("test_proto", dummy_probe)
    probes = get_registered_probes()
    assert "test_proto" in probes
