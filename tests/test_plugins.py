"""Plugin API tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from honeypot_auditor.plugins import api
from honeypot_auditor.plugins.api import (
    get_registered_probes,
    load_plugins,
    register_probe,
    register_probes,
)


def test_register_probe():
    def dummy_probe(host, port):
        return []

    register_probe("test_proto", dummy_probe)
    probes = get_registered_probes()
    assert "test_proto" in probes


def test_register_probes_bulk():
    register_probes({"bulk_a": lambda h, p: [], "bulk_b": lambda h, p: []})
    probes = get_registered_probes()
    assert "bulk_a" in probes and "bulk_b" in probes


def test_load_plugins_skips_failing_entry_point():
    bad = MagicMock()
    bad.name = "badplug"
    bad.load.side_effect = RuntimeError("boom")
    good = MagicMock()
    good.name = "goodplug"

    def _register(reg):
        reg["from_plugin"] = lambda h, p: []

    good.load.return_value = _register
    with patch.object(api, "_registry", {}):
        with patch("importlib.metadata.entry_points", return_value=[bad, good]):
            loaded = load_plugins()
    assert "from_plugin" in loaded
    assert bad.load.called
