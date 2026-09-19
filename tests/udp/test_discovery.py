"""UDP package discovery: skip private modules; empty package stays import-safe."""

from __future__ import annotations

import types
from unittest.mock import MagicMock, patch

from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.probes.udp import discover_udp_engines
from honeypot_auditor.probes.udp._engine import UDPEngine


def test_import_probes_package_with_udp_is_safe():
    """UDP package discovery merges engines without breaking the registry."""
    assert isinstance(PROBE_BY_PROTOCOL, dict)
    assert "ssh" in PROBE_BY_PROTOCOL
    assert "snmp" in PROBE_BY_PROTOCOL
    discovered = {e.name for e in discover_udp_engines()}
    assert discovered <= set(PROBE_BY_PROTOCOL)
    assert "dns" in discovered
    assert "ntp" in discovered
    assert "ntp" in PROBE_BY_PROTOCOL


def test_discover_udp_engines_skips_underscore_modules():
    def probe_public(host: str, port: int):
        return []

    def probe_private(host: str, port: int):
        return []

    public_mod = types.ModuleType("honeypot_auditor.probes.udp.fake_public")
    public_mod.UDP_ENGINE = UDPEngine(name="fake_public", probe=probe_public)

    private_mod = types.ModuleType("honeypot_auditor.probes.udp._fake_private")
    private_mod.UDP_ENGINE = UDPEngine(name="fake_private", probe=probe_private)

    mods = {
        "honeypot_auditor.probes.udp.fake_public": public_mod,
        "honeypot_auditor.probes.udp._fake_private": private_mod,
    }

    def fake_import(name: str, package: str | None = None):
        del package
        if name in mods:
            return mods[name]
        raise ImportError(name)

    infos = [
        MagicMock(name="fake_public"),
        MagicMock(name="_fake_private"),
    ]
    # pkgutil.ModuleInfo uses .name attribute
    for info, n in zip(infos, ("fake_public", "_fake_private"), strict=True):
        info.name = n

    with (
        patch("honeypot_auditor.probes.udp._engine.pkgutil.iter_modules", return_value=infos),
        patch("honeypot_auditor.probes.udp._engine.importlib.import_module", side_effect=fake_import),
    ):
        engines = discover_udp_engines()

    names = {e.name for e in engines}
    assert names == {"fake_public"}
    assert "fake_private" not in names


def test_discover_udp_engines_includes_dns_and_ntp():
    engines = discover_udp_engines()
    names = {e.name for e in engines}
    assert "dns" in names
    assert "ntp" in names
    assert names <= set(PROBE_BY_PROTOCOL)


def test_udp_engine_dataclass_shape():
    def _probe(host: str, port: int):
        return []

    eng = UDPEngine(name="example", probe=_probe)
    assert eng.name == "example"
    assert eng.probe is _probe
