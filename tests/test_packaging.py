"""Packaging and config package smoke tests."""

from __future__ import annotations

from honeypot_auditor import config
from honeypot_auditor.http2_fingerprint import load_http2_profiles
from honeypot_auditor.signatures.loader import load_core_pack
from honeypot_auditor.tls_fingerprint import load_tls_profiles


def test_config_package_exports_legacy_symbols():
    """Barrel re-exports keep `from honeypot_auditor.config import X` working."""
    required = [
        "WEIGHTS",
        "DEEP_WEIGHTS",
        "PROBE_USERNAME_TEMPLATE",
        "probe_port_map",
        "expand_scan_targets",
        "match_ssh_banner",
        "match_ftp_stale_banner",
        "match_nmap_service_tell",
        "USER_AGENT",
        "HTTP_HEADER_LURE_ORDERS",
        "MSSQL_CANNED_PRELOGIN",
        "is_private_or_loopback",
    ]
    missing = [name for name in required if not hasattr(config, name)]
    assert not missing, f"missing config exports: {missing}"
    assert "match_ssh_banner" in config.__all__
    assert "WEIGHTS" in config.__all__


def test_bundled_signature_and_profile_data():
    pack = load_core_pack()
    assert len(pack.rules) >= 3
    tls = load_tls_profiles()
    assert "lures" in tls
    assert tls["lures"], "tls lure table should ship in package data"
    h2 = load_http2_profiles()
    assert h2.get("lures"), "http2 lure profiles should ship in package data"
