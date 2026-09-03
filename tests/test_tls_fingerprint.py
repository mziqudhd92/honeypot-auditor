"""TLS fingerprint tests."""

from __future__ import annotations

from honeypot_auditor.tls_fingerprint import (
    build_client_hello,
    compute_ja3s,
    read_server_hello,
)


def test_client_hello_bytes_stable():
    a = build_client_hello()
    b = build_client_hello(sni="example.com")
    assert a == b
    assert len(a) > 50


def test_blend_seed_changes_client_hello():
    a = build_client_hello(blend=True, seed=0)
    b = build_client_hello(blend=True, seed=1)
    assert a != b


def test_match_lure_profile_empty_when_no_match():
    from honeypot_auditor.tls_fingerprint import match_lure_profile

    name, kind = match_lure_profile("deadbeef" * 4)
    assert name == ""
    assert kind == ""


def test_merge_tls_profile_entry_lure_and_cdn():
    from honeypot_auditor.tls_fingerprint import merge_tls_profile_entry

    doc = {"lures": {}, "cdn_edge": {"keep": {"ja3s": "abc"}}}
    merged = merge_tls_profile_entry(
        doc, name="lab_cowrie", ja3s="a" * 32, ja4s="", kind="lure"
    )
    assert merged["lures"]["lab_cowrie"]["ja3s"] == "a" * 32
    assert merged["cdn_edge"]["keep"]["ja3s"] == "abc"
    cdn = merge_tls_profile_entry(
        merged, name="cloudflare", ja3s="b" * 32, kind="cdn"
    )
    assert cdn["cdn_edge"]["cloudflare"]["ja3s"] == "b" * 32


def test_parse_host_port_ipv4_ipv6_and_default():
    from honeypot_auditor.tls_fingerprint import parse_host_port

    assert parse_host_port("127.0.0.1:8443") == ("127.0.0.1", 8443)
    assert parse_host_port("example.com") == ("example.com", 443)
    assert parse_host_port("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert parse_host_port("2001:db8::1") == ("2001:db8::1", 443)


def test_load_tls_profiles_merges_cdn_file():
    from honeypot_auditor.tls_fingerprint import clear_tls_profile_cache, load_tls_profiles

    clear_tls_profile_cache()
    profiles = load_tls_profiles()
    assert "lures" in profiles
    assert "cdn_edge" in profiles
    assert "cloudflare" in profiles["cdn_edge"]


def test_read_server_hello_minimal():
    # Synthetic TLS record: ServerHello with TLS 1.2
    body = b"\x02\x00\x00\x2e\x03\x03" + b"\x00" * 32 + b"\x00" + b"\xc0\x2f" + b"\x00"
    record = b"\x16\x03\x03" + len(body).to_bytes(2, "big") + body
    parsed = read_server_hello(record)
    assert parsed is not None
    assert parsed.version == 0x0303
    ja3s = compute_ja3s(parsed)
    assert ja3s != ""
    assert "n/a" not in ja3s
