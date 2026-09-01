"""HTTP/2 SETTINGS fingerprint tests."""

from __future__ import annotations

import struct

from honeypot_auditor.http2_fingerprint import match_http2_profile, parse_settings_order


def _settings_frame(*setting_ids: int) -> bytes:
    body = b"".join(struct.pack("!HI", sid, 1) for sid in setting_ids)
    header = struct.pack("!I", len(body))[1:4] + bytes([0x04, 0x00]) + struct.pack("!I", 0)
    return header + body


def test_parse_settings_order():
    raw = _settings_frame(0x03, 0x04, 0x05)
    order = parse_settings_order(raw)
    assert order == ["MAX_CONCURRENT_STREAMS", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE"]


def test_match_lure_profile():
    raw = _settings_frame(0x03, 0x04, 0x05)
    order = parse_settings_order(raw)
    name, kind = match_http2_profile(order)
    assert name == "python_h2_minimal"
    assert kind == "lure"
