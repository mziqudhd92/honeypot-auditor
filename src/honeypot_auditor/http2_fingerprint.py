"""HTTP/2 SETTINGS frame fingerprinting."""

from __future__ import annotations

import json
import struct
from functools import lru_cache
from pathlib import Path

# HTTP/2 frame types
_FRAME_SETTINGS = 0x04

# Common SETTINGS identifiers
_SETTINGS_NAMES = {
    0x01: "HEADER_TABLE_SIZE",
    0x02: "ENABLE_PUSH",
    0x03: "MAX_CONCURRENT_STREAMS",
    0x04: "INITIAL_WINDOW_SIZE",
    0x05: "MAX_FRAME_SIZE",
    0x06: "MAX_HEADER_LIST_SIZE",
}


def _http2_profiles_path() -> Path:
    """Resolve bundled profiles (wheel-safe package path)."""
    return Path(__file__).resolve().parent / "data" / "http2_settings_profiles.json"


@lru_cache(maxsize=1)
def load_http2_profiles() -> dict:
    path = _http2_profiles_path()
    if not path.is_file():
        return {"lures": {}, "production": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def parse_settings_order(raw: bytes) -> list[str]:
    """Extract SETTINGS parameter order from raw HTTP/2 bytes."""
    pos = 0
    order: list[str] = []
    while pos + 9 <= len(raw):
        length = struct.unpack("!I", b"\x00" + raw[pos : pos + 3])[0]
        ftype = raw[pos + 3]
        pos += 9
        if ftype != _FRAME_SETTINGS:
            pos += length
            continue
        body = raw[pos : pos + length]
        pos += length
        off = 0
        while off + 6 <= len(body):
            sid = struct.unpack("!H", body[off : off + 2])[0]
            order.append(_SETTINGS_NAMES.get(sid, f"UNKNOWN_{sid:04x}"))
            off += 6
        break
    return order


def settings_signature(order: list[str]) -> str:
    return ",".join(order)


def match_http2_profile(order: list[str]) -> tuple[str, str]:
    sig = settings_signature(order)
    profiles = load_http2_profiles()
    for name, prof in profiles.get("lures", {}).items():
        if prof.get("settings_order") == sig:
            return name, "lure"
    for name, prof in profiles.get("production", {}).items():
        if prof.get("settings_order") == sig:
            return name, "production"
    return "", ""


def probe_http2_settings(raw_h2_bytes: bytes) -> tuple[list[str], str, str]:
    """Return (order, signature, lure_match)."""
    order = parse_settings_order(raw_h2_bytes)
    sig = settings_signature(order)
    match, kind = match_http2_profile(order)
    return order, sig, match if kind == "lure" else ""
