"""Deterministic TLS ClientHello and JA3S/JA4S parsing."""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from honeypot_auditor.proxy_transport import create_connection

# Fixed TLS 1.2 ClientHello template (golden — do not change without updating tests)
_CLIENT_HELLO_TLS12 = bytes.fromhex(
    "16030100cd010000c90303"
    "0000000000000000000000000000000000000000000000000000"
    "0020"
    "0000000000000000000000000000000000000000000000000000"
    "0010"
    "c02fc030009fcca9cca8ccaa0039006b0035003f"
    "0100"
    "0066"
    "0000"
    "00170000"
    "001500000017000000"
    "000a0008000600170018001900"
    "000b0002010000"
    "000d0014001204030804030105030805050108060601020100"
)

# Alternate templates for blend profile (deterministic per seed)
_BLEND_HELLOS = (
    _CLIENT_HELLO_TLS12,
    bytes.fromhex(
        "16030100cd010000c90303"
        "0000000000000000000000000000000000000000000000000000"
        "0020"
        "0000000000000000000000000000000000000000000000000000"
        "0010"
        "c030c02f009eccaa0039006735003d0033003f"
        "0100"
        "0066"
        "0000"
        "00170000"
        "001500000017000000"
        "000a0008000600170018001900"
        "000b0002010000"
        "000d0014001204030804030105030805050108060601020100"
    ),
    bytes.fromhex(
        "16030100cd010000c90303"
        "0000000000000000000000000000000000000000000000000000"
        "0020"
        "0000000000000000000000000000000000000000000000000000"
        "0010"
        "130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035"
        "0100"
        "0066"
        "0000"
        "00170000"
        "001500000017000000"
        "000a0008000600170018001900"
        "000b0002010000"
        "000d0014001204030804030105030805050108060601020100"
    ),
)


@dataclass
class ServerHelloParsed:
    version: int
    cipher: int
    extensions: list[tuple[int, bytes]]
    raw: bytes


def build_client_hello(
    version: int = 0x0303,
    ciphers: list[int] | None = None,
    extensions: list[tuple[int, bytes]] | None = None,
    sni: str = "",
    *,
    seed: int | None = None,
    blend: bool = False,
) -> bytes:
    """Return fixed ClientHello bytes (audit) or seeded blend template."""
    _ = (version, ciphers, extensions, sni)
    if blend:
        idx = (seed or 0) % len(_BLEND_HELLOS)
        return _BLEND_HELLOS[idx]
    return _CLIENT_HELLO_TLS12


def _tls_profiles_path() -> Path:
    """Resolve bundled profiles (wheel-safe package path)."""
    return Path(__file__).resolve().parent / "data" / "tls_profiles.json"


@lru_cache(maxsize=1)
def load_tls_profiles() -> dict:
    """Load lure/CDN TLS profiles from packaged data/tls_profiles.json."""
    path = _tls_profiles_path()
    if not path.is_file():
        return {"lures": {}, "cdn_edge": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def match_lure_profile(ja3s: str, ja4s: str = "") -> tuple[str, str]:
    """Return (profile_name, kind) when ja3s/ja4s matches a lure entry."""
    profiles = load_tls_profiles()
    for name, prof in profiles.get("lures", {}).items():
        prof_ja3s = prof.get("ja3s", "")
        if prof_ja3s and "placeholder" not in str(prof_ja3s).lower() and prof_ja3s == ja3s:
            return name, "lure"
        prof_ja4s = prof.get("ja4s", "")
        if ja4s and prof_ja4s and "placeholder" not in str(prof_ja4s).lower() and prof_ja4s == ja4s:
            return name, "lure"
    for name, prof in profiles.get("cdn_edge", {}).items():
        prof_ja3s = prof.get("ja3s", "")
        if prof_ja3s and "placeholder" not in str(prof_ja3s).lower() and prof_ja3s == ja3s:
            return name, "cdn"
    return "", ""


def read_server_hello(raw: bytes) -> ServerHelloParsed | None:
    """Parse TLS ServerHello from raw bytes."""
    if len(raw) < 5 or raw[0] != 0x16:
        return None
    rec_len = struct.unpack("!H", raw[3:5])[0]
    body = raw[5 : 5 + rec_len]
    if len(body) < 38 or body[0] != 0x02:
        return None
    version = struct.unpack("!H", body[4:6])[0]
    cipher = struct.unpack("!H", body[34:36])[0]
    ext_data = body[36:]
    extensions: list[tuple[int, bytes]] = []
    if len(ext_data) >= 2:
        ext_len = struct.unpack("!H", ext_data[:2])[0]
        pos = 2
        end = min(2 + ext_len, len(ext_data))
        while pos + 4 <= end:
            etype = struct.unpack("!H", ext_data[pos : pos + 2])[0]
            elen = struct.unpack("!H", ext_data[pos + 2 : pos + 4])[0]
            pos += 4
            extensions.append((etype, ext_data[pos : pos + elen]))
            pos += elen
    return ServerHelloParsed(version=version, cipher=cipher, extensions=extensions, raw=raw)


def compute_ja3s(parsed: ServerHelloParsed) -> str:
    """JA3S for TLS 1.2 ServerHello (cleartext extensions)."""
    if parsed.version >= 0x0304:
        return "n/a (TLS 1.3 — use JA4S)"
    ext_str = "-".join(str(e[0]) for e in parsed.extensions) if parsed.extensions else ""
    raw = f"{parsed.version},{parsed.cipher},{ext_str}"
    return hashlib.md5(raw.encode()).hexdigest()  # noqa: S324


def compute_ja4s(parsed: ServerHelloParsed) -> str:
    """Simplified JA4S-style fingerprint for TLS 1.3+."""
    parts = [
        f"t{parsed.version:04x}",
        f"c{parsed.cipher:04x}",
        str(len(parsed.extensions)),
    ]
    return hashlib.sha256(",".join(parts).encode()).hexdigest()[:32]


def tls_handshake(
    host: str,
    port: int,
    timeout: float = 3.0,
    *,
    seed: int | None = None,
    blend: bool = False,
) -> tuple[bytes, str]:
    """Send fixed ClientHello and read ServerHello bytes."""
    hello = build_client_hello(seed=seed, blend=blend)
    try:
        with create_connection(host, port, timeout) as sock:
            sock.sendall(hello)
            data = b""
            while len(data) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) >= 5:
                    rec_len = struct.unpack("!H", data[3:5])[0]
                    if len(data) >= 5 + rec_len:
                        break
            return data, ""
    except OSError as exc:
        return b"", str(exc)
