"""SSH HASSH / HASSHServer computation (Salesforce HASSH spec)."""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass


@dataclass
class SSHKexInit:
    kex: str
    host_key: str
    enc_c2s: str
    enc_s2c: str
    mac_c2s: str
    mac_s2c: str
    comp_c2s: str
    comp_s2c: str

    @property
    def hassh_server(self) -> str:
        return _md5(";".join([self.kex, self.enc_s2c, self.mac_s2c, self.comp_s2c]))

    @property
    def hassh_client(self) -> str:
        return _md5(";".join([self.kex, self.enc_c2s, self.mac_c2s, self.comp_c2s]))


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).hexdigest()


def parse_kexinit_payload(payload: bytes) -> SSHKexInit | None:
    if len(payload) < 17 or payload[0] != 20:
        return None
    reader = payload[17:]
    lists: list[str] = []
    while len(lists) < 8 and reader:
        if len(reader) < 4:
            return None
        (n,) = struct.unpack(">I", reader[:4])
        reader = reader[4:]
        if n > len(reader):
            return None
        lists.append(reader[:n].decode("utf-8", "replace"))
        reader = reader[n:]
    if len(lists) < 8:
        return None
    return SSHKexInit(*lists[:8])


def find_kexinit_payload(raw: bytes) -> bytes | None:
    offset = 0
    # Identification string is text; binary packets follow the first LF.
    if raw.startswith(b"SSH-"):
        nl = raw.find(b"\n")
        if nl >= 0:
            offset = nl + 1
    while offset + 5 <= len(raw):
        pkt_len = struct.unpack(">I", raw[offset : offset + 4])[0]
        if pkt_len < 1 or offset + 4 + pkt_len > len(raw):
            idx = raw.find(bytes([20]), offset)
            if idx < 0:
                return None
            offset = max(offset + 1, idx - 4)
            continue
        pad = raw[offset + 4]
        pay_start = offset + 5
        pay_end = offset + 4 + pkt_len - pad
        if pay_start >= pay_end or pay_end > len(raw):
            offset += 1
            continue
        payload = raw[pay_start:pay_end]
        if payload and payload[0] == 20:
            return payload
        offset += 4 + pkt_len
    return None


def capture_server_kexinit(raw: bytes) -> tuple[str, SSHKexInit | None]:
    banner = ""
    if raw:
        first_line = raw.split(b"\n", 1)[0]
        banner = first_line.decode("utf-8", "replace").strip()
    payload = find_kexinit_payload(raw)
    if payload is None:
        return banner, None
    return banner, parse_kexinit_payload(payload)


_OPENSSH_VERSION_RE = re.compile(r"OpenSSH_(\d+\.\d+p?\d*)")


def openssh_version_from_banner(banner: str) -> str | None:
    match = _OPENSSH_VERSION_RE.search(banner or "")
    return match.group(1) if match else None


# Algorithm prefixes typical of OpenSSH 8.x/9.x server KEXINIT (not Twisted/Cowrie).
_OPENSSH_KEX_PREFIXES = (
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
)

_TWISTED_KEX_MARKERS = (
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
)

_OPENSSH_MAJOR_RE = re.compile(r"^(\d+)\.(\d+)")


def hassh_algo_mismatch(banner: str, kex: SSHKexInit) -> tuple[bool, str]:
    """Return (triggered, detail) when claimed OpenSSH banner disagrees with KEXINIT shape.

    Catches classic Twisted/Cowrie (legacy-first KEX) and modern Cowrie facades that
    advertise curve25519 while still shipping Twisted host-key / AEAD / MAC suites.
    Works pre-auth — useful when Cowrie is password-gated (no any-password tell).
    """
    version = openssh_version_from_banner(banner)
    if not version:
        return False, "non-OpenSSH banner"
    kex_list = [p for p in kex.kex.split(",") if p]
    first_kex = kex_list[0] if kex_list else ""
    twistedish = any(m in kex.kex for m in _TWISTED_KEX_MARKERS) and not any(
        p in kex.kex for p in _OPENSSH_KEX_PREFIXES[:2]
    )
    if twistedish and banner.startswith("SSH-2.0-OpenSSH"):
        return (
            True,
            f"banner claims OpenSSH_{version} but KEX order looks Twisted/Cowrie ({first_kex})",
        )
    if first_kex and not any(
        first_kex.startswith(p.split("-")[0]) or p in first_kex for p in _OPENSSH_KEX_PREFIXES
    ):
        if "group1-sha1" in first_kex or "group14-sha1" in first_kex:
            return (
                True,
                f"legacy-first KEX {first_kex} inconsistent with modern OpenSSH_{version} banner",
            )

    facade_bits = _cowrie_facade_bits(version, kex)
    if len(facade_bits) >= 2:
        return (
            True,
            f"OpenSSH_{version} banner with Twisted/Cowrie KEX facade: " + "; ".join(facade_bits),
        )
    return False, f"KEX first={first_kex or '?'}"


def _cowrie_facade_bits(version: str, kex: SSHKexInit) -> list[str]:
    """Heuristic tells for password-gated Cowrie that mimics OpenSSH 8+/9+ banners."""
    match = _OPENSSH_MAJOR_RE.match(version or "")
    if not match:
        return []
    major = int(match.group(1))
    if major < 8:
        return []
    bits: list[str] = []
    host_keys = [h for h in (kex.host_key or "").split(",") if h]
    enc = kex.enc_s2c or ""
    mac = kex.mac_s2c or ""
    kex_algs = kex.kex or ""
    if (
        host_keys
        and host_keys[0] == "ssh-rsa"
        and "rsa-sha2-256" not in host_keys
        and "rsa-sha2-512" not in host_keys
    ):
        bits.append("host_key prefers ssh-rsa without rsa-sha2-*")
    has_aead = "chacha20-poly1305" in enc or "aes128-gcm" in enc or "aes256-gcm" in enc
    has_legacy_enc = "3des-cbc" in enc or "aes128-cbc" in enc or "aes256-cbc" in enc
    if not has_aead and has_legacy_enc:
        bits.append("enc lacks AEAD (chacha20/gcm) but still offers CBC/3DES")
    if "etm@openssh.com" not in mac and "hmac-sha1" in mac:
        bits.append("MAC lacks *-etm@openssh.com")
    if (
        "diffie-hellman-group14-sha1" in kex_algs
        and "diffie-hellman-group-exchange-sha256" not in kex_algs
    ):
        bits.append("KEX includes group14-sha1 without group-exchange-sha256")
    return bits
