from honeypot_auditor.config.tells.smb import (
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
    SMB_SMB1_DIALECTS,
    STATUS_OBJECT_NAME_NOT_FOUND,
)


def match_smb_static_ntlm_challenge(challenges: list[bytes]) -> str | None:
    """Two sessions received the same 8-byte NTLM server challenge."""
    if len(challenges) < 2:
        return None
    if challenges[0] == challenges[1]:
        return f"identical NTLM server challenge across {len(challenges)} sessions"
    return None


def match_smb_bogus_pipe(code: int | None, detail: str, *, accepted: bool) -> str | None:
    """Random IPC$ pipe should return OBJECT_NAME_NOT_FOUND, not accept or reset."""
    if accepted:
        return f"bogus named pipe accepted ({detail})"
    if code == STATUS_OBJECT_NAME_NOT_FOUND:
        return None
    if code is not None:
        return f"bogus pipe NTSTATUS 0x{code:08X} (expected 0x{STATUS_OBJECT_NAME_NOT_FOUND:08X})"
    low = (detail or "").lower()
    if any(tok in low for tok in ("reset", "broken pipe", "connection refused", "timed out")):
        return f"bogus pipe probe failed messily: {detail[:120]}"
    return None


def match_smb_negotiate_deficit(facts: dict) -> str | None:
    """Negotiate stuck on legacy dialect or SMB 3.1.1 without encryption capability."""
    dialect = facts.get("dialect")
    if dialect is None:
        return None
    if isinstance(dialect, str):
        blob = dialect.strip()
        if blob in SMB_SMB1_DIALECTS or blob.upper().startswith("SMB 1") or blob == "1":
            return f"negotiated legacy dialect {blob}"
    if isinstance(dialect, int) and dialect < SMB2_DIALECT_30:
        return f"negotiated legacy dialect 0x{dialect:04x}"
    if dialect == SMB2_DIALECT_311 and not facts.get("supports_encryption"):
        return "SMB 3.1.1 without encryption capability"
    return None


def match_smb_target_info_mismatch(native_os: str, meta: dict) -> str | None:
    """Windows native_os but NTLM AV pairs advertise Unix/Samba-style names."""
    av = meta.get("av_pairs")
    if not av:
        return None
    try:
        from impacket import ntlm
    except ImportError:
        return None

    def _av_name(pair_id: int) -> str:
        item = av.get(pair_id)
        if not item:
            return ""
        raw = item[1]
        if isinstance(raw, bytes):
            return raw.decode("utf-16le", "replace")
        return str(raw)

    os_low = (native_os or "").lower()
    if "windows" not in os_low:
        return None
    for label in (_av_name(ntlm.NTLMSSP_AV_HOSTNAME), _av_name(ntlm.NTLMSSP_AV_DNS_HOSTNAME)):
        if not label:
            continue
        low = label.lower()
        if any(tok in low for tok in ("samba", "linux", "unix", "ubuntu", "debian", "emerald")):
            return f"native_os {native_os!r} vs NTLM name {label!r}"
    return None
