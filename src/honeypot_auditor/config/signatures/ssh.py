from honeypot_auditor.config.tells.ssh import (
    COWRIE_HOSTNAMES,
    COWRIE_MOTD_TELLS,
    CPUINFO_TELLS,
    SSH_BANNER_SIGNATURES,
    UNAME_HOST_RE,
    UNAME_SIGNATURES,
)


def match_ssh_banner(banner: str) -> str | None:
    text = (banner or "").strip()
    for sig in SSH_BANNER_SIGNATURES:
        if sig in text:
            return sig
    return None


def normalize_uname(text: str) -> str:
    if not text:
        return ""
    lines = (text or "").strip().splitlines()
    if not lines:
        return ""
    line = lines[0]
    return UNAME_HOST_RE.sub("Linux <host> ", line).strip()


def match_uname_signature(text: str) -> str | None:
    norm = normalize_uname(text)
    for sig in UNAME_SIGNATURES:
        if norm == sig:
            return sig
    return None


def match_cpuinfo_signature(text: str) -> str | None:
    blob = text or ""
    for tell in CPUINFO_TELLS:
        if tell in blob:
            return tell
    return None


def match_cowrie_identity(text: str) -> str | None:
    """Default Cowrie/Kippo hostname or MOTD (works even when banners are modern OpenSSH)."""
    blob = text or ""
    if not blob.strip():
        return None
    low = blob.lower()
    for host in COWRIE_HOSTNAMES:
        token = host.lower()
        if f"@{token}" in low or f"linux {token} " in low or f"linux {token}\n" in low:
            return f"cowrie-default-hostname={host}"
    for motd in COWRIE_MOTD_TELLS:
        if motd.lower() in low:
            return "cowrie-default-motd"
    return None
