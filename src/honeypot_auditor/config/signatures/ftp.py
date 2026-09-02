from honeypot_auditor.config.tells.ftp import (
    FTP_CANNED_REJECTS,
    FTP_STALE_BANNER_RE,
    FTP_STOCK_220,
)


def match_ftp_port_bounce(resp: str) -> str | None:
    """PORT to an unrelated host was accepted (no anti-bounce)."""
    first = (resp or "").strip().split(None, 1)[0] if resp else ""
    if first in {"200", "250"}:
        return f"PORT to an external address accepted ({first})"
    return None


def match_ftp_command_desert(responses: dict[str, str]) -> str | None:
    """Common FTP verbs all return the same shallow 500 Unknown Command."""
    unknown: list[str] = []
    for cmd, resp in (responses or {}).items():
        low = (resp or "").lower()
        if "500" in (resp or "") and "unknown" in low:
            unknown.append(cmd)
    if len(unknown) >= 2:
        return f"{len(unknown)} common verbs return 500 Unknown Command ({', '.join(unknown)})"
    return None


def match_ftp_stale_banner(welcome: str) -> str | None:
    """Stock/default 220 (e.g. ProFTPD 1.2.10) or an EOL daemon version on the greeting."""
    blob = welcome or ""
    low = blob.lower()
    for tell in FTP_STOCK_220:
        if tell.lower() in low:
            return f"stock default 220 {tell}"
    m = FTP_STALE_BANNER_RE.search(blob)
    return f"stale FTP banner {m.group(1)}" if m else None


def match_ftp_auth_lure(
    # These defaults initialize response text; neither value is a credential.
    user_resp: str = "",
    pass_resp: str = "",  # nosec B107
) -> str | None:
    blob = f"{user_resp}\n{pass_resp}"
    low = blob.lower()
    if ("guest login ok" in low or "anonymous login ok" in low) and (
        "530" in low or "authentication failed" in low
    ):
        return "331 guest/anonymous login ok then 530 reject"
    for tell in FTP_CANNED_REJECTS:
        if tell.lower() in low:
            return tell
    return None
