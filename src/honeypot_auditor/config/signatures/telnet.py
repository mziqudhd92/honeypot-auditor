from honeypot_auditor.config.tells.telnet import TELNET_BANNER_TELLS, TELNET_CANNED_REJECTS


def match_telnet_banner(text: str) -> str | None:
    blob = text or ""
    if not blob.strip():
        return None
    low = blob.lower()
    for tell in TELNET_BANNER_TELLS:
        if tell.lower() in low:
            return tell
    return None


def match_telnet_canned_reject(text: str) -> str | None:
    blob = text or ""
    if not blob.strip():
        return None
    low = blob.lower()
    for tell in TELNET_CANNED_REJECTS:
        if tell.lower() in low:
            return tell
    return None


def match_telnet_option_spray(raw: bytes, text: str = "") -> str | None:
    """Many WILL/DO options then a Username: prompt — typical of a canned telnet FSM."""
    data = raw or b""
    n_will_do = 0
    i = 0
    while i + 2 < len(data):
        if data[i] == 255 and data[i + 1] in (251, 253):
            n_will_do += 1
            i += 3
            continue
        i += 1
    if n_will_do >= 5 and "username:" in (text or "").lower():
        return f"IAC option spray ({n_will_do} WILL/DO) then Username:"
    return None


def match_telnet_blind_option(raw: bytes) -> str | None:
    """Server WILL/DO unknown option 99 (RFC 854 would WONT/DONT)."""
    data = raw or b""
    if b"\xff\xfb\x63" in data or b"\xff\xfd\x63" in data:
        return "accepted unknown Telnet option 99"
    return None
