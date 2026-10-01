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


def match_telnet_cowrie_preamble(raw: bytes) -> str | None:
    """Cowrie/Kippo often emits IAC DO NAWS then a bare 'login:' prompt."""
    data = raw or b""
    if not data:
        return None
    low = data.lower()
    if b"\xff\xfd\x1f" in data and b"login:" in low:
        return "IAC DO NAWS then login: (Cowrie-style preamble)"
    return None


def match_telnet_ayt_stub(raw: bytes, *, spoke: bool = False) -> str | None:
    """IAC AYT (246) unanswered after a confirmed Telnet speaker.

    Many real stacks ignore AYT until login — empty/timeout alone is never scored.
    Only fire when we already saw Telnet speakership and the reply has no
    printable content (callers should also set ``requires_corroboration``).
    """
    if not spoke:
        return None
    data = raw or b""
    if not data:
        # Timeout / empty after speakership — corroboration-gated only.
        return "IAC AYT unanswered"
    # Strip IAC sequences; if nothing printable remains, treat as stub.
    i = 0
    printable = bytearray()
    while i < len(data):
        if data[i] == 255 and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd == 255:
                printable.append(255)
                i += 2
                continue
            if cmd == 250:  # SB … SE
                i += 2
                while i + 1 < len(data) and not (data[i] == 255 and data[i + 1] == 240):
                    i += 1
                i = i + 2 if i + 1 < len(data) else len(data)
                continue
            i += 3 if i + 2 < len(data) else len(data)
            continue
        printable.append(data[i])
        i += 1
    if not bytes(printable).strip():
        return "IAC AYT unanswered (no printable reply)"
    return None


def match_telnet_cmd_desert(outputs: dict[str, str]) -> str | None:
    """Distinct post-login commands return the same canned reject/lure line."""
    cleaned: list[tuple[str, str]] = []
    for cmd, out in (outputs or {}).items():
        line = (out or "").strip()
        if not line:
            continue
        # Normalize whitespace for comparison.
        norm = " ".join(line.split())
        cleaned.append((cmd, norm))
    if len(cleaned) < 2:
        return None
    first = cleaned[0][1]
    if all(norm == first for _cmd, norm in cleaned):
        # Identical empty-ish prompts alone are weak; require substance.
        if len(first) < 8:
            return None
        cmds = ", ".join(cmd for cmd, _ in cleaned)
        return f"identical canned reply for {cmds}"
    return None
