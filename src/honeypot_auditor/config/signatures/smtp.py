from __future__ import annotations

import re


def match_smtp_extension_monotone(replies: list[tuple[str, int, str]]) -> str | None:
    """VRFY/EXPN/STARTTLS/ETRN return one generic code instead of RFC-distinct replies."""
    if len(replies) < 3:
        return None
    hits: list[str] = []
    for cmd, code, _msg in replies:
        if cmd == "VRFY" and code == 250:
            hits.append("VRFY 250 (real MTAs usually 252/550/502)")
        if cmd == "STARTTLS" and code == 250:
            hits.append("STARTTLS 250 instead of 220")
    codes = [c for _, c, _ in replies]
    if len(set(codes)) == 1 and codes[0] in {250, 500, 502, 503}:
        hits.append(f"VRFY/EXPN/ETRN/STARTTLS all returned {codes[0]}")
    return "; ".join(hits) if hits else None


def match_smtp_placeholder_identity(text: str) -> str | None:
    """Greeting/EHLO hostname is loopback, RFC1918-in-name, or a canned 'no relay' lure."""
    blob = (text or "").lower()
    if not blob.strip():
        return None
    if "127.0.0.1" in blob or "localhost" in blob:
        return "SMTP identity is loopback/localhost"
    if re.search(r"\bip-127-\d+-\d+-\d+\b", blob):
        return "SMTP identity encodes loopback"
    if re.search(r"\bip-(?:10|172-(?:1[6-9]|2\d|3[01])|192-168)-\d+", blob):
        return "SMTP identity encodes a private IP"
    if "no uce" in blob or "no ube" in blob or "no relay probes" in blob:
        return "SMTP 220 advertises canned NO UCE/RELAY PROBES"
    return None


def match_smtp_lost_envelope(mail_code: int, rcpt_code: int, rcpt_msg: str = "") -> str | None:
    """MAIL FROM 2xx then RCPT 503 need-sender: the envelope was not actually stored."""
    try:
        mail_n, rcpt_n = int(mail_code), int(rcpt_code)
    except (TypeError, ValueError):
        return None
    if not (200 <= mail_n < 300 and rcpt_n == 503):
        return None
    blob = (rcpt_msg or "").lower()
    if any(t in blob for t in ("sender", "mail from", "need mail", "mail first")):
        return "MAIL FROM accepted then RCPT 503 (envelope not stored)"
    return None
