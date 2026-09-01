from honeypot_auditor.config.tells.rdp_vnc import (
    RDP_CANNED_FAIL,
    RDP_CANNED_NLA,
    VNC_CANNED_AUTH_FAIL,
)


def match_vnc_invalid_security_challenge(raw: bytes) -> str | None:
    """Selecting security type 0 still produced a 16-byte VNC-auth challenge."""
    data = raw or b""
    if len(data) == 16 and not data.startswith(b"RFB"):
        return "security type 0 still sent a VNC-auth challenge"
    return None


def match_rdp_canned_nla(raw: bytes) -> str | None:
    """First RDP reply is a canned NLA TPKT with cookie 0x1234."""
    data = raw or b""
    if data.startswith(RDP_CANNED_NLA) or RDP_CANNED_NLA in data[:32]:
        return "canned NLA cookie 0x1234"
    return None


def match_vnc_auth_fail(raw: bytes) -> str | None:
    """RFB SecurityResult is a canned Authentication failure (length 0x16), never a desktop."""
    data = raw or b""
    if VNC_CANNED_AUTH_FAIL in data or data.startswith(VNC_CANNED_AUTH_FAIL):
        return "canned RFB Authentication failure"
    return None


def match_vnc_vncauth_only(raw: bytes) -> str | None:
    """Security handshake offers only VNC authentication (type 2)."""
    data = raw or b""
    if data[:2] == b"\x01\x02" or data.startswith(b"\x01\x02"):
        return "RFB offers only VNC-auth"
    return None


def match_rdp_neg_fail(raw: bytes) -> str | None:
    """Second RDP write is a canned negotiation-failure blob, then close."""
    data = raw or b""
    if data.startswith(RDP_CANNED_FAIL) or RDP_CANNED_FAIL in data[:24]:
        return "canned RDP negotiation failure"
    return None
