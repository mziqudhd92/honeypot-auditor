"""Telnet fingerprint engine.

Strategies: arbitrary auth (any-password) · state non-persistence (canned reject, /tmp canary) · static signature (UAV / IAC spray, whoami).
"""

from __future__ import annotations

import re
import secrets

from honeypot_auditor.config import (
    match_cowrie_identity,
    match_telnet_banner,
    match_telnet_blind_option,
    match_telnet_canned_reject,
    match_telnet_option_spray,
    match_uname_signature,
)
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import is_safe_mode, random_creds, skip_suite
from honeypot_auditor.probes.shell_cti import (
    CTI_SHELL_COMMANDS,
    identity_tells,
    whoami_matches_lure,
)

_TELNET_SKIP = (
    ("telnet.banner", "Telnet pre-auth banner matches a known lure template", "static_signature"),
    ("telnet.iac_negotiate", "Telnet IAC accepts unknown options or resets on AUTH/NAWS", "static_signature"),
    ("telnet.arbitrary_auth", "Telnet arbitrary credential acceptance", "arbitrary_auth"),
    ("telnet.auth_lure", "Telnet canned auth reject (fake login FSM)", "state_nonpersist"),
    ("telnet.uname", "Telnet uname/cpuinfo / Cowrie identity", "static_signature"),
    ("telnet.whoami", "Telnet whoami/prompt is the random lure account", "static_signature"),
    ("telnet.session_persist", "Telnet filesystem does not persist across sessions", "state_nonpersist"),
)

# IAC WILL 99, IAC DO AUTH (37), IAC SB AUTH, IAC SB NAWS 80x24.
_IAC_PROBE = bytes(
    [
        255, 251, 99,
        255, 253, 37,
        255, 250, 37, 0, 255, 240,
        255, 250, 31, 0, 80, 0, 24, 255, 240,
    ]
)


def probe_telnet(host: str, port: int) -> list[Indicator]:
    if is_safe_mode():
        return _probe_telnet_safe(host, port)
    user, password = random_creds()
    user2, password2 = random_creds()
    canary = secrets.token_hex(4)
    canary_path = f"/tmp/hpaudit_{canary}"
    banner_raw, banner_err = tcp_transact(host, port, _IAC_PROBE, recv_first=True)
    banner_text = _telnet_text(banner_raw)
    if banner_err and not banner_raw:
        return skip_suite(_TELNET_SKIP, closed_reason(banner_err), protocol="telnet", error=banner_err)

    auth_ok, session_out, auth_err = _telnet_login_and_probe(
        host, port, user, password, extra_cmds=(f"echo {canary} > {canary_path}", f"cat {canary_path}")
    )
    if auth_err and not banner_raw and not auth_ok:
        return skip_suite(_TELNET_SKIP, closed_reason(auth_err), protocol="telnet", error=auth_err)

    auth2_ok, session2, _ = _telnet_login_and_probe(
        host, port, user2, password2, extra_cmds=(f"cat {canary_path}",)
    )
    preauth = "\n".join(p for p in (banner_text, session_out) if p)
    banner_hit = match_telnet_banner(preauth) or match_telnet_option_spray(banner_raw, banner_text)
    iac_hit = match_telnet_blind_option(banner_raw)
    if banner_err and banner_raw and "reset" in banner_err.lower():
        iac_hit = iac_hit or "connection reset on AUTH/NAWS subnegotiation"
    reject_hit = match_telnet_canned_reject(session_out or preauth)
    persist_missing = bool(auth_ok and auth2_ok and canary and canary not in session2)
    id_bits = identity_tells(session_out)
    whoami_hit = bool(auth_ok and whoami_matches_lure(session_out, user))
    auth_detail = (
        f"random {user}:**** accepted"
        + (f"; 2nd login {user2}:**** also accepted" if auth2_ok else "; 2nd random login not accepted")
        if auth_ok
        else f"random {user}:**** not accepted"
    )

    return [
        Indicator(
            id="telnet.banner",
            title="Telnet pre-auth banner matches a known lure template",
            category="static_signature",
            triggered=bool(banner_hit),
            protocol="telnet",
            detail=banner_hit or (banner_text.strip()[:240] or "(no printable banner)"),
            evidence=preauth[:1500],
        ),
        Indicator(
            id="telnet.iac_negotiate",
            title="Telnet IAC accepts unknown options or resets on AUTH/NAWS",
            category="static_signature",
            triggered=bool(iac_hit),
            protocol="telnet",
            detail=iac_hit or "unknown option 99 declined (WONT/DONT) or ignored",
            evidence=banner_raw[:200],
        ),
        Indicator(
            id="telnet.arbitrary_auth",
            title="Telnet arbitrary credential acceptance",
            category="arbitrary_auth",
            triggered=auth_ok and auth2_ok,
            protocol="telnet",
            detail=auth_detail,
            evidence=f"{user},{user2}" if auth2_ok else user,
        ),
        Indicator(
            id="telnet.auth_lure",
            title="Telnet canned auth reject (fake login FSM)",
            category="state_nonpersist",
            triggered=bool(reject_hit),
            protocol="telnet",
            skipped=not (session_out or banner_text),
            skip_reason="" if (session_out or banner_text) else "no login transcript",
            detail=(
                f"canned reject {reject_hit!r} (not a real Cisco/Unix auth error)"
                if reject_hit
                else "no canned reject string in login transcript"
            ),
            evidence=(session_out or preauth)[:800],
        ),
        Indicator(
            id="telnet.uname",
            title="Telnet uname/cpuinfo / Cowrie identity",
            category="static_signature",
            triggered=bool(id_bits),
            protocol="telnet",
            skipped=not auth_ok,
            skip_reason="" if auth_ok else "no session (auth failed)",
            detail="; ".join(id_bits) if id_bits else (session_out[:240] or "no identity output"),
            evidence=session_out[:1500],
        )
        if auth_ok
        else skipped_indicator(
            "telnet.uname",
            "Telnet uname/cpuinfo / Cowrie identity",
            "static_signature",
            "no session (auth failed)",
            protocol="telnet",
        ),
        Indicator(
            id="telnet.whoami",
            title="Telnet whoami/prompt is the random lure account",
            category="static_signature",
            triggered=whoami_hit,
            protocol="telnet",
            skipped=not auth_ok,
            skip_reason="" if auth_ok else "no session (auth failed)",
            detail=(
                f"session identity is lure account {user}"
                if whoami_hit
                else f"lure account {user} not reflected in whoami/prompt"
            ),
            evidence=session_out[:800],
        )
        if auth_ok
        else skipped_indicator(
            "telnet.whoami",
            "Telnet whoami/prompt is the random lure account",
            "static_signature",
            "no session (auth failed)",
            protocol="telnet",
        ),
        Indicator(
            id="telnet.session_persist",
            title="Telnet filesystem does not persist across sessions",
            category="state_nonpersist",
            triggered=persist_missing,
            protocol="telnet",
            skipped=not (auth_ok and auth2_ok),
            skip_reason="" if (auth_ok and auth2_ok) else "need two sessions to verify persist",
            detail=(
                f"wrote {canary_path} then new login could not read it"
                if persist_missing
                else (f"canary {canary} still present after reconnect" if auth2_ok else "2nd session failed")
            ),
            evidence=session2[:400],
        )
        if auth_ok and auth2_ok
        else skipped_indicator(
            "telnet.session_persist",
            "Telnet filesystem does not persist across sessions",
            "state_nonpersist",
            "need two sessions to verify persist",
            protocol="telnet",
        ),
    ]


def strip_telnet_iac(data: bytes) -> bytes:
    """Drop Telnet IAC option negotiation so banners/prompts are searchable."""
    iac, sb, se = 255, 250, 240
    out = bytearray()
    i = 0
    n = len(data or b"")
    while i < n:
        if data[i] == iac and i + 1 < n:
            cmd = data[i + 1]
            if cmd == iac:
                out.append(255)
                i += 2
                continue
            if cmd == sb:
                i += 2
                while i + 1 < n and not (data[i] == iac and data[i + 1] == se):
                    i += 1
                i = i + 2 if i + 1 < n else n
                continue
            i += 3 if i + 2 < n else n
            continue
        out.append(data[i])
        i += 1
    return bytes(out)


def _telnet_text(data: bytes) -> str:
    return strip_telnet_iac(data or b"").decode("utf-8", "replace")


def _telnet_login_and_probe(
    host: str,
    port: int,
    user: str,
    password: str,
    extra_cmds: tuple[str, ...] = (),
) -> tuple[bool, str, str]:
    """Sync telnet probe (safe inside asyncio.to_thread workers)."""
    cmds = "\r\n".join((*CTI_SHELL_COMMANDS, *extra_cmds))
    payload = user.encode() + b"\r\n" + password.encode() + b"\r\n" + cmds.encode() + b"\r\n"
    data, err = tcp_transact(host, port, payload, recv_first=True)
    text = _telnet_text(data)
    return _looks_like_shell(text), text, err


def _looks_like_shell(text: str) -> bool:
    low = (text or "").lower()
    if any(x in low for x in ("login incorrect", "authentication failed", "access denied", "wrong password")):
        return False
    if match_uname_signature(text) or match_cowrie_identity(text) or "processor\t:" in low or "processor :" in low:
        return True
    if re.search(r"user_a\d+@", text or ""):
        return True
    return any(tok in text for tok in ("$ ", "# ", ":~$", "~$"))


def _probe_telnet_safe(host: str, port: int) -> list[Indicator]:
    """Safe mode: pre-auth banner + IAC spray only."""
    banner_raw, err = tcp_transact(host, port, b"", recv_first=True)
    if err and not banner_raw:
        return skip_suite(_TELNET_SKIP, closed_reason(err), protocol="telnet", error=err)
    banner_text = _telnet_text(banner_raw)
    iac_raw, _ = tcp_transact(host, port, _IAC_PROBE, recv_first=False)
    iac_text = _telnet_text(iac_raw)
    skipped = [
        skipped_indicator(i, title, cat, "safe-mode: handshake-only", protocol="telnet")
        for i, title, cat in _TELNET_SKIP
        if i not in ("telnet.banner", "telnet.iac_negotiate")
    ]
    return [
        Indicator(
            id="telnet.banner",
            title="Telnet pre-auth banner matches a known lure template",
            category="static_signature",
            triggered=bool(match_telnet_banner(banner_text)),
            protocol="telnet",
            detail=banner_text[:240] or "(no banner)",
        ),
        Indicator(
            id="telnet.iac_negotiate",
            title="Telnet IAC accepts unknown options or resets on AUTH/NAWS",
            category="static_signature",
            triggered=bool(match_telnet_option_spray(iac_text) or match_telnet_blind_option(iac_text)),
            protocol="telnet",
            detail=iac_text[:240] or "(no IAC response)",
        ),
        *skipped,
    ]
