"""SMB fingerprint engine.

Strategies: arbitrary auth (dual entropy-varied logins both accepted) ·
state non-persistence (bogus pipe NTSTATUS · ghost share TREE_CONNECT) ·
static signature (SMB1/EOL native_os, static NTLM challenge, stock lure
shares, silent TCP accept / tarpit).
"""

from __future__ import annotations

from honeypot_auditor.config import (
    SMB_NATIVE_OS_TELLS,
    SMB_SMB1_DIALECTS,
    match_smb_bogus_pipe,
    match_smb_ghost_share,
    match_smb_static_ntlm_challenge,
    match_smb_stock_shares,
)
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import tcp_transact
from honeypot_auditor.probes.common import entropy_varied_creds, skip_suite
from honeypot_auditor.proxy_transport import create_connection
from honeypot_auditor.settings import settings
from honeypot_auditor.smbutil import (
    collect_ntlm_challenges,
    optional_impacket,
    probe_arbitrary_logins,
    probe_pipe_and_ghost_share,
    smb_connection_summary,
)

_SMB_SKIP = (
    ("smb.arbitrary_auth", "SMB accepts two entropy-varied credentials", "arbitrary_auth"),
    ("smb.dialect", "SMB dialect / native-OS emulator anomaly", "static_signature"),
    ("smb.ntlm_challenge", "NTLM server challenge is static across sessions", "static_signature"),
    ("smb.stock_shares", "SMB share list matches stock honeypot lure names", "static_signature"),
    ("smb.bogus_pipe", "Bogus IPC$ named pipe NTSTATUS is wrong", "state_nonpersist"),
    ("smb.ghost_share", "Ghost share TREE_CONNECT NTSTATUS is wrong", "state_nonpersist"),
    ("smb.silent_accept", "SMB TCP accepts then returns no protocol response", "static_signature"),
)


def _tcp_accepts(host: str, port: int) -> bool:
    try:
        with create_connection(host, port, min(2.0, float(settings.timeout_seconds))):
            return True
    except (OSError, ImportError, TimeoutError):
        return False


def _looks_like_smb_timeout(err: str) -> bool:
    low = (err or "").lower()
    return any(
        tok in low
        for tok in (
            "timed out",
            "timeout",
            "netbios connection with the remote host timed out",
        )
    )


def _silent_accept_suite(detail: str) -> list[Indicator]:
    out: list[Indicator] = []
    for i, title, cat in _SMB_SKIP:
        if i == "smb.silent_accept":
            out.append(
                Indicator(
                    id=i,
                    title=title,
                    category=cat,
                    triggered=True,
                    protocol="smb",
                    detail=detail[:240],
                    remediation="Speak SMB or refuse the TCP connection; silent accepts look like tarpits",
                )
            )
        else:
            out.append(
                Indicator(
                    id=i,
                    title=title,
                    category=cat,
                    triggered=False,
                    protocol="smb",
                    detail="no SMB session (silent TCP accept)",
                )
            )
    return out


def probe_smb(host: str, port: int) -> list[Indicator]:
    if optional_impacket()[0] is None:
        return skip_suite(
            _SMB_SKIP,
            "impacket not installed (pip install honeypot-auditor[full])",
            protocol="smb",
        )

    timeout = max(1, int(settings.timeout_seconds))
    summary = smb_connection_summary(host, port, timeout=timeout)
    if summary.get("login_error") and not summary.get("dialect"):
        return _smb_session_failure_indicator(host, port, summary["login_error"])

    dialect = str(summary.get("dialect") or "")
    native_os = str(summary.get("native_os") or "")
    share_names = list(summary.get("shares") or [])
    smb1 = dialect in SMB_SMB1_DIALECTS or dialect.upper().startswith("SMB 1") or dialect == "1"
    os_hit = any(tell.lower() in native_os.lower() for tell in SMB_NATIVE_OS_TELLS if native_os)
    dialect_hit = smb1 or os_hit

    challenges = collect_ntlm_challenges(host, port, timeout=timeout, count=2)
    challenge_hit = match_smb_static_ntlm_challenge(challenges)

    stock_share_detail, stock_share_requires = match_smb_stock_shares(share_names)
    stock_share_hit = bool(stock_share_detail)

    (pipe_code, pipe_detail, pipe_accepted), (ghost_code, ghost_detail, ghost_accepted) = (
        probe_pipe_and_ghost_share(host, port, timeout=timeout)
    )
    pipe_hit = match_smb_bogus_pipe(pipe_code, pipe_detail, accepted=pipe_accepted)
    pipe_skipped = not pipe_hit and pipe_code is None and "session" in (pipe_detail or "").lower()

    ghost_hit = match_smb_ghost_share(ghost_code, ghost_detail, accepted=ghost_accepted)
    ghost_skipped = (
        not ghost_hit and ghost_code is None and "session" in (ghost_detail or "").lower()
    )

    (low_user, low_pass), (high_user, high_pass) = entropy_varied_creds()
    auth_ok, auth_notes = probe_arbitrary_logins(
        host,
        port,
        timeout=timeout,
        creds=[(low_user, low_pass), (high_user, high_pass)],
    )
    auth_hit = auth_ok == 2
    auth_detail = (
        "two entropy-varied credentials both established an SMB session"
        if auth_hit
        else ("; ".join(auth_notes) if auth_notes else "synthetic logins rejected")
    )

    return [
        Indicator(
            id="smb.arbitrary_auth",
            title="SMB accepts two entropy-varied credentials",
            category="arbitrary_auth",
            triggered=bool(auth_hit),
            protocol="smb",
            detail=auth_detail,
            evidence=f"{low_user},{high_user}" if auth_hit else "; ".join(auth_notes)[:200],
            remediation="Reject unknown credentials instead of accepting any password",
            fidelity="decisive" if auth_hit else "medium",
        ),
        Indicator(
            id="smb.dialect",
            title="SMB dialect / native-OS emulator anomaly",
            category="static_signature",
            triggered=bool(dialect_hit),
            protocol="smb",
            detail=f"dialect={dialect or '?'} native_os={native_os or '?'} shares={share_names[:8]}",
            evidence=f"{dialect}|{native_os}",
        ),
        Indicator(
            id="smb.ntlm_challenge",
            title="NTLM server challenge is static across sessions",
            category="static_signature",
            triggered=bool(challenge_hit),
            skipped=len(challenges) < 2,
            skip_reason="" if len(challenges) >= 2 else "need two NTLM challenges",
            protocol="smb",
            detail=challenge_hit or "NTLM challenges differ across sessions",
            evidence=",".join(c.hex() for c in challenges),
        ),
        Indicator(
            id="smb.stock_shares",
            title="SMB share list matches stock honeypot lure names",
            category="static_signature",
            triggered=bool(stock_share_hit),
            protocol="smb",
            detail=stock_share_detail or "share list does not match stock lure names",
            evidence=",".join(share_names[:12]),
            remediation="Avoid canned lure share names (honey, honeypot, …)",
            requires_corroboration=stock_share_requires,
            fidelity="medium",
        ),
        Indicator(
            id="smb.bogus_pipe",
            title="Bogus IPC$ named pipe NTSTATUS is wrong",
            category="state_nonpersist",
            triggered=bool(pipe_hit),
            skipped=pipe_skipped,
            skip_reason=pipe_detail if pipe_skipped else "",
            protocol="smb",
            detail=pipe_hit or (pipe_detail or "STATUS_OBJECT_NAME_NOT_FOUND on bogus pipe"),
            evidence=f"0x{pipe_code:08X}" if pipe_code is not None else pipe_detail[:160],
        ),
        Indicator(
            id="smb.ghost_share",
            title="Ghost share TREE_CONNECT NTSTATUS is wrong",
            category="state_nonpersist",
            triggered=bool(ghost_hit),
            skipped=ghost_skipped,
            skip_reason=ghost_detail if ghost_skipped else "",
            protocol="smb",
            detail=ghost_hit
            or (ghost_detail or "STATUS_BAD_NETWORK_NAME on ghost share"),
            evidence=f"0x{ghost_code:08X}" if ghost_code is not None else ghost_detail[:160],
            remediation="Return STATUS_BAD_NETWORK_NAME for unknown share TREE_CONNECT",
            fidelity="high" if ghost_hit else "medium",
        ),
        Indicator(
            id="smb.silent_accept",
            title="SMB TCP accepts then returns no protocol response",
            category="static_signature",
            triggered=False,
            protocol="smb",
            detail="SMB session established",
        ),
    ]


def _smb_session_failure_indicator(host: str, port: int, exc: Exception | str) -> list[Indicator]:
    err = str(exc)
    # TCP open + negotiate/session timeout = tarpit / silent SMB face.
    if _looks_like_smb_timeout(err) and _tcp_accepts(host, port):
        return _silent_accept_suite(
            f"TCP accept; SMB/NETBIOS session timed out without a dialect ({err[:120]})"
        )

    framing_anomaly = any(
        tok in err.lower()
        for tok in ("unpack requires", "ntlm", "protocol", "not supported", "connection reset")
    )
    if framing_anomaly:
        return [
            skipped_indicator(
                "smb.arbitrary_auth",
                "SMB accepts two entropy-varied credentials",
                "arbitrary_auth",
                "no SMB session",
                protocol="smb",
            ),
            Indicator(
                id="smb.dialect",
                title="SMB dialect / native-OS emulator anomaly",
                category="static_signature",
                triggered=True,
                protocol="smb",
                detail=f"SMB listener up but session setup failed: {err[:160]}",
                evidence=err[:200],
            ),
            skipped_indicator(
                "smb.ntlm_challenge",
                "NTLM server challenge is static across sessions",
                "static_signature",
                "no SMB session",
                protocol="smb",
            ),
            skipped_indicator(
                "smb.stock_shares",
                "SMB share list matches stock honeypot lure names",
                "static_signature",
                "no SMB session",
                protocol="smb",
            ),
            skipped_indicator(
                "smb.bogus_pipe",
                "Bogus IPC$ named pipe NTSTATUS is wrong",
                "state_nonpersist",
                "no SMB session",
                protocol="smb",
            ),
            skipped_indicator(
                "smb.ghost_share",
                "Ghost share TREE_CONNECT NTSTATUS is wrong",
                "state_nonpersist",
                "no SMB session",
                protocol="smb",
            ),
            Indicator(
                id="smb.silent_accept",
                title="SMB TCP accepts then returns no protocol response",
                category="static_signature",
                triggered=False,
                protocol="smb",
                detail="SMB framing anomaly (not a silent accept)",
            ),
        ]
    raw, _ = tcp_transact(
        host, port, b"", recv_first=True, timeout=min(2.0, settings.timeout_seconds)
    )
    smb_listener = bool(raw) and (raw[:1] == b"\x00" or b"SMB" in raw[:64])
    if not smb_listener:
        return skip_suite(
            _SMB_SKIP,
            f"NTLM session not established: {err[:160]}",
            protocol="smb",
            error=err,
        )
    return [
        skipped_indicator(
            "smb.arbitrary_auth",
            "SMB accepts two entropy-varied credentials",
            "arbitrary_auth",
            "session setup failed",
            protocol="smb",
        ),
        Indicator(
            id="smb.dialect",
            title="SMB dialect / native-OS emulator anomaly",
            category="static_signature",
            triggered=True,
            protocol="smb",
            detail=f"SMB listener up but session setup failed: {err[:160]}",
            evidence=raw[:120].hex() if raw else err[:200],
        ),
        skipped_indicator(
            "smb.ntlm_challenge",
            "NTLM server challenge is static across sessions",
            "static_signature",
            "session setup failed",
            protocol="smb",
        ),
        skipped_indicator(
            "smb.stock_shares",
            "SMB share list matches stock honeypot lure names",
            "static_signature",
            "session setup failed",
            protocol="smb",
        ),
        skipped_indicator(
            "smb.bogus_pipe",
            "Bogus IPC$ named pipe NTSTATUS is wrong",
            "state_nonpersist",
            "session setup failed",
            protocol="smb",
        ),
        skipped_indicator(
            "smb.ghost_share",
            "Ghost share TREE_CONNECT NTSTATUS is wrong",
            "state_nonpersist",
            "session setup failed",
            protocol="smb",
        ),
        Indicator(
            id="smb.silent_accept",
            title="SMB TCP accepts then returns no protocol response",
            category="static_signature",
            triggered=False,
            protocol="smb",
            detail="SMB bytes observed (not a silent accept)",
        ),
    ]
