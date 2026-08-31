"""SMB fingerprint engine.

Strategies: static signature (SMB1/EOL native_os, static NTLM challenge) ·
state non-persistence (bogus pipe NTSTATUS). Arbitrary auth is not on the basic path.
"""

from __future__ import annotations

from honeypot_auditor.config import (
    SMB_NATIVE_OS_TELLS,
    SMB_SMB1_DIALECTS,
    match_smb_bogus_pipe,
    match_smb_static_ntlm_challenge,
)
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import skip_suite
from honeypot_auditor.settings import settings
from honeypot_auditor.smbutil import (
    collect_ntlm_challenges,
    optional_impacket,
    probe_bogus_pipe,
    smb_connection_summary,
)

_SMB_SKIP = (
    ("smb.dialect", "SMB dialect / native-OS emulator anomaly", "static_signature"),
    ("smb.ntlm_challenge", "NTLM server challenge is static across sessions", "static_signature"),
    ("smb.bogus_pipe", "Bogus IPC$ named pipe NTSTATUS is wrong", "state_nonpersist"),
)


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

    pipe_code, pipe_detail, pipe_accepted = probe_bogus_pipe(host, port, timeout=timeout)
    pipe_hit = match_smb_bogus_pipe(pipe_code, pipe_detail, accepted=pipe_accepted)
    pipe_skipped = not pipe_hit and pipe_code is None and "session" in (pipe_detail or "").lower()

    return [
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
    ]


def _smb_session_failure_indicator(host: str, port: int, exc: Exception | str) -> list[Indicator]:
    err = str(exc)
    framing_anomaly = any(
        tok in err.lower()
        for tok in ("unpack requires", "ntlm", "protocol", "not supported", "connection reset")
    )
    if framing_anomaly:
        return [
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
                "smb.bogus_pipe",
                "Bogus IPC$ named pipe NTSTATUS is wrong",
                "state_nonpersist",
                "no SMB session",
                protocol="smb",
            ),
        ]
    raw, _ = tcp_transact(host, port, b"", recv_first=True, timeout=min(2.0, settings.timeout_seconds))
    smb_listener = bool(raw) and (raw[:1] == b"\x00" or b"SMB" in raw[:64])
    if not smb_listener:
        return skip_suite(
            _SMB_SKIP,
            f"NTLM session not established: {err[:160]}",
            protocol="smb",
            error=err,
        )
    return [
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
            "smb.bogus_pipe",
            "Bogus IPC$ named pipe NTSTATUS is wrong",
            "state_nonpersist",
            "session setup failed",
            protocol="smb",
        ),
    ]
