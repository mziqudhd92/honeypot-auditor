"""Deep probe #1: shell execution semantics and auth-curve analysis."""

from __future__ import annotations

import secrets
import time

from honeypot_auditor.config import PROBE_PASSWORD_TEMPLATE, PROBE_USERNAME_TEMPLATE
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.settings import settings
from honeypot_auditor.sshutil import random_creds, ssh_exec, try_ssh_auth

_SEMANTIC_COMMANDS = (
    ("arith", "echo $((73*41))", "2993"),
    ("brace", "echo {1..3}", "1 2 3"),
    ("random", "echo $RANDOM", None),
    ("pid", "echo $$", None),
)


def probe_shell_semantics(host: str, port: int) -> list[Indicator]:
    user, password = random_creds()
    client, err = try_ssh_auth(host, port, user, password)
    if client is None:
        reason = closed_reason(err) if err else "auth failed"
        return [
            skipped_indicator(
                "deep.shell_semantics",
                "Shell execution semantics inconsistent with real OS",
                "behavior",
                reason,
                protocol="ssh",
                error=err,
            )
        ]

    failures: list[str] = []
    evidence_parts: list[str] = []
    random_values: list[str] = []
    try:
        for name, cmd, expected in _SEMANTIC_COMMANDS:
            out, exec_err, elapsed = ssh_exec(client, cmd)
            evidence_parts.append(f"{name}: {out[:80]!r} err={exec_err!r} t={elapsed:.3f}s")
            if exec_err or "channel" in exec_err.lower():
                failures.append(f"{name}: exec failed ({exec_err or 'channel closed'})")
                continue
            if expected and expected not in out.replace("\n", " "):
                failures.append(f"{name}: expected {expected!r}, got {out[:60]!r}")
            if name == "random" and out.strip().isdigit():
                random_values.append(out.strip())
        # sleep timing check
        _, sleep_err, sleep_elapsed = ssh_exec(client, "sleep 1", timeout=max(3.0, settings.timeout_seconds))
        evidence_parts.append(f"sleep: t={sleep_elapsed:.3f}s err={sleep_err!r}")
        if sleep_err:
            failures.append(f"sleep: exec failed ({sleep_err})")
        elif sleep_elapsed < 0.55:
            failures.append(f"sleep: returned in {sleep_elapsed:.2f}s (instant fake sleep)")
        # cross-session state (same connection)
        token = secrets.token_hex(4)
        write_out, w_err, _ = ssh_exec(client, f"echo {token} > /tmp/hpaudit_{token}")
        read_out, r_err, _ = ssh_exec(client, f"cat /tmp/hpaudit_{token}")
        evidence_parts.append(f"state: write={write_out!r} read={read_out!r}")
        if w_err or r_err or token not in read_out:
            failures.append("state: /tmp write/read failed in-session")
        if len(random_values) >= 2 and random_values[0] == random_values[1]:
            failures.append("random: identical values across calls")
    finally:
        try:
            client.close()
        except Exception:
            pass

    triggered = bool(failures) and (
        any("exec failed" in f or "channel" in f for f in failures) or len(failures) >= 2
    )
    detail = "; ".join(failures[:4]) if failures else "shell semantics look coherent"
    return [
        Indicator(
            id="deep.shell_semantics",
            title="Shell execution semantics inconsistent with real OS",
            category="behavior",
            triggered=triggered,
            protocol="ssh",
            detail=detail,
            evidence="\n".join(evidence_parts)[:2000],
        )
    ]


def probe_auth_curve(host: str, port: int, attempts: int = 5) -> list[Indicator]:
    """Behavioral/temporal: map when arbitrary credentials start succeeding."""
    successes: list[int] = []
    for i in range(attempts):
        n = 10 + secrets.randbelow(89) + i
        user = PROBE_USERNAME_TEMPLATE.format(n=n)
        password = PROBE_PASSWORD_TEMPLATE.format(n=n + 69)
        client, err = try_ssh_auth(host, port, user, password)
        if client is not None:
            successes.append(i + 1)
            try:
                client.close()
            except Exception:
                pass
        time.sleep(0.05)

    first_success = successes[0] if successes else 0
    # Immediate any-password on attempt 1 is classic honeypot; never is real-ish.
    triggered = first_success == 1 and len(successes) >= 2
    detail = (
        f"random creds accepted on attempts {successes}"
        if successes
        else "no random credential accepted across probe curve"
    )
    return [
        Indicator(
            id="deep.auth_curve",
            title="Auth engagement curve suggests honeypot any-password policy",
            category="temporal",
            triggered=triggered,
            protocol="ssh",
            detail=detail,
            evidence=f"attempts={attempts} successes={successes}",
        )
    ]


def probe_telnet_shell_semantics(host: str, port: int) -> list[Indicator]:
    user, password = random_creds()
    payload = (
        user.encode()
        + b"\r\n"
        + password.encode()
        + b"\r\n"
        + b"echo $((73*41))\r\n"
        + b"sleep 1\r\n"
        + b"echo done\r\n"
    )
    start = time.monotonic()
    data, err = tcp_transact(host, port, payload, recv_first=True, timeout=max(5.0, settings.timeout_seconds))
    elapsed = time.monotonic() - start
    if err and not data:
        return [
            skipped_indicator(
                "deep.telnet_shell_semantics",
                "Telnet shell semantics inconsistent with real OS",
                "behavior",
                closed_reason(err),
                protocol="telnet",
                error=err,
            )
        ]
    text = data.decode("utf-8", "replace")
    failures = []
    if "2993" not in text:
        failures.append("arithmetic expansion missing/wrong")
    if elapsed < 0.8 and "done" in text.lower():
        failures.append(f"sleep completed in {elapsed:.2f}s (too fast)")
    if not text.strip():
        return [
            skipped_indicator(
                "deep.telnet_shell_semantics",
                "Telnet shell semantics inconsistent with real OS",
                "behavior",
                "no telnet banner/session data",
                protocol="telnet",
            )
        ]
    if any(x in text.lower() for x in ("login incorrect", "authentication failed")):
        return [
            skipped_indicator(
                "deep.telnet_shell_semantics",
                "Telnet shell semantics inconsistent with real OS",
                "behavior",
                "auth failed",
                protocol="telnet",
            )
        ]
    has_shell = any(x in text for x in ("$ ", "# ", ":~$", "~$")) or "2993" in text
    triggered = has_shell and bool(failures)
    return [
        Indicator(
            id="deep.telnet_shell_semantics",
            title="Telnet shell semantics inconsistent with real OS",
            category="behavior",
            triggered=triggered,
            protocol="telnet",
            detail="; ".join(failures) if failures else "telnet session output looks coherent",
            evidence=text[:1500],
        )
    ]
