"""Deep probe #1: shell execution semantics and auth-curve analysis."""

from __future__ import annotations

import secrets
import time
from contextlib import suppress

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
        _, sleep_err, sleep_elapsed = ssh_exec(
            client, "sleep 1", timeout=max(3.0, settings.timeout_seconds)
        )
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
        with suppress(Exception):
            client.close()

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
            with suppress(Exception):
                client.close()
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
    data, err = tcp_transact(
        host, port, payload, recv_first=True, timeout=max(5.0, settings.timeout_seconds)
    )
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


def probe_shell_entropy(host: str, port: int) -> list[Indicator]:
    """Check $RANDOM variance and urandom RTT when shell auth succeeds."""
    if settings.safe_mode:
        return [
            skipped_indicator(
                "deep.shell_entropy",
                "Shell entropy / urandom latency anomaly",
                "behavior",
                "safe-mode",
                protocol="ssh",
            )
        ]
    user, password = random_creds()
    client, err = try_ssh_auth(host, port, user, password)
    if client is None:
        return [
            skipped_indicator(
                "deep.shell_entropy",
                "Shell entropy / urandom latency anomaly",
                "behavior",
                closed_reason(err) if err else "auth failed",
                protocol="ssh",
                error=err,
            )
        ]
    random_vals: list[str] = []
    failures: list[str] = []
    try:
        for _ in range(3):
            out, exec_err, _ = ssh_exec(client, "echo $RANDOM")
            if exec_err:
                failures.append(f"random: {exec_err}")
                break
            random_vals.append(out.strip())
        _, base_err, base_t = ssh_exec(client, "echo ok")
        _, urandom_err, urandom_t = ssh_exec(client, "time head -c 512 /dev/urandom 2>&1")
        if base_err:
            failures.append(f"baseline: {base_err}")
        elif urandom_err and "not found" not in urandom_err.lower():
            failures.append(f"urandom: {urandom_err}")
        elif urandom_t < base_t * 0.5 and urandom_t < 0.05:
            failures.append(f"urandom too fast ({urandom_t:.3f}s vs baseline {base_t:.3f}s)")
        if len(random_vals) >= 2 and len(set(random_vals)) == 1:
            failures.append(f"static $RANDOM values: {random_vals}")
    finally:
        with suppress(Exception):
            client.close()
    return [
        Indicator(
            id="deep.shell_entropy",
            title="Shell entropy / urandom latency anomaly",
            category="behavior",
            triggered=bool(failures),
            protocol="ssh",
            detail="; ".join(failures) if failures else "entropy/latency plausible",
            evidence=f"random={random_vals}",
            requires_corroboration=True,
            tell_tier="behavior",
        )
    ]


def probe_mtime_uniformity(host: str, port: int) -> list[Indicator]:
    """Flag directory mtimes clustered within 1s (container bake artifact)."""
    if settings.safe_mode:
        return [
            skipped_indicator(
                "deep.mtime_uniformity",
                "Directory timestamp uniformity",
                "coherence",
                "safe-mode",
                protocol="ssh",
            )
        ]
    user, password = random_creds()
    client, err = try_ssh_auth(host, port, user, password)
    if client is None:
        return [
            skipped_indicator(
                "deep.mtime_uniformity",
                "Directory timestamp uniformity",
                "coherence",
                closed_reason(err) if err else "auth failed",
                protocol="ssh",
                error=err,
            )
        ]
    out, exec_err, _ = ssh_exec(
        client,
        "ls -l --time-style=+%s /etc/passwd /var/log /usr/bin 2>/dev/null | awk '{print $6}'",
    )
    with suppress(Exception):
        client.close()
    if exec_err or not out.strip():
        return [
            skipped_indicator(
                "deep.mtime_uniformity",
                "Directory timestamp uniformity",
                "coherence",
                exec_err or "no stat output",
                protocol="ssh",
            )
        ]
    stamps = [ln.strip() for ln in out.splitlines() if ln.strip().isdigit()]
    triggered = False
    detail = "mtime spread plausible"
    if len(stamps) >= 3:
        vals = [int(s) for s in stamps[:6]]
        if max(vals) - min(vals) <= 1:
            triggered = True
            detail = f"mtimes cluster within 1s: {vals}"
    return [
        Indicator(
            id="deep.mtime_uniformity",
            title="Directory timestamp uniformity",
            category="coherence",
            triggered=triggered,
            protocol="ssh",
            detail=detail,
            evidence=out[:500],
            remediation="Vary file mtimes in container bake or use realistic filesystem layers",
            tell_tier="behavior",
        )
    ]


def probe_llm_hallucination(host: str, port: int) -> list[Indicator]:
    """Experimental: flag plausible fake success on invalid commands (LLM decoys)."""
    if settings.safe_mode or not settings.deep:
        return [
            skipped_indicator(
                "deep.llm_hallucination",
                "LLM hallucination probe (experimental)",
                "behavior",
                "requires --deep and not --safe-mode",
                protocol="ssh",
            )
        ]
    user, password = random_creds()
    client, err = try_ssh_auth(host, port, user, password)
    if client is None:
        return [
            skipped_indicator(
                "deep.llm_hallucination",
                "LLM hallucination probe (experimental)",
                "behavior",
                closed_reason(err) if err else "auth failed",
                protocol="ssh",
                error=err,
            )
        ]
    probes = (
        "cat /sys/kernel/debug/nonexistent_hpaudit_99887",
        "ls --fake-flag-x99",
    )
    failures: list[str] = []
    evidence: list[str] = []
    try:
        for cmd in probes:
            out, exec_err, _ = ssh_exec(client, cmd)
            evidence.append(f"{cmd}: {out[:120]!r} err={exec_err!r}")
            text = out.lower()
            if "no such file" in text or "unrecognized" in text or "invalid" in text:
                continue
            if out.strip() and "error" not in text and exec_err == "":
                failures.append(f"plausible fake success for {cmd!r}")
    finally:
        with suppress(Exception):
            client.close()
    return [
        Indicator(
            id="deep.llm_hallucination",
            title="LLM hallucination probe (experimental)",
            category="behavior",
            triggered=bool(failures),
            protocol="ssh",
            detail="; ".join(failures) if failures else "errors look standard",
            evidence="\n".join(evidence)[:1500],
            requires_corroboration=True,
            tell_tier="behavior",
        )
    ]
