"""SSH fingerprint engine.

Strategies: arbitrary auth (any-password) · state non-persistence (exec vs PTY, /tmp canary) ·
static signature (banner, whoami, honeyfs) · pre-auth KEX facade (password-gated Cowrie/Twisted).
"""

from __future__ import annotations

import json
import secrets
import time
from contextlib import suppress

from honeypot_auditor.config import match_ssh_banner
from honeypot_auditor.hassh import capture_server_kexinit, hassh_algo_mismatch
from honeypot_auditor.models import Indicator, optional_import, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import is_safe_mode, random_creds, skip_suite
from honeypot_auditor.probes.shell_cti import (
    CTI_SHELL_COMMANDS,
    identity_tells,
    whoami_matches_lure,
)
from honeypot_auditor.proxy_transport import paramiko_proxy_sock
from honeypot_auditor.settings import settings
from honeypot_auditor.sshutil import probe_ssh_auth_methods, try_ssh_auth

_SSH_SKIP = (
    ("ssh.banner", "SSH static banner signature", "static_signature"),
    ("ssh.kex_facade", "SSH OpenSSH banner with Twisted/Cowrie KEX facade", "static_signature"),
    ("ssh.password_only", "SSH OpenSSH banner advertises password-only auth", "static_signature"),
    ("ssh.arbitrary_auth", "SSH arbitrary credential acceptance", "arbitrary_auth"),
    (
        "ssh.exec_denied",
        "SSH exec channel missing after login (fake shell only)",
        "state_nonpersist",
    ),
    ("ssh.uname", "SSH uname/cpuinfo / Cowrie identity", "static_signature"),
    ("ssh.whoami", "SSH whoami/prompt is the random lure account", "static_signature"),
    ("ssh.session_persist", "SSH filesystem does not persist across sessions", "state_nonpersist"),
)

_CLIENT_BANNER = b"SSH-2.0-honeypot_auditor_1.0\r\n"


def _capture_ssh_handshake(host: str, port: int) -> tuple[str, object | None, bytes, str]:
    """Pre-auth banner + KEXINIT (no credentials). Returns banner, kex, raw, err."""
    raw, err = tcp_transact(
        host,
        port,
        _CLIENT_BANNER,
        recv_first=True,
        timeout=max(4.0, settings.timeout_seconds),
        max_bytes=16384,
    )
    banner, kex = capture_server_kexinit(raw or b"")
    return banner, kex, raw or b"", err


def _password_only_indicator(banner: str, methods: list[str], err: str) -> Indicator:
    """Modern OpenSSH almost always offers publickey; password-only is a common lure."""
    if err and not methods:
        return skipped_indicator(
            "ssh.password_only",
            "SSH OpenSSH banner advertises password-only auth",
            "static_signature",
            closed_reason(err),
            protocol="ssh",
            error=err,
        )
    low_methods = {m.lower() for m in methods}
    openssh = "openssh" in (banner or "").lower()
    password_only = openssh and low_methods == {"password"}
    detail = (
        f"OpenSSH banner offers only password auth ({', '.join(methods) or 'none'})"
        if password_only
        else f"auth methods={', '.join(methods) or '(none advertised)'}; banner={banner or '?'}"
    )
    return Indicator(
        id="ssh.password_only",
        title="SSH OpenSSH banner advertises password-only auth",
        category="static_signature",
        triggered=password_only,
        protocol="ssh",
        detail=detail,
        evidence=json.dumps({"banner": banner, "methods": methods}),
        remediation="Offer publickey (and/or keyboard-interactive) like real OpenSSH, not password alone",
    )


def _kex_facade_indicator(banner: str, kex: object | None, raw: bytes) -> Indicator:
    if kex is None:
        return Indicator(
            id="ssh.kex_facade",
            title="SSH OpenSSH banner with Twisted/Cowrie KEX facade",
            category="static_signature",
            triggered=False,
            protocol="ssh",
            detail=f"no KEXINIT captured; banner={banner or '?'}",
            evidence=json.dumps({"banner": banner}),
            fingerprint_type="ssh_hassh",
        )
    triggered, detail = hassh_algo_mismatch(banner, kex)  # type: ignore[arg-type]
    evidence = {
        "banner": banner,
        "hassh_server": getattr(kex, "hassh_server", ""),
        "kex": (getattr(kex, "kex", "") or "")[:160],
        "host_key": (getattr(kex, "host_key", "") or "")[:120],
        "enc_s2c": (getattr(kex, "enc_s2c", "") or "")[:120],
        "mac_s2c": (getattr(kex, "mac_s2c", "") or "")[:80],
    }
    return Indicator(
        id="ssh.kex_facade",
        title="SSH OpenSSH banner with Twisted/Cowrie KEX facade",
        category="static_signature",
        triggered=triggered,
        protocol="ssh",
        detail=detail,
        evidence=json.dumps(evidence),
        fingerprint_type="ssh_hassh",
        remediation="Align KEXINIT host keys / AEAD ciphers / ETM MACs with the claimed OpenSSH version",
    )


def probe_ssh(host: str, port: int) -> list[Indicator]:
    if is_safe_mode():
        return _probe_ssh_safe(host, port)
    paramiko = optional_import("paramiko")
    if paramiko is None:
        return skip_suite(_SSH_SKIP, "paramiko not installed", protocol="ssh")

    # Pre-auth KEX facade (password-gated Cowrie still leaks Twisted suite shape).
    hs_banner, hs_kex, hs_raw, hs_err = _capture_ssh_handshake(host, port)
    kex_ind = _kex_facade_indicator(hs_banner, hs_kex, hs_raw)
    auth_methods, auth_banner, auth_meth_err = probe_ssh_auth_methods(host, port)
    password_only_ind = _password_only_indicator(
        auth_banner or hs_banner, auth_methods, auth_meth_err
    )

    user, password = random_creds()
    user2, password2 = random_creds()
    canary = secrets.token_hex(4)
    # This is a path on the explicitly authorized remote target, not a local temp file.
    canary_path = f"/tmp/hpaudit_{canary}"  # nosec B108
    banner = hs_banner
    auth_ok = False
    auth2_ok = False
    uname = ""
    cpuinfo = ""
    transcript = ""
    persist_out = ""
    err = hs_err if (hs_err and not hs_raw) else ""
    client = paramiko.SSHClient()
    # This is a host-key fingerprinting probe, not a trusted SSH client session.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": user,
        "password": password,
        "timeout": settings.timeout_seconds,
        "banner_timeout": settings.timeout_seconds,
        "auth_timeout": settings.timeout_seconds,
        "allow_agent": False,
        "look_for_keys": False,
    }
    proxy_sock = paramiko_proxy_sock(host, port, settings.timeout_seconds)
    if proxy_sock is not None:
        connect_kwargs["sock"] = proxy_sock
    try:
        try:
            client.connect(**connect_kwargs)
            auth_ok = True
        except paramiko.AuthenticationException:
            auth_ok = False
        except Exception as exc:
            err = str(exc)
        transport = client.get_transport()
        if transport is not None:
            banner = transport.remote_version or banner
        if auth_ok:
            uname = _ssh_exec(client, "uname -a")
            cpuinfo = _ssh_exec(client, "cat /proc/cpuinfo")
            cti_cmds = list(CTI_SHELL_COMMANDS) + [
                f"echo {canary} > {canary_path}",
                f"cat {canary_path}",
            ]
            if _exec_looks_denied(uname) or _exec_looks_denied(cpuinfo):
                transcript = _ssh_interactive(client, cti_cmds)
            else:
                chunks = [uname, cpuinfo]
                for cmd in CTI_SHELL_COMMANDS:
                    chunks.append(_ssh_exec(client, cmd))
                chunks.append(_ssh_exec(client, f"echo {canary} > {canary_path}"))
                chunks.append(_ssh_exec(client, f"cat {canary_path}"))
                transcript = "\n".join(chunks)
    except Exception as exc:
        err = str(exc)
    finally:
        with suppress(Exception):
            client.close()

    if err and not banner and not hs_raw:
        return skip_suite(_SSH_SKIP, closed_reason(err), protocol="ssh", error=err)

    if auth_ok:
        client2, _auth2_err = try_ssh_auth(host, port, user2, password2)
        auth2_ok = client2 is not None
        if client2 is not None:
            persist_out = _ssh_exec(client2, f"cat {canary_path}")
            if _exec_looks_denied(persist_out):
                persist_out += "\n" + _ssh_interactive(client2, [f"cat {canary_path}"])
            with suppress(Exception):
                client2.close()

    exec_denied = auth_ok and (_exec_looks_denied(uname) or _exec_looks_denied(cpuinfo))
    identity_src = "\n".join(p for p in (uname, cpuinfo, transcript) if p)
    id_bits = identity_tells(identity_src)
    whoami_hit = auth_ok and whoami_matches_lure(transcript or identity_src, user)
    persist_missing = bool(auth_ok and auth2_ok and canary and canary not in persist_out)

    auth_detail = (
        f"random {user}:**** accepted"
        + (
            f"; 2nd login {user2}:**** also accepted"
            if auth2_ok
            else "; 2nd random login not accepted"
        )
        if auth_ok
        else f"random {user}:**** rejected (not an any-password handler)"
    )

    return [
        Indicator(
            id="ssh.banner",
            title="SSH static banner signature",
            category="static_signature",
            triggered=bool(match_ssh_banner(banner)),
            protocol="ssh",
            detail=banner or "(no banner)",
            evidence=match_ssh_banner(banner) or "",
        ),
        kex_ind,
        password_only_ind,
        Indicator(
            id="ssh.arbitrary_auth",
            title="SSH arbitrary credential acceptance",
            category="arbitrary_auth",
            triggered=auth_ok and auth2_ok,
            protocol="ssh",
            detail=auth_detail,
            evidence=f"{user},{user2}" if auth2_ok else user,
        ),
        Indicator(
            id="ssh.exec_denied",
            title="SSH exec channel missing after login (fake shell only)",
            category="state_nonpersist",
            triggered=exec_denied,
            protocol="ssh",
            skipped=not auth_ok,
            skip_reason="" if auth_ok else "no session (auth failed)",
            detail=(
                "exec_command failed after random login; interactive shell is a lure"
                if exec_denied
                else "exec_command available after login"
            ),
            evidence=(uname + "\n" + cpuinfo)[:800],
        )
        if auth_ok
        else skipped_indicator(
            "ssh.exec_denied",
            "SSH exec channel missing after login (fake shell only)",
            "state_nonpersist",
            "no session (auth failed)",
            protocol="ssh",
        ),
        Indicator(
            id="ssh.uname",
            title="SSH uname/cpuinfo / Cowrie identity",
            category="static_signature",
            triggered=bool(id_bits),
            protocol="ssh",
            skipped=not auth_ok,
            skip_reason="" if auth_ok else "no session (auth failed)",
            detail="; ".join(id_bits) if id_bits else (identity_src[:240] or "no identity output"),
            evidence=identity_src[:1500],
        )
        if auth_ok
        else skipped_indicator(
            "ssh.uname",
            "SSH uname/cpuinfo / Cowrie identity",
            "static_signature",
            "no session (auth failed)",
            protocol="ssh",
        ),
        Indicator(
            id="ssh.whoami",
            title="SSH whoami/prompt is the random lure account",
            category="static_signature",
            triggered=whoami_hit,
            protocol="ssh",
            skipped=not auth_ok,
            skip_reason="" if auth_ok else "no session (auth failed)",
            detail=(
                f"session identity is lure account {user}"
                if whoami_hit
                else f"lure account {user} not reflected in whoami/prompt"
            ),
            evidence=transcript[:800],
        )
        if auth_ok
        else skipped_indicator(
            "ssh.whoami",
            "SSH whoami/prompt is the random lure account",
            "static_signature",
            "no session (auth failed)",
            protocol="ssh",
        ),
        Indicator(
            id="ssh.session_persist",
            title="SSH filesystem does not persist across sessions",
            category="state_nonpersist",
            triggered=persist_missing,
            protocol="ssh",
            skipped=not (auth_ok and auth2_ok),
            skip_reason="" if (auth_ok and auth2_ok) else "need two sessions to verify persist",
            detail=(
                f"wrote {canary_path} then new login could not read it"
                if persist_missing
                else (
                    f"canary {canary} still present after reconnect"
                    if auth2_ok
                    else "2nd session failed"
                )
            ),
            evidence=persist_out[:400],
        )
        if auth_ok and auth2_ok
        else skipped_indicator(
            "ssh.session_persist",
            "SSH filesystem does not persist across sessions",
            "state_nonpersist",
            "need two sessions to verify persist",
            protocol="ssh",
        ),
    ]


def _exec_looks_denied(text: str) -> bool:
    low = (text or "").lower()
    return low.startswith("(exec failed:") or "channel closed" in low


def _ssh_exec(client, command: str) -> str:
    try:
        # Callers supply only fixed probe commands and hex-generated canary paths.
        _stdin, stdout, stderr = client.exec_command(  # nosec B601
            command, timeout=settings.timeout_seconds
        )
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        return (out or err).strip()
    except Exception as exc:
        return f"(exec failed: {exc})"


def _ssh_interactive(client, commands: list[str]) -> str:
    """Cowrie-style lures often reject exec_command but still offer a fake PTY shell."""
    try:
        chan = client.invoke_shell(term="vt100", width=80, height=24)
    except Exception as exc:
        return f"(shell failed: {exc})"
    buf = bytearray()
    try:
        with suppress(Exception):
            chan.settimeout(1.0)
            deadline = time.monotonic() + min(8.0, max(3.0, settings.timeout_seconds * 2.0))
            for cmd in commands:
                sent = False
                while time.monotonic() < deadline:
                    if chan.recv_ready():
                        buf.extend(chan.recv(4096))
                        continue
                    if not sent:
                        chan.send(cmd + "\n")
                        sent = True
                        time.sleep(0.15)
                        continue
                    time.sleep(0.05)
                    if not chan.recv_ready():
                        break
            if chan.recv_ready():
                buf.extend(chan.recv(8192))
    finally:
        with suppress(Exception):
            chan.close()
    return buf.decode("utf-8", "replace")


def _probe_ssh_safe(host: str, port: int) -> list[Indicator]:
    """Safe mode: banner + KEX facade only — no auth or shell commands."""
    banner, kex, raw, err = _capture_ssh_handshake(host, port)
    if err and not raw:
        return skip_suite(_SSH_SKIP, closed_reason(err), protocol="ssh", error=err)
    sig = match_ssh_banner(banner)
    skipped = [
        skipped_indicator(i, title, cat, "safe-mode: handshake-only", protocol="ssh")
        for i, title, cat in _SSH_SKIP
        if i not in ("ssh.banner", "ssh.kex_facade", "ssh.password_only")
    ]
    methods, auth_banner, auth_err = probe_ssh_auth_methods(host, port)
    return [
        Indicator(
            id="ssh.banner",
            title="SSH static banner signature",
            category="static_signature",
            triggered=bool(sig),
            protocol="ssh",
            detail=banner or "(no banner)",
            evidence=raw[:800].decode("utf-8", "replace"),
        ),
        _kex_facade_indicator(banner, kex, raw),
        _password_only_indicator(auth_banner or banner, methods, auth_err),
        *skipped,
    ]
