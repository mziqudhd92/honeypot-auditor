"""Shared SSH session helpers for deep probes."""

from __future__ import annotations

import secrets
import time
from contextlib import suppress

from honeypot_auditor.config import PROBE_PASSWORD_TEMPLATE, PROBE_USERNAME_TEMPLATE
from honeypot_auditor.models import optional_import
from honeypot_auditor.settings import settings


def random_creds() -> tuple[str, str]:
    n = 10 + secrets.randbelow(89)
    return PROBE_USERNAME_TEMPLATE.format(n=n), PROBE_PASSWORD_TEMPLATE.format(n=n + 69)


def try_ssh_auth(host: str, port: int, user: str, password: str):
    paramiko = optional_import("paramiko")
    if paramiko is None:
        return None, "paramiko not installed"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=user,
            password=password,
            timeout=settings.timeout_seconds,
            banner_timeout=settings.timeout_seconds,
            auth_timeout=settings.timeout_seconds,
            allow_agent=False,
            look_for_keys=False,
        )
        return client, ""
    except paramiko.AuthenticationException as exc:
        with suppress(Exception):
            client.close()
        return None, str(exc)
    except Exception as exc:
        with suppress(Exception):
            client.close()
        return None, str(exc)


def probe_ssh_auth_methods(
    host: str, port: int, username: str = "root"
) -> tuple[list[str], str, str]:
    """Return (methods, banner, error) via SSH USERAUTH none (no credentials tried)."""
    paramiko = optional_import("paramiko")
    if paramiko is None:
        return [], "", "paramiko not installed"
    from honeypot_auditor.proxy_transport import paramiko_proxy_sock

    transport = None
    try:
        sock = paramiko_proxy_sock(host, port, settings.timeout_seconds)
        if sock is not None:
            transport = paramiko.Transport(sock)
        else:
            transport = paramiko.Transport((host, port))
        transport.banner_timeout = settings.timeout_seconds
        transport.auth_timeout = settings.timeout_seconds
        transport.start_client(timeout=settings.timeout_seconds)
        banner = transport.remote_version or ""
        try:
            transport.auth_none(username)
            # Rare: none auth succeeded — treat as empty method list with note via banner path.
            return ["none"], banner, ""
        except paramiko.BadAuthenticationType as exc:
            methods = [str(m) for m in (exc.allowed_types or [])]
            return methods, banner, ""
        except paramiko.AuthenticationException:
            # Some servers reject none without advertising alternatives.
            return [], banner, ""
    except Exception as exc:
        return [], "", str(exc)
    finally:
        if transport is not None:
            with suppress(Exception):
                transport.close()


def ssh_exec(client, command: str, timeout: float | None = None) -> tuple[str, str, float]:
    """Run command; return (stdout+stderr, error, elapsed_seconds)."""
    if timeout is None:
        timeout = settings.timeout_seconds
    start = time.monotonic()
    try:
        # Callers supply fixed audit commands; target output never reaches this argument.
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)  # nosec B601
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        return (out or err).strip(), "", time.monotonic() - start
    except Exception as exc:
        return "", str(exc), time.monotonic() - start


def ssh_banner(client) -> str:
    try:
        transport = client.get_transport()
        return (transport.remote_version or "") if transport else ""
    except Exception:
        return ""
