"""Shared SSH session helpers for deep probes."""

from __future__ import annotations

import secrets
import time

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
        try:
            client.close()
        except Exception:
            pass
        return None, str(exc)
    except Exception as exc:
        try:
            client.close()
        except Exception:
            pass
        return None, str(exc)


def ssh_exec(client, command: str, timeout: float | None = None) -> tuple[str, str, float]:
    """Run command; return (stdout+stderr, error, elapsed_seconds)."""
    if timeout is None:
        timeout = settings.timeout_seconds
    start = time.monotonic()
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
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
