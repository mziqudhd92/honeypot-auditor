"""Git-daemon fingerprint engine.

Strategies: static signature (git-upload-pack always ERR no such repository).
Arbitrary auth and state non-persistence are not on the basic path.
"""

from __future__ import annotations

from honeypot_auditor.config import match_git_always_missing
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import skip_suite

_GIT_SKIP = (
    ("git.signature", "Git daemon always ERR no such repository", "static_signature"),
)


def _git_pkt(payload: bytes) -> bytes:
    return f"{len(payload) + 4:04x}".encode("ascii") + payload


def probe_git(host: str, port: int) -> list[Indicator]:
    inner = b"git-upload-pack /hpaudit.git\0host=auditor.invalid\0"
    raw, err = tcp_transact(host, port, _git_pkt(inner))
    if err and not raw:
        return skip_suite(_GIT_SKIP, closed_reason(err), protocol="git", error=err)
    text = raw.decode("utf-8", "replace")
    if not text.strip():
        return skip_suite(_GIT_SKIP, "not a git-daemon speaker", protocol="git")
    hit = match_git_always_missing(text)
    return [
        Indicator(
            id="git.signature",
            title="Git daemon always ERR no such repository",
            category="static_signature",
            triggered=bool(hit),
            protocol="git",
            detail=hit or text.strip()[:160],
            evidence=text[:400],
        )
    ]
