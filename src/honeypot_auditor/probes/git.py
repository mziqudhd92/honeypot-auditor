"""Git-daemon fingerprint engine.

Strategies: arbitrary auth (any-repo façade), state non-persistence
(capability lie / inconsistent ERR), static signature (always-missing ERR).
"""

from __future__ import annotations

import re
import secrets

from honeypot_auditor.config import match_git_always_missing
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_roundtrips, tcp_transact
from honeypot_auditor.probes.common import (
    entropy_varied_creds,
    is_safe_mode,
    jittered_reconnect_pause,
    skip_suite,
)

_GIT_SKIP = (
    ("git.arbitrary_auth", "Git daemon advertises refs for nonexistent repos", "arbitrary_auth"),
    (
        "git.state_nonpersist",
        "Git advertised upload-pack capabilities fail on follow-up",
        "state_nonpersist",
    ),
    ("git.signature", "Git daemon always ERR no such repository", "static_signature"),
)

_CAPS = ("multi_ack", "thin-pack", "side-band-64k")
_AD_RE = re.compile(rb"(?i)#\s*service=git-upload-pack")
_ERR_RE = re.compile(rb"(?i)\bERR\b")


def _git_pkt(payload: bytes) -> bytes:
    return f"{len(payload) + 4:04x}".encode("ascii") + payload


def _repo_path(label: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "", label)[:20] or "hpa"
    return f"/{safe}-{secrets.token_hex(2)}.git"


def _upload_pack_req(repo: str) -> bytes:
    inner = f"git-upload-pack {repo}\0host=auditor.invalid\0".encode("utf-8")
    return _git_pkt(inner)


def _is_advertisement(raw: bytes) -> bool:
    return bool(raw) and bool(_AD_RE.search(raw)) and not _ERR_RE.search(raw[:80])


def _is_err(raw: bytes) -> bool:
    return bool(raw) and bool(_ERR_RE.search(raw))


def _claimed_caps(raw: bytes) -> list[str]:
    text = raw.decode("utf-8", "replace").lower()
    return [c for c in _CAPS if c in text]


def _want_negotiate(caps: list[str]) -> bytes:
    """Minimal want/have negotiation referencing advertised capabilities."""
    cap_str = " ".join(caps) if caps else "multi_ack"
    fake = "0" * 40
    want = f"want {fake} {cap_str}\n".encode("ascii")
    return _git_pkt(want) + b"0000" + _git_pkt(b"done\n")


def probe_git(host: str, port: int) -> list[Indicator]:
    # Signature baseline on a fixed nonexistent path (preserves match_git_always_missing).
    sig_raw, sig_err = tcp_transact(host, port, _upload_pack_req("/hpaudit.git"))
    if sig_err and not sig_raw:
        return skip_suite(_GIT_SKIP, closed_reason(sig_err), protocol="git", error=sig_err)
    text = sig_raw.decode("utf-8", "replace")
    if not text.strip():
        return skip_suite(_GIT_SKIP, "not a git-daemon speaker", protocol="git")

    if is_safe_mode():
        hit = match_git_always_missing(text)
        out: list[Indicator] = []
        for iid, title, cat in _GIT_SKIP:
            if iid == "git.signature":
                out.append(
                    Indicator(
                        id=iid,
                        title=title,
                        category=cat,
                        triggered=bool(hit),
                        protocol="git",
                        detail=hit or text.strip()[:160],
                        evidence=text[:400],
                    )
                )
            else:
                out.extend(
                    skip_suite(
                        ((iid, title, cat),),
                        "safe-mode: handshake-only probe",
                        protocol="git",
                    )
                )
        return out

    low, high = entropy_varied_creds()
    repo_a = _repo_path(low[0])
    repo_b = _repo_path(high[0])
    raw_a, err_a = tcp_transact(host, port, _upload_pack_req(repo_a))
    raw_b, err_b = tcp_transact(host, port, _upload_pack_req(repo_b))

    ad_a = _is_advertisement(raw_a)
    ad_b = _is_advertisement(raw_b)
    err_only_a = _is_err(raw_a)
    err_only_b = _is_err(raw_b)
    auth_hit = ad_a and ad_b
    auth_detail = (
        f"both nonexistent repos advertised upload-pack ({repo_a}, {repo_b})"
        if auth_hit
        else (
            "nonexistent repos returned ERR (not an any-repo façade)"
            if err_only_a and err_only_b
            else f"mixed replies for {repo_a}/{repo_b}"
        )
    )
    auth_skipped = (bool(err_a) and not raw_a) and (bool(err_b) and not raw_b)

    # --- state ---
    state_hit = False
    state_detail = "no capability lie or inconsistent ERR observed"
    state_evidence = ""
    ads_raw = raw_a if ad_a else (raw_b if ad_b else b"")
    caps = _claimed_caps(ads_raw) if ads_raw else []

    if caps and ads_raw:
        # want/done must follow the advertisement on the same TCP session.
        # A fresh connection that only sends `want` is not a capability check.
        session_repo = repo_a if ad_a else repo_b
        replies, _neg_err = tcp_roundtrips(
            host,
            port,
            [_upload_pack_req(session_repo), _want_negotiate(caps)],
        )
        neg_raw = replies[1] if len(replies) > 1 else b""
        if _is_err(neg_raw) or (neg_raw and b"ERR" in neg_raw.upper()):
            state_hit = True
            state_detail = (
                f"advertised {','.join(caps)} but same-session negotiation returned ERR/canned failure"
            )
            state_evidence = neg_raw[:300].decode("utf-8", "replace")
        elif not neg_raw:
            state_hit = True
            state_detail = (
                f"advertised {','.join(caps)} but same-session negotiation produced no pack data"
            )
    elif ad_a or ad_b:
        # First looked like advertisement; re-check after jitter — ERR is inconsistent.
        jittered_reconnect_pause()
        re_repo = repo_a if ad_a else repo_b
        re_raw, _ = tcp_transact(host, port, _upload_pack_req(re_repo))
        if _is_err(re_raw):
            state_hit = True
            state_detail = (
                f"repo {re_repo} advertised refs then returned ERR after reconnect"
            )
            state_evidence = re_raw[:300].decode("utf-8", "replace")
    elif err_only_a and err_only_b and raw_a and raw_b:
        jittered_reconnect_pause()
        re_a, _ = tcp_transact(host, port, _upload_pack_req(repo_a))
        re_b, _ = tcp_transact(host, port, _upload_pack_req(repo_b))
        # Identical canned ERR across distinct repos is weak alone; only score when
        # a later exchange flips relative to an earlier advertisement-shaped reply.
        # (Covered above.) Keep non-hit for pure dual-ERR.
        if _is_advertisement(re_a) or _is_advertisement(re_b):
            state_hit = True
            state_detail = "ERR for nonexistent repos flipped to advertisement after reconnect"
            state_evidence = (re_a or re_b)[:300].decode("utf-8", "replace")

    sig_hit = match_git_always_missing(text)
    return [
        Indicator(
            id="git.arbitrary_auth",
            title="Git daemon advertises refs for nonexistent repos",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason=closed_reason(err_a or err_b) if auth_skipped else "",
            error=(err_a or err_b) if auth_skipped else "",
            protocol="git",
            detail=auth_detail,
            evidence=f"{repo_a};{repo_b}",
            fidelity="decisive" if auth_hit else "medium",
            remediation="Reject git-upload-pack for repositories that do not exist",
        ),
        Indicator(
            id="git.state_nonpersist",
            title="Git advertised upload-pack capabilities fail on follow-up",
            category="state_nonpersist",
            triggered=state_hit,
            protocol="git",
            detail=state_detail,
            evidence=state_evidence,
            fidelity="high" if state_hit else "medium",
            remediation="Honor advertised capabilities or omit them from the refs advertisement",
        ),
        Indicator(
            id="git.signature",
            title="Git daemon always ERR no such repository",
            category="static_signature",
            triggered=bool(sig_hit),
            protocol="git",
            detail=sig_hit or text.strip()[:160],
            evidence=text[:400],
        ),
    ]
