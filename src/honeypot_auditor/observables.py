"""Lift CTI observables (HASSH/JA3S/JA4S/cert/NTLM) from indicator evidence."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from honeypot_auditor.models import Indicator
from honeypot_auditor.tls_fingerprint import pem_cert_sha256


def parse_evidence_json(evidence: str) -> dict[str, Any]:
    """Parse indicator evidence as JSON object; return {} on failure."""
    text = (evidence or "").strip()
    if not text or text[0] not in "{[":
        return {}
    try:
        data = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def collect_observables(indicators: Iterable[Indicator]) -> dict[str, dict[str, str]]:
    """Build top-level observables from probe evidence (first non-empty wins per key)."""
    ssh: dict[str, str] = {}
    tls: dict[str, str] = {}
    ntlm: dict[str, str] = {}

    for ind in indicators:
        data = parse_evidence_json(ind.evidence)
        if ind.id == "deep.hassh" or ind.fingerprint_type == "ssh_hassh":
            val = str(data.get("hassh_server") or "").strip()
            if val and "hassh_server" not in ssh:
                ssh["hassh_server"] = val
        if ind.id == "deep.tls_stack" or ind.fingerprint_type in ("tls_ja3s", "tls_ja4s"):
            for key in ("ja3s", "ja4s", "cert_sha256"):
                val = str(data.get(key) or "").strip()
                if val and key not in tls:
                    tls[key] = val
            if "cert_sha256" not in tls:
                snippet = str(data.get("cert_snippet") or "")
                digest = pem_cert_sha256(snippet)
                if digest:
                    tls["cert_sha256"] = digest
        if ind.id in ("smb.ntlm_challenge", "deep.smb_target_mismatch") or ind.protocol.startswith(
            "smb"
        ):
            if data:
                if "challenge" not in ntlm:
                    challenges = data.get("challenges")
                    if isinstance(challenges, list) and challenges:
                        ntlm["challenge"] = str(challenges[0])
                    elif data.get("challenge"):
                        ntlm["challenge"] = str(data["challenge"])
                for key in ("native_os", "av_hostname", "av_domain"):
                    val = str(data.get(key) or "").strip()
                    if val and key not in ntlm:
                        ntlm[key] = val
            elif ind.id == "smb.ntlm_challenge" and ind.evidence and "challenge" not in ntlm:
                # Legacy comma-separated hex challenges
                first = ind.evidence.split(",", 1)[0].strip()
                if first and all(c in "0123456789abcdefABCDEF" for c in first):
                    ntlm["challenge"] = first.lower()

    out: dict[str, dict[str, str]] = {}
    if ssh:
        out["ssh"] = ssh
    if tls:
        out["tls"] = tls
    if ntlm:
        out["ntlm"] = ntlm
    return out
