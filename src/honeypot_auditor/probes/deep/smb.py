"""Deep SMB probes: dialect/capability downgrade and NTLM target-info coherence."""

from __future__ import annotations

import json
from typing import Any

from honeypot_auditor.config import match_smb_negotiate_deficit, match_smb_target_info_mismatch
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.settings import settings
from honeypot_auditor.smbutil import capture_ntlm_challenge, optional_impacket, smb_negotiate_facts


def _ntlm_av_labels(meta: dict[str, Any]) -> dict[str, str]:
    """Extract hostname/domain strings from NTLM AV pairs for observables."""
    av = meta.get("av_pairs")
    out = {"av_hostname": "", "av_domain": ""}
    if av is None or not hasattr(av, "get"):
        return out
    try:
        from impacket import ntlm
    except ImportError:
        return out

    def _name(pair_id: int) -> str:
        try:
            item = av.get(pair_id)
        except Exception:
            return ""
        if not item:
            return ""
        raw = item[1] if isinstance(item, (tuple, list)) and len(item) > 1 else item
        if isinstance(raw, bytes):
            return raw.decode("utf-16le", "replace")
        return str(raw) if raw else ""

    try:
        out["av_hostname"] = _name(ntlm.NTLMSSP_AV_HOSTNAME) or _name(ntlm.NTLMSSP_AV_DNS_HOSTNAME)
        out["av_domain"] = _name(ntlm.NTLMSSP_AV_DOMAINNAME) or _name(ntlm.NTLMSSP_AV_DNS_DOMAINNAME)
    except Exception:
        return {"av_hostname": "", "av_domain": ""}
    return out


def probe_smb_negotiate(host: str, port: int) -> list[Indicator]:
    if optional_impacket()[0] is None:
        return [
            skipped_indicator(
                "deep.smb_negotiate",
                "SMB negotiate lacks SMB 3.x capabilities",
                "stack_fingerprint",
                "impacket not installed (pip install honeypot-auditor[full])",
                protocol="smb",
            )
        ]
    facts = smb_negotiate_facts(host, port, timeout=max(1, int(settings.timeout_seconds)))
    if facts.get("error") and not facts.get("dialect"):
        return [
            skipped_indicator(
                "deep.smb_negotiate",
                "SMB negotiate lacks SMB 3.x capabilities",
                "stack_fingerprint",
                facts["error"][:160],
                protocol="smb",
                error=facts["error"],
            )
        ]
    hit = match_smb_negotiate_deficit(facts)
    return [
        Indicator(
            id="deep.smb_negotiate",
            title="SMB negotiate lacks SMB 3.x capabilities",
            category="stack_fingerprint",
            triggered=bool(hit),
            protocol="smb",
            detail=hit or f"dialect={facts.get('dialect')!r} capabilities look normal",
            evidence=str(facts)[:300],
        )
    ]


def probe_smb_target_mismatch(host: str, port: int) -> list[Indicator]:
    if optional_impacket()[0] is None:
        return [
            skipped_indicator(
                "deep.smb_target_mismatch",
                "NTLM target info disagrees with native OS",
                "coherence",
                "impacket not installed (pip install honeypot-auditor[full])",
                protocol="smb",
            )
        ]
    meta = capture_ntlm_challenge(host, port, timeout=max(1, int(settings.timeout_seconds)))
    if not meta:
        return [
            skipped_indicator(
                "deep.smb_target_mismatch",
                "NTLM target info disagrees with native OS",
                "coherence",
                "no NTLM Type-2 challenge captured",
                protocol="smb",
            )
        ]
    hit = match_smb_target_info_mismatch(meta.get("native_os", ""), meta)
    av = _ntlm_av_labels(meta)
    challenge = meta.get("challenge")
    challenge_hex = challenge.hex() if isinstance(challenge, (bytes, bytearray)) else ""
    return [
        Indicator(
            id="deep.smb_target_mismatch",
            title="NTLM target info disagrees with native OS",
            category="coherence",
            triggered=bool(hit),
            protocol="smb",
            detail=hit or "NTLM AV pairs match native_os",
            evidence=json.dumps(
                {
                    "native_os": meta.get("native_os") or "",
                    "challenge": challenge_hex,
                    "av_hostname": av["av_hostname"],
                    "av_domain": av["av_domain"],
                }
            ),
        )
    ]
