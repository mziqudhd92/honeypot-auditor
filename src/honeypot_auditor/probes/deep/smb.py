"""Deep SMB probes: dialect/capability downgrade and NTLM target-info coherence."""

from __future__ import annotations

from honeypot_auditor.config import match_smb_negotiate_deficit, match_smb_target_info_mismatch
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.settings import settings
from honeypot_auditor.smbutil import capture_ntlm_challenge, optional_impacket, smb_negotiate_facts


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
    return [
        Indicator(
            id="deep.smb_target_mismatch",
            title="NTLM target info disagrees with native OS",
            category="coherence",
            triggered=bool(hit),
            protocol="smb",
            detail=hit or "NTLM AV pairs match native_os",
            evidence=(meta.get("native_os") or "")[:200],
        )
    ]
