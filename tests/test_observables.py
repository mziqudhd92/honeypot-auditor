"""TDD: top-level CTI observables lifted from indicator evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from honeypot_auditor.analyzer import build_report
from honeypot_auditor.models import Indicator
from honeypot_auditor.observables import collect_observables
from honeypot_auditor.reporters import json_export
from honeypot_auditor.tls_fingerprint import pem_cert_sha256

# Short-lived self-signed CN=cowrie (test-only; not a production lure capture).
_FAKE_PEM = """-----BEGIN CERTIFICATE-----
MIIB/jCCAWegAwIBAgIUTgCfOGiRdVgJ531F9UD8xEBdakAwDQYJKoZIhvcNAQEL
BQAwETEPMA0GA1UEAwwGY293cmllMB4XDTI2MTEwNDA2MzY0NVoXDTI2MTEwNTA2
MzY0NVowETEPMA0GA1UEAwwGY293cmllMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDJkEzInjCAWhO6D3mVVD+QyUkjxYfcOhTgn7IUiES5vrY92QdAZADGfELZ
Q8XregRQZxd7Cf9D6ALua41FNRh9uwJLV/JL+N7icflQUHAOQCsrGVSN8PKhOhZJ
7Tla0WJCAQ9cfdXP0RIAW56ocC9DTVhSw+boi9d2ANvrsJ9//wIDAQABo1MwUTAd
BgNVHQ4EFgQUH6vrXHX8d6DNLAJh2pt20BcPGHYwHwYDVR0jBBgwFoAUH6vrXHX8
d6DNLAJh2pt20BcPGHYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOB
gQCz3gI/rys6VKFvgVGqb5qw32mTSZQ4UXXVoAvFXaLcp3t6uDUMT+TC1YSyWC3Q
EQj2RBIT6ectBd/akp9BDfMPgZ/JTEPyrfTAgg8cLZD2otZ6xDbrtHS9Ft21bIsY
RLRZnrau+JZYnGp/YAJ+CUQp4ipherU4VgXpeRTZZUwk/g==
-----END CERTIFICATE-----
"""
_FAKE_CERT_SHA256 = "75e4ada7199d1a271e463e24bc41fb9e14409de6ad28c4578e00219ff568181c"  # pragma: allowlist secret


def _inds() -> list[Indicator]:
    return [
        Indicator(
            id="deep.hassh",
            title="HASSH",
            category="stack_fingerprint",
            triggered=True,
            protocol="ssh",
            evidence=json.dumps(
                {
                    "banner": "SSH-2.0-OpenSSH_7.9",
                    "hassh_server": "aabbccddeeff00112233445566778899",  # pragma: allowlist secret
                    "kex": "curve25519",
                }
            ),
        ),
        Indicator(
            id="deep.tls_stack",
            title="TLS",
            category="stack_fingerprint",
            triggered=True,
            protocol="tls",
            evidence=json.dumps(
                {
                    "ja3s": "cafebabedeadbeefcafebabedeadbeef",
                    "ja4s": "t130200_1301_0000",
                    "cert_snippet": _FAKE_PEM[:240],
                    "cert_sha256": _FAKE_CERT_SHA256,
                    "lure_match": "",
                }
            ),
        ),
        Indicator(
            id="smb.ntlm_challenge",
            title="NTLM",
            category="static_signature",
            triggered=True,
            protocol="smb",
            evidence=json.dumps(
                {
                    "challenges": ["aaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaa"],
                    "native_os": "Windows Server 2016",
                    "av_hostname": "SAMBA-FAKE",
                    "av_domain": "WORKGROUP",
                }
            ),
        ),
    ]


def test_collect_observables_from_fixture_indicators():
    obs = collect_observables(_inds())
    assert obs["ssh"]["hassh_server"] == "aabbccddeeff00112233445566778899"  # pragma: allowlist secret
    assert obs["tls"]["ja3s"] == "cafebabedeadbeefcafebabedeadbeef"  # pragma: allowlist secret
    assert obs["tls"]["ja4s"] == "t130200_1301_0000"
    assert obs["tls"]["cert_sha256"] == _FAKE_CERT_SHA256
    assert obs["ntlm"]["native_os"] == "Windows Server 2016"
    assert obs["ntlm"]["challenge"] == "aaaaaaaaaaaaaaaa"
    assert obs["ntlm"]["av_hostname"] == "SAMBA-FAKE"


def test_build_report_attaches_observables():
    report = build_report(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        ports={"ssh": [22], "http": [443], "smb": [445]},
        indicators=_inds(),
        notes=[],
        started_at="",
        finished_at="",
        deep=True,
    )
    assert report.observables["ssh"]["hassh_server"]
    assert report.observables["tls"]["cert_sha256"]
    assert report.observables["ntlm"]["native_os"]


def test_json_export_includes_top_level_observables(tmp_path: Path):
    report = build_report(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        ports={"ssh": [22]},
        indicators=_inds(),
        notes=[],
        started_at="",
        finished_at="",
        deep=True,
    )
    dest = tmp_path / "out.json"
    json_export.export(report, dest)
    payload = json.loads(dest.read_text(encoding="utf-8"))
    assert "observables" in payload
    assert payload["observables"]["tls"]["ja3s"]
    assert payload["observables"]["tls"]["cert_sha256"]


def test_pem_cert_sha256_is_der_digest():
    digest = pem_cert_sha256(_FAKE_PEM)
    assert digest == _FAKE_CERT_SHA256
    assert digest != hashlib.sha256(_FAKE_PEM.encode()).hexdigest()
