"""Optional Censys passive_intel provider (same spirit as Shodan history entropy)."""

from __future__ import annotations

import json
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from honeypot_auditor.config import USER_AGENT
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.probes.history_intel import evaluate_sudden_buffet, project_history_row
from honeypot_auditor.settings import settings

_CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"


def censys_provider(ip: str, api_key: str | None) -> list[Indicator]:
    """Entry-point callable: provider(ip, api_key) -> list[Indicator]."""
    if not api_key:
        return [
            skipped_indicator(
                "history",
                "Censys host history / service entropy",
                "passive_intel",
                "no API key (HONEYPOT_AUDITOR_INTEL_CENSYS_KEY or --intel-key censys=…)",
                protocol="intel:censys",
            )
        ]
    # Token may be "id:secret" or a single personal access token.
    auth = api_key.strip()
    url = _CENSYS_HOST_URL.format(ip=ip)
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "search.censys.io":
        return [
            skipped_indicator(
                "history",
                "Censys host history / service entropy",
                "passive_intel",
                "refusing URL outside HTTPS Censys API allowlist",
                protocol="intel:censys",
            )
        ]
    req = Request(
        url + "?" + urlencode({}),
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    # Prefer Basic when id:secret; else Bearer.
    if ":" in auth and not auth.lower().startswith("bearer "):
        import base64

        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    else:
        token = auth.removeprefix("Bearer ").removeprefix("bearer ")
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(req, timeout=min(8.0, settings.timeout_seconds)) as resp:  # nosec B310
            raw = resp.read(512_000 + 1)
            if len(raw) > 512_000:
                return [
                    skipped_indicator(
                        "history",
                        "Censys host history / service entropy",
                        "passive_intel",
                        "response exceeded size cap; skipped",
                        protocol="intel:censys",
                    )
                ]
            body = raw.decode("utf-8", "replace")
    except OSError as exc:
        detail = str(exc)
        if api_key:
            detail = detail.replace(api_key, "[REDACTED]")
        return [
            skipped_indicator(
                "history",
                "Censys host history / service entropy",
                "passive_intel",
                f"censys request failed: {detail}",
                protocol="intel:censys",
                error=detail,
            )
        ]
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return [
            skipped_indicator(
                "history",
                "Censys host history / service entropy",
                "passive_intel",
                "invalid JSON from Censys",
                protocol="intel:censys",
            )
        ]
    result = payload.get("result") if isinstance(payload, dict) else None
    services = (result or {}).get("services") if isinstance(result, dict) else []
    rows: list[dict] = []
    for svc in services or []:
        if not isinstance(svc, dict):
            continue
        port = svc.get("port")
        transport = str(svc.get("transport_protocol") or "tcp")
        product = str(svc.get("service_name") or "").strip()
        observed = str(svc.get("observed_at") or svc.get("last_updated_at") or "")
        projected = project_history_row(
            {"port": port, "transport": transport, "timestamp": observed, "product": product}
        )
        if projected:
            rows.append(projected)
    # Current host snapshot ≠ historical emergence. Reuse entropy helpers for family
    # diversity, but never emit high-fidelity sudden_buffet from a co-resident snapshot.
    ind = evaluate_sudden_buffet(rows)
    if ind is None or not ind.triggered:
        return [
            Indicator(
                id="history",
                title="Censys service entropy",
                category="passive_intel",
                triggered=False,
                detail="no multi-family co-resident services in Censys snapshot",
                fidelity="low",
            )
        ]
    return [
        Indicator(
            id="multi_family_services",
            title="Censys multi-family co-resident services",
            category="passive_intel",
            triggered=True,
            detail=(
                "Censys current services show diverse legacy/DB/ICS families "
                "(snapshot co-presence, not proven sudden emergence); "
                + (ind.detail or "")
            )[:500],
            evidence=ind.evidence,
            fidelity="medium",
            requires_corroboration=True,
        )
    ]
