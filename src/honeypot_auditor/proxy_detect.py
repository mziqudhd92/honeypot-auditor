"""Reverse-proxy / CDN detection and tiered indicator suppression."""

from __future__ import annotations

from dataclasses import dataclass, field

_EDGE_TIERS = frozenset({"edge"})


@dataclass
class ProxyResult:
    detected: bool = False
    evidence: list[str] = field(default_factory=list)
    context: str = ""


def detect_proxy_from_headers(headers: dict[str, str]) -> ProxyResult:
    """Detect CDN/reverse-proxy from HTTP response headers."""
    evidence: list[str] = []
    lower = {k.lower(): v for k, v in headers.items()}

    proxy_headers = (
        "via",
        "x-forwarded-for",
        "x-forwarded-proto",
        "cf-ray",
        "x-amz-cf-id",
        "x-cache",
        "x-served-by",
    )
    for name in proxy_headers:
        if name in lower and lower[name]:
            evidence.append(f"{name}: {lower[name][:80]}")

    server = lower.get("server", "").lower()
    for token in ("cloudflare", "akamaighost", "amazons3", "nginx/1.18.0 (cloudflare)"):
        if token in server:
            evidence.append(f"server: {lower.get('server', '')[:80]}")
            break

    alt_svc = lower.get("alt-svc", "")
    if "h3=" in alt_svc and ("cloudflare" in alt_svc or "google" in alt_svc):
        evidence.append(f"alt-svc: {alt_svc[:80]}")

    detected = bool(evidence)
    return ProxyResult(
        detected=detected,
        evidence=evidence,
        context="edge_proxy_present" if detected else "",
    )


def detect_proxy(signals: dict) -> ProxyResult:
    """Aggregate proxy signals from HTTP headers and optional TLS hints."""
    headers = signals.get("headers") or {}
    result = detect_proxy_from_headers(headers)
    tls_cdn = signals.get("tls_cdn_match")
    if tls_cdn:
        result.detected = True
        result.evidence.append(f"tls_cdn: {tls_cdn}")
        result.context = "edge_proxy_present"
    return result


def should_suppress(indicator_tell_tier: str, proxy_detected: bool) -> bool:
    """Suppress edge-tier tells when a reverse proxy/CDN is detected."""
    if not proxy_detected:
        return False
    return indicator_tell_tier in _EDGE_TIERS
