def match_http_proxy_lure(text: str) -> str | None:
    """407 with Via localhost, frozen squid 3.3.8, X-Squid-Error, or ISA deny phrase."""
    blob = text or ""
    if not blob.strip():
        return None
    low = blob.lower()
    hits: list[str] = []
    if "via:" in low and "localhost" in low:
        hits.append("Via: localhost")
    if "squid/3.3.8" in low:
        hits.append("frozen squid/3.3.8")
    if "x-squid-error" in low:
        hits.append("X-Squid-Error")
    if "web proxy service is denied" in low:
        hits.append("ISA proxy deny phrase")
    return "; ".join(hits) if hits else None


def match_tls_stock_cert(text: str) -> str | None:
    """TLS certificate CN/SAN is a stock lab/dev name, not a production hostname."""
    low = (text or "").lower()
    for tell in (
        "synologynas.local",
        "localhost",
        "cowrie",
        "dionaea",
        "honeypot",
        "example.local",
    ):
        if tell in low:
            return f"stock TLS certificate name {tell}"
    return None
