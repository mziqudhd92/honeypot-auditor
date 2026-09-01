from honeypot_auditor.config.signatures.smtp import match_smtp_placeholder_identity
from honeypot_auditor.config.signatures.telnet import (
    match_telnet_banner,
    match_telnet_canned_reject,
)
from honeypot_auditor.config.tells.nmap import (
    NMAP_HONEYPOT_TELLS,
    NMAP_NSE_SCRIPT_NAMES,
    NMAP_PRODUCT_FAMILIES,
)


def _nmap_product_families(text: str) -> set[str]:
    low = (text or "").lower()
    return {fam for fam in NMAP_PRODUCT_FAMILIES if fam in low}


def match_nmap_service_tell(data: dict) -> str | None:
    """Class-level -sV tells: unknown fingerprint on any protocol, family mismatch, lure banners."""
    name = str(data.get("name") or "").strip()
    if name.lower() == "tcpwrapped":
        return None
    product = str(data.get("product") or "").strip()
    version = str(data.get("version") or "").strip()
    extra = str(data.get("extrainfo") or "").strip()
    fp = str(data.get("servicefp") or "").strip()
    blob_parts = [name, product, version, extra, fp]
    for key, val in data.items():
        if key in {"script", "name", "product", "version", "extrainfo", "servicefp"}:
            continue
        if isinstance(val, str) and val.strip():
            blob_parts.append(val)
    blob = " ".join(blob_parts)
    low = blob.lower()
    for tell in NMAP_HONEYPOT_TELLS:
        if tell in low:
            snippet = (product or version or tell)[:120]
            return f"{name or 'service'}: {tell} ({snippet})"
    telnet_hit = match_telnet_banner(blob) or match_telnet_canned_reject(blob)
    if telnet_hit:
        return f"telnet lure in -sV ({telnet_hit})"
    smtp_hit = match_smtp_placeholder_identity(blob)
    if smtp_hit:
        return smtp_hit
    banner_blob = " ".join(
        str(data.get(k) or "") for k in ("script_blob", "extrainfo", "servicefp")
    )
    prod_fams = _nmap_product_families(f"{product} {version}")
    banner_fams = _nmap_product_families(banner_blob)
    if prod_fams and banner_fams and prod_fams.isdisjoint(banner_fams):
        return (
            f"{name or 'service'} -sV/banner family mismatch "
            f"({', '.join(sorted(prod_fams))} vs {', '.join(sorted(banner_fams))})"
        )
    is_nse = name.lower() in NMAP_NSE_SCRIPT_NAMES
    if not is_nse:
        if fp.startswith("SF-") or "SF-Port" in fp:
            if not product:
                return f"{name or 'port'} unrecognized -sV fingerprint (data, no product match)"
        if not product and not version and name.lower() not in {"", "tcpwrapped"}:
            return f"{name} open but -sV has no product/version (unrecognized service)"
    if "ftp" in low and " or " in low:
        return f"ambiguous FTP -sV ({(product or version)[:120]})"
    return None
