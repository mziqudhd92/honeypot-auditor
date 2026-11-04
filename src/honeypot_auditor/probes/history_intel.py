"""Shodan/Censys history projection → sudden_buffet (entropy, not raw port count)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from honeypot_auditor.config import USER_AGENT
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.settings import settings

# Cheap port→family map for entropy scoring (not full product attribution).
_PORT_FAMILY: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "mail",
    53: "dns",
    80: "web",
    110: "mail",
    143: "mail",
    161: "snmp",
    443: "web",
    445: "smb",
    502: "modbus",
    993: "mail",
    995: "mail",
    1433: "mssql",
    1883: "mqtt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "web",
    8443: "web",
    9200: "elasticsearch",
    27017: "mongo",
}

# EIP-recycle faces commonly appear together on cloud churn — low deception alone.
_EIP_FAMILIES = frozenset({"web", "mail", "ssh"})

# Legacy / DB / ICS families that raise sudden_buffet entropy.
_LEGACY_DB_ICS = frozenset(
    {
        "telnet",
        "smb",
        "ftp",
        "mysql",
        "mssql",
        "postgres",
        "redis",
        "mongo",
        "modbus",
        "snmp",
        "mqtt",
        "rdp",
        "vnc",
        "elasticsearch",
        "dns",
    }
)

SHODAN_HISTORY_URL = "https://api.shodan.io/shodan/host/{ip}/history"
HISTORY_MAX_BYTES = 512_000
HISTORY_TIMEOUT_SECONDS = 8.0
SUDDEN_WINDOW_DAYS = 7
SUDDEN_MIN_PORTS = 8
SUDDEN_MIN_LEGACY_FAMILIES = 4


def port_family(port: int, product: str = "") -> str:
    fam = _PORT_FAMILY.get(int(port), "")
    if fam:
        return fam
    prod = (product or "").lower()
    for token, name in (
        ("mysql", "mysql"),
        ("redis", "redis"),
        ("mongo", "mongo"),
        ("telnet", "telnet"),
        ("smb", "smb"),
        ("modbus", "modbus"),
        ("postgres", "postgres"),
        ("mssql", "mssql"),
        ("mqtt", "mqtt"),
    ):
        if token in prod:
            return name
    return "other"


def project_history_row(row: dict[str, Any]) -> dict[str, Any] | None:
    """Keep only cheap fields: port/transport/timestamp/(cheap product)."""
    if not isinstance(row, dict):
        return None
    port = row.get("port")
    if port is None:
        return None
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return None
    ts = row.get("timestamp") or row.get("last_update") or ""
    transport = str(row.get("transport") or row.get("protocol") or "tcp").lower()
    product = str(row.get("product") or "").strip()[:80]
    return {
        "port": port_i,
        "transport": transport,
        "timestamp": str(ts),
        "product": product,
        "family": port_family(port_i, product),
    }


def _parse_ts(raw: str) -> datetime | None:
    text = (raw or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text.replace("Z", ""), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def evaluate_sudden_buffet(history_rows: list[dict[str, Any]]) -> Indicator | None:
    """Entropy-based sudden buffet from projected history rows (fixtures/unit-testable)."""
    projected = [p for p in (project_history_row(r) for r in history_rows) if p]
    if not projected:
        return None
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=SUDDEN_WINDOW_DAYS)
    in_window: list[dict[str, Any]] = []
    for row in projected:
        ts = _parse_ts(str(row.get("timestamp") or ""))
        if ts is None or ts >= window_start:
            in_window.append(row)
    ports = {int(r["port"]) for r in in_window}
    if len(ports) < SUDDEN_MIN_PORTS:
        return None
    families = {str(r.get("family") or "other") for r in in_window}
    legacy = families & _LEGACY_DB_ICS
    eip_only = families <= _EIP_FAMILIES or (
        len(legacy) < SUDDEN_MIN_LEGACY_FAMILIES and families <= (_EIP_FAMILIES | {"other"})
    )
    if eip_only or len(legacy) < SUDDEN_MIN_LEGACY_FAMILIES:
        # EIP churn / low entropy — do not emit high-fidelity sudden_buffet.
        return Indicator(
            id="shodan.sudden_buffet",
            title="Shodan history sudden service buffet",
            category="passive_intel",
            triggered=False,
            protocol="shodan",
            detail=(
                f"ports={len(ports)} families={sorted(families)} "
                f"(EIP/low-entropy; not high-fidelity sudden_buffet)"
            ),
            evidence=json.dumps({"ports": sorted(ports), "families": sorted(families)})[:500],
            fidelity="low",
        )
    return Indicator(
        id="shodan.sudden_buffet",
        title="Shodan history sudden service buffet",
        category="passive_intel",
        triggered=True,
        protocol="shodan",
        detail=(
            f"≥{SUDDEN_MIN_PORTS} ports in {SUDDEN_WINDOW_DAYS}d spanning "
            f"{len(legacy)} legacy/DB/ICS families: {sorted(legacy)}"
        ),
        evidence=json.dumps({"ports": sorted(ports), "families": sorted(families)})[:500],
        fidelity="high",
    )


def fetch_shodan_history(
    ip: str,
    api_key: str,
    *,
    timeout: float | None = None,
    max_bytes: int = HISTORY_MAX_BYTES,
) -> tuple[list[dict[str, Any]], str]:
    """Capped REST history fetch. Returns ([], skip_reason) on timeout/oversize/error."""
    url = SHODAN_HISTORY_URL.format(ip=ip)
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "api.shodan.io":
        return [], "refusing history URL outside HTTPS Shodan API allowlist"
    full = url + "?" + urlencode({"key": api_key})
    req = Request(full, headers={"User-Agent": USER_AGENT})
    to = timeout if timeout is not None else min(HISTORY_TIMEOUT_SECONDS, settings.timeout_seconds)
    try:
        with urlopen(req, timeout=to) as resp:  # nosec B310
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                return [], f"history response exceeded {max_bytes} bytes; skipped"
            if resp.status >= 400:
                return [], f"HTTP {resp.status}: {raw[:200]!r}"
            body = raw.decode("utf-8", "replace")
    except TimeoutError:
        return [], "history request timed out; skipped"
    except OSError as exc:
        return [], f"history request failed: {exc}"
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return [], "invalid JSON from Shodan history API"
    # Shodan may return a list of banners or a dict with data=[]
    if isinstance(data, list):
        rows = [r for r in data if isinstance(r, dict)]
    elif isinstance(data, dict):
        if data.get("error"):
            return [], str(data.get("error"))
        rows = [r for r in (data.get("data") or data.get("matches") or []) if isinstance(r, dict)]
    else:
        return [], "unexpected history payload shape"
    return rows, ""


def shodan_history_indicators(ip: str, api_key: str | None) -> list[Indicator]:
    """Opt-in history path; never raises — skip indicators keep the audit going."""
    if not api_key:
        return [
            skipped_indicator(
                "shodan.sudden_buffet",
                "Shodan history sudden service buffet",
                "passive_intel",
                "no API key",
                protocol="shodan",
            )
        ]
    rows, err = fetch_shodan_history(ip, api_key)
    if err:
        return [
            skipped_indicator(
                "shodan.sudden_buffet",
                "Shodan history sudden service buffet",
                "passive_intel",
                err,
                protocol="shodan",
                error=err,
            )
        ]
    ind = evaluate_sudden_buffet(rows)
    if ind is None:
        return [
            Indicator(
                id="shodan.sudden_buffet",
                title="Shodan history sudden service buffet",
                category="passive_intel",
                triggered=False,
                protocol="shodan",
                detail="history present; no sudden multi-family buffet",
                fidelity="low",
            )
        ]
    return [ind]
