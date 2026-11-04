"""Shodan/Censys history projection → sudden_buffet (entropy, not raw port count)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from honeypot_auditor.config import USER_AGENT
from honeypot_auditor.config.history_families import (
    EIP_FAMILIES,
    LEGACY_DB_ICS_FAMILIES,
    PORT_FAMILY,
)
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.settings import settings

# Documented host endpoint with history=true (not a separate /history path).
SHODAN_HISTORY_URL = "https://api.shodan.io/shodan/host/{ip}"
# History payloads with many banners routinely exceed 512KB; keep a hard cap.
HISTORY_MAX_BYTES = 2_000_000
HISTORY_TIMEOUT_SECONDS = 8.0
SUDDEN_WINDOW_DAYS = 7
SUDDEN_MIN_PORTS = 8
SUDDEN_MIN_LEGACY_FAMILIES = 4


def _scrub_api_key(detail: str, api_key: str) -> str:
    """Keep API keys out of skip_reason / error fields (URLError may embed the keyed URL)."""
    text = detail or ""
    if api_key:
        text = text.replace(api_key, "[REDACTED]")
    # Query-string form even if key value was partially escaped in the exception.
    text = re.sub(r"([?&]key=)[^&\s\"']+", r"\1[REDACTED]", text, flags=re.I)
    return text


def port_family(port: int, product: str = "") -> str:
    fam = PORT_FAMILY.get(int(port), "")
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
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def evaluate_sudden_buffet(history_rows: list[dict[str, Any]]) -> Indicator | None:
    """Entropy-based sudden buffet from projected history rows (fixtures/unit-testable)."""
    projected = [p for p in (project_history_row(r) for r in history_rows) if p]
    if not projected:
        return None
    now = datetime.now(UTC)
    window_start = now - timedelta(days=SUDDEN_WINDOW_DAYS)
    in_window: list[dict[str, Any]] = []
    for row in projected:
        ts = _parse_ts(str(row.get("timestamp") or ""))
        # Unparseable / missing timestamps must not inflate the 7-day window.
        if ts is not None and ts >= window_start:
            in_window.append(row)
    ports = {int(r["port"]) for r in in_window}
    if len(ports) < SUDDEN_MIN_PORTS:
        return None
    families = {str(r.get("family") or "other") for r in in_window}
    legacy = families & LEGACY_DB_ICS_FAMILIES
    eip_only = families <= EIP_FAMILIES or (
        len(legacy) < SUDDEN_MIN_LEGACY_FAMILIES and families <= (EIP_FAMILIES | {"other"})
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
    full = url + "?" + urlencode({"key": api_key, "history": "true"})
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
        return [], _scrub_api_key(f"history request failed: {exc}", api_key)
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return [], "invalid JSON from Shodan history API"
    # Shodan may return a list of banners or a dict with data=[]
    if isinstance(data, list):
        rows = [r for r in data if isinstance(r, dict)]
    elif isinstance(data, dict):
        if data.get("error"):
            return [], _scrub_api_key(str(data.get("error")), api_key)
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
