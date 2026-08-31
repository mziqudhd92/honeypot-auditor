"""Shodan Honeyscore + optional Nmap NSE recon."""

from __future__ import annotations

import json
import shutil
import socket
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from honeypot_auditor.config import (
    NMAP_HOST_TIMEOUT,
    NMAP_PORT_PRIORITY,
    NMAP_SCRIPTS,
    SHODAN_HONEYSCORE_URL,
    SHODAN_HOST_URL,
    SHODAN_SCORE_THRESHOLD,
    USER_AGENT,
    all_tcp_ports,
    is_private_or_loopback,
    match_nmap_service_tell,
    protocol_by_port,
)
from honeypot_auditor.models import Indicator, optional_import, skipped_indicator
from honeypot_auditor.settings import settings


def _open_tcp_ports(host: str, ports: list[int], timeout: float) -> list[int]:
    open_ports: list[int] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            sock.close()
    return open_ports


def shodan_lookup(ip: str, api_key: str | None) -> list[Indicator]:
    out: list[Indicator] = []
    if not api_key:
        out.append(
            skipped_indicator(
                "shodan.honeyscore",
                "Shodan Honeyscore > 0.6",
                "shodan",
                "no API key (--shodan-key or SHODAN_API_KEY)",
                protocol="shodan",
            )
        )
        out.append(
            skipped_indicator(
                "shodan.tags",
                "Shodan host tag contains honeypot",
                "shodan",
                "no API key",
                protocol="shodan",
            )
        )
        return out

    if is_private_or_loopback(ip):
        reason = "Shodan does not index loopback/RFC1918 addresses"
        return [
            skipped_indicator("shodan.honeyscore", "Shodan Honeyscore > 0.6", "shodan", reason, protocol="shodan"),
            skipped_indicator("shodan.tags", "Shodan host tag contains honeypot", "shodan", reason, protocol="shodan"),
        ]

    score, score_err = _honeyscore(ip, api_key)
    if score_err:
        out.append(
            skipped_indicator(
                "shodan.honeyscore",
                "Shodan Honeyscore > 0.6",
                "shodan",
                score_err,
                protocol="shodan",
                error=score_err,
            )
        )
    else:
        triggered = score is not None and score > SHODAN_SCORE_THRESHOLD
        out.append(
            Indicator(
                id="shodan.honeyscore",
                title="Shodan Honeyscore > 0.6",
                category="shodan",
                triggered=triggered,
                protocol="shodan",
                detail=f"honeyscore={score}",
                evidence=str(score),
            )
        )

    tags, tag_err = _host_tags(ip, api_key)
    if tag_err:
        out.append(
            skipped_indicator(
                "shodan.tags",
                "Shodan host tag contains honeypot",
                "shodan",
                tag_err,
                protocol="shodan",
                error=tag_err,
            )
        )
    else:
        hit = any("honeypot" in t.lower() for t in tags)
        out.append(
            Indicator(
                id="shodan.tags",
                title="Shodan host tag contains honeypot",
                category="shodan",
                triggered=hit,
                protocol="shodan",
                detail="tags=" + (", ".join(tags) if tags else "(none)"),
                evidence=",".join(tags),
            )
        )
    return out


def nmap_scan(ip: str, ports: dict[str, int | list[int]], enabled: bool = True) -> list[Indicator]:
    if not enabled:
        return [
            skipped_indicator(
                "nmap.nse",
                "Nmap -sV / NSE honeypot tells",
                "static_signature",
                "disabled (pass --with-nmap / -n to enable)",
                protocol="nmap",
            )
        ]
    if shutil.which("nmap") is None:
        return [
            skipped_indicator(
                "nmap.nse",
                "Nmap -sV / NSE honeypot tells",
                "static_signature",
                "nmap binary not on PATH",
                protocol="nmap",
            )
        ]
    nmap_mod = optional_import("nmap")
    if nmap_mod is None:
        return [
            skipped_indicator(
                "nmap.nse",
                "Nmap -sV / NSE honeypot tells",
                "static_signature",
                "python-nmap not installed (pip install honeypot-auditor[full])",
                protocol="nmap",
            )
        ]

    port_list = sorted(all_tcp_ports(ports))
    open_ports = _open_tcp_ports(ip, port_list, min(2.0, settings.timeout_seconds))
    if not open_ports:
        return [
            skipped_indicator(
                "nmap.nse",
                "Nmap -sV / NSE honeypot tells",
                "static_signature",
                "no open TCP ports in preset to scan",
                protocol="nmap",
            )
        ]
    # Version-scan every open preset port (unknown -sV on any protocol is a tell).
    name_by_port = protocol_by_port(ports)
    prioritized: list[int] = []
    for proto_name in NMAP_PORT_PRIORITY:
        for port in open_ports:
            if name_by_port.get(port) == proto_name and port not in prioritized:
                prioritized.append(port)
    for port in open_ports:
        if port not in prioritized:
            prioritized.append(port)
    scan_ports = prioritized
    port_spec = ",".join(str(p) for p in scan_ports)
    arguments = (
        f"-Pn -sV --script={NMAP_SCRIPTS} -p {port_spec} "
        f"--host-timeout {NMAP_HOST_TIMEOUT} --max-retries 1"
    )
    try:
        scanner = nmap_mod.PortScanner()
        scanner.scan(hosts=ip, arguments=arguments)
    except Exception as exc:
        return [
            skipped_indicator(
                "nmap.nse",
                "Nmap -sV / NSE honeypot tells",
                "static_signature",
                f"nmap failed: {exc}",
                protocol="nmap",
                error=str(exc),
            )
        ]

    triggers: list[str] = []
    banners: list[str] = []
    for host in scanner.all_hosts() if hasattr(scanner, "all_hosts") else []:
        host_obj = scanner[host]
        for proto, port_enum in (("tcp", "all_tcp"), ("udp", "all_udp")):
            if not hasattr(host_obj, port_enum):
                continue
            ports_found = getattr(host_obj, port_enum)()
            if not ports_found:
                continue
            bucket = host_obj[proto]
            for _port in ports_found:
                data = bucket.get(_port) or {}
                scripts = data.get("script") or {}
                merged = dict(data)
                if scripts:
                    merged["script_blob"] = " ".join(str(v) for v in scripts.values())
                svc_bits = " ".join(
                    str(data.get(k) or "")
                    for k in ("name", "product", "version", "extrainfo", "cpe")
                ).strip()
                if svc_bits:
                    banners.append(f"{_port}/{proto} {svc_bits}")
                hit = match_nmap_service_tell(merged)
                if hit:
                    triggers.append(f"{_port}/{proto}: {hit}")
                for sname, output in scripts.items():
                    banners.append(f"{sname}: {str(output)[:200]}")
                    script_hit = match_nmap_service_tell({"name": sname, "extrainfo": str(output)})
                    if script_hit:
                        triggers.append(f"{sname}@{_port}: {script_hit}")

    detail = "; ".join(triggers) if triggers else (
        "-sV ran; no unknown fingerprint or lure flags. " + "; ".join(banners[:6])
    )
    return [
        Indicator(
            id="nmap.nse",
            title="Nmap -sV / NSE honeypot tells",
            category="static_signature",
            triggered=bool(triggers),
            protocol="nmap",
            detail=detail[:800],
            evidence="\n".join(triggers[:12] or banners[:8]),
        )
    ]


def _http_get(url: str, params: dict) -> tuple[str, str]:
    full = url + "?" + urlencode(params)
    req = Request(full, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=settings.timeout_seconds) as resp:
            body = resp.read().decode("utf-8", "replace")
            if resp.status >= 400:
                return "", f"HTTP {resp.status}: {body[:200]}"
            return body, ""
    except OSError as exc:
        return "", str(exc)


def _honeyscore(ip: str, key: str) -> tuple[float | None, str]:
    body, err = _http_get(SHODAN_HONEYSCORE_URL.format(ip=ip), {"key": key})
    if err:
        return None, err
    try:
        return float(body.strip()), ""
    except ValueError:
        return None, f"non-numeric honeyscore: {body[:80]!r}"


def _host_tags(ip: str, key: str) -> tuple[list[str], str]:
    shodan = optional_import("shodan")
    if shodan is not None:
        try:
            api = shodan.Shodan(key)
            info = api.host(ip)
            return [str(t) for t in (info.get("tags") or [])], ""
        except Exception as exc:
            sdk_err = str(exc)
    else:
        sdk_err = ""

    body, err = _http_get(SHODAN_HOST_URL.format(ip=ip), {"key": key})
    if err:
        return [], err if not sdk_err else f"{sdk_err}; REST: {err}"
    try:
        info = json.loads(body)
    except json.JSONDecodeError:
        return [], f"invalid JSON from Shodan host API: {body[:80]!r}"
    if isinstance(info, dict) and info.get("error"):
        return [], str(info.get("error"))
    tags = [str(t) for t in (info.get("tags") or [])] if isinstance(info, dict) else []
    return tags, ""
