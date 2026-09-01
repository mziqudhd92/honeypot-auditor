"""Deep probe #3: HASSH and TCP stack fingerprinting."""

from __future__ import annotations

import json
import socket

from honeypot_auditor.config import claimed_os_from_banner, match_tls_stock_cert
from honeypot_auditor.hassh import capture_server_kexinit, find_kexinit_payload, hassh_algo_mismatch
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.settings import ProbeProfile, settings
from honeypot_auditor.tls_fingerprint import (
    compute_ja3s,
    compute_ja4s,
    match_lure_profile,
    read_server_hello,
    tls_handshake,
)

_CLIENT_BANNER = b"SSH-2.0-honeypot_auditor_1.0\r\n"


def probe_hassh(host: str, port: int) -> list[Indicator]:
    payload = _CLIENT_BANNER
    raw, err = tcp_transact(
        host,
        port,
        payload,
        recv_first=True,
        timeout=max(4.0, settings.timeout_seconds),
        max_bytes=16384,
    )
    if err and not raw:
        return [
            skipped_indicator(
                "deep.hassh",
                "SSH HASSHServer diverges from claimed OpenSSH baseline",
                "stack_fingerprint",
                closed_reason(err),
                protocol="ssh",
                error=err,
            )
        ]
    banner, kex = capture_server_kexinit(raw)
    kex_payload = find_kexinit_payload(raw)
    raw_kexinit = kex_payload.hex() if kex_payload else ""
    if kex is None:
        return [
            Indicator(
                id="deep.hassh",
                title="SSH HASSHServer diverges from claimed OpenSSH baseline",
                category="stack_fingerprint",
                triggered=False,
                protocol="ssh",
                detail=f"no KEXINIT captured; banner={banner or '?'}",
                evidence=json.dumps({"banner": banner, "raw_kexinit": raw_kexinit}),
            )
        ]
    triggered, detail = hassh_algo_mismatch(banner, kex)
    evidence = {
        "banner": banner,
        "hassh_server": kex.hassh_server,
        "kex": kex.kex[:120],
        "raw_kexinit": raw_kexinit,
    }
    return [
        Indicator(
            id="deep.hassh",
            title="SSH HASSHServer diverges from claimed OpenSSH baseline",
            category="stack_fingerprint",
            triggered=triggered,
            protocol="ssh",
            detail=detail,
            evidence=json.dumps(evidence),
            fingerprint_type="ssh_hassh",
            requires_corroboration=True,
            tell_tier="edge",
        )
    ]


def _parse_synack_options(resp) -> str:
    """Build SYN-ACK TCP option order signature from Scapy response."""
    try:
        tcp = getattr(resp, "payload", None)
        if tcp is None or not hasattr(tcp, "options"):
            return ""
        names = []
        for opt in tcp.options:
            if isinstance(opt, tuple) and opt:
                names.append(str(opt[0]))
        return ",".join(names)
    except Exception:
        return ""


def probe_tcp_stack(host: str, port: int, claimed_os: str = "linux") -> list[Indicator]:
    """SYN-less stack hints via socket connect + optional SYN-ACK option order."""
    try:
        with socket.create_connection((host, port), timeout=settings.timeout_seconds) as sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            _ = sock.getsockname()
    except OSError as exc:
        return [
            skipped_indicator(
                "deep.tcp_stack",
                "TCP/IP stack traits inconsistent with claimed OS",
                "stack_fingerprint",
                closed_reason(str(exc)),
                protocol="tcp",
                error=str(exc),
            )
        ]

    ttl_hint = ""
    window_hint = ""
    synack_opts = ""
    caps = settings.capabilities
    raw_ok = getattr(caps, "raw_sockets", False) if caps else False

    if raw_ok:
        try:
            scapy = __import__("scapy.all", fromlist=["IP", "TCP", "sr1"])
            IP = scapy.IP
            TCP = scapy.TCP
            sr1 = scapy.sr1
            pkt = IP(dst=host) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=settings.timeout_seconds, verbose=0)
            if resp is not None:
                ttl_hint = str(getattr(resp, "ttl", ""))
                window_hint = str(getattr(getattr(resp, "payload", None), "window", ""))
                synack_opts = _parse_synack_options(resp)
        except ImportError:
            pass
        except Exception:
            pass

    indicators: list[Indicator] = []
    triggered = False
    detail_parts = [f"ttl={ttl_hint or '?'} window={window_hint or '?'}"]
    if ttl_hint.isdigit():
        ttl = int(ttl_hint)
        if claimed_os.lower().startswith("win") and 48 <= ttl <= 72:
            triggered = True
            detail_parts.append("TTL looks Linux-like but service claims Windows")
        if claimed_os.lower() == "linux" and ttl >= 120:
            triggered = True
            detail_parts.append("TTL looks Windows-like on claimed Linux service")

    indicators.append(
        Indicator(
            id="deep.tcp_stack",
            title="TCP/IP stack traits inconsistent with claimed OS",
            category="stack_fingerprint",
            triggered=triggered,
            protocol="tcp",
            detail="; ".join(detail_parts),
            evidence=f"port={port} ttl={ttl_hint} win={window_hint}",
            tell_tier="edge",
        )
    )

    if synack_opts:
        indicators.append(
            Indicator(
                id="deep.tcp_synack_options",
                title="TCP SYN-ACK option order fingerprint",
                category="stack_fingerprint",
                triggered=False,
                protocol="tcp",
                detail=f"option_order={synack_opts}",
                evidence=synack_opts,
                fingerprint_type="tcp_synack_options",
                requires_corroboration=True,
                tell_tier="edge",
            )
        )
    elif not raw_ok:
        indicators.append(
            skipped_indicator(
                "deep.tcp_synack_options",
                "TCP SYN-ACK option order fingerprint",
                "stack_fingerprint",
                "raw_sockets_disabled",
                protocol="tcp",
            )
        )

    return indicators


def _stdlib_cert_peek(host: str, port: int) -> tuple[str, tuple | None, tuple | None, str]:
    """Fallback stdlib TLS for cert CN and cipher stability."""
    ssl = __import__("ssl")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    cert_text = ""
    cipher1 = None
    cipher2 = None
    version = ""
    with socket.create_connection((host, port), timeout=settings.timeout_seconds) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cipher1 = tls.cipher()
            version = tls.version()
            try:
                cert_text = ssl.get_server_certificate((host, port))
            except Exception:
                cert_text = str(tls.getpeercert() or "")
    with socket.create_connection((host, port), timeout=settings.timeout_seconds) as sock2:
        with ctx.wrap_socket(sock2, server_hostname=host) as tls2:
            cipher2 = tls2.cipher()
    return cert_text, cipher1, cipher2, version


def probe_tls_stack(host: str, port: int) -> list[Indicator]:
    """Fixed ClientHello → JA3S/JA4S lure match + cert/cipher stability."""
    blend = settings.profile == ProbeProfile.BLEND
    seed = settings.seed
    raw, err = tls_handshake(
        host,
        port,
        timeout=settings.timeout_seconds,
        seed=seed,
        blend=blend,
    )

    cert_text = ""
    cipher1 = None
    cipher2 = None
    version = ""
    ja3s = ""
    ja4s = ""
    lure_name = ""
    lure_kind = ""

    if raw:
        parsed = read_server_hello(raw)
        if parsed:
            if parsed.version >= 0x0304:
                ja4s = compute_ja4s(parsed)
            else:
                ja3s = compute_ja3s(parsed)
            if not blend and settings.profile == ProbeProfile.AUDIT:
                lure_name, lure_kind = match_lure_profile(ja3s, ja4s)

    if err and not raw:
        try:
            cert_text, cipher1, cipher2, version = _stdlib_cert_peek(host, port)
        except Exception as exc:
            return [
                skipped_indicator(
                    "deep.tls_stack",
                    "TLS ServerHello / certificate looks like a stock lure",
                    "stack_fingerprint",
                    closed_reason(str(exc)),
                    protocol="tls",
                    error=str(exc),
                )
            ]
    elif not raw or not (ja3s or ja4s):
        try:
            cert_text, cipher1, cipher2, version = _stdlib_cert_peek(host, port)
        except Exception:
            pass

    cn_hit = match_tls_stock_cert(cert_text)
    stable = cipher1 == cipher2 if cipher1 and cipher2 else True
    parts: list[str] = []
    if ja3s:
        parts.append(f"ja3s={ja3s}")
    if ja4s:
        parts.append(f"ja4s={ja4s}")
    if version:
        parts.append(f"tls={version}")
    if cipher1:
        parts.append(f"cipher={cipher1}")
    if lure_name:
        parts.append(f"lure_match={lure_name}({lure_kind})")
    elif blend:
        parts.append("ja3s informational (blend profile)")
    detail = "; ".join(parts) or "tls handshake completed"
    if cn_hit:
        detail = f"{cn_hit}; {detail}"
    if not stable:
        detail = f"{detail}; cipher tuple unstable across handshakes"

    triggered = bool(lure_name and lure_kind == "lure") or bool(cn_hit) or not stable
    if blend:
        triggered = bool(cn_hit) or not stable

    evidence = json.dumps(
        {
            "ja3s": ja3s,
            "ja4s": ja4s,
            "raw_kexinit": "",
            "cert_snippet": cert_text[:240],
            "lure_match": lure_name,
        }
    )
    return [
        Indicator(
            id="deep.tls_stack",
            title="TLS ServerHello / certificate looks like a stock lure",
            category="stack_fingerprint",
            triggered=triggered,
            protocol="tls",
            tell_tier="edge",
            fingerprint_type="tls_ja3s" if ja3s else "tls_ja4s",
            requires_corroboration=not bool(cn_hit),
            detail=detail,
            evidence=evidence,
            remediation="Use production-grade TLS cert and stable cipher negotiation",
        )
    ]


def probe_tls_wildcard_sni(host: str, port: int) -> list[Indicator]:
    """TLS handshake with invalid SNI — traps often accept any name with a stock face."""
    import ssl

    from honeypot_auditor.config import WILDCARD_HOST
    from honeypot_auditor.proxy_transport import create_connection

    if settings.safe_mode:
        return [
            skipped_indicator(
                "tls.wildcard_sni",
                "TLS accepts invalid SNI",
                "proto_conformance",
                "safe-mode",
                protocol="tls",
            )
        ]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    err = ""
    status_line = ""
    handshake_ok = False
    tls = None
    try:
        sock = create_connection(host, port, settings.timeout_seconds)
        tls = ctx.wrap_socket(sock, server_hostname=WILDCARD_HOST)
        handshake_ok = True
        try:
            tls.sendall(
                b"GET / HTTP/1.1\r\nHost: "
                + WILDCARD_HOST.encode("ascii")
                + b"\r\nConnection: close\r\n\r\n"
            )
            data = tls.recv(1024)
            status_line = data.decode("latin-1", "replace").split("\r\n", 1)[0]
        except OSError:
            pass
    except (OSError, ssl.SSLError) as exc:
        err = str(exc)
    finally:
        if tls is not None:
            try:
                tls.close()
            except Exception:
                pass

    if not handshake_ok:
        return [
            skipped_indicator(
                "tls.wildcard_sni",
                "TLS accepts invalid SNI",
                "proto_conformance",
                closed_reason(err) if err else "handshake failed",
                protocol="tls",
                error=err,
            )
        ]
    app_200 = (" 200" in status_line) if status_line.startswith("HTTP/") else False
    detail = f"SNI={WILDCARD_HOST} handshake ok; {status_line or 'no HTTP response'}"
    return [
        Indicator(
            id="tls.wildcard_sni",
            title="TLS accepts invalid SNI",
            category="proto_conformance",
            triggered=app_200,
            protocol="tls",
            tell_tier="edge",
            detail=detail,
            evidence=status_line or err,
            requires_corroboration=True,
            remediation="Terminate unknown SNI with unrecognized_name alert or 421 Misdirected Request",
        )
    ]


def probe_http2_settings(host: str, port: int) -> list[Indicator]:
    """HTTP/2 SETTINGS order fingerprint (ALPN h2 via stdlib TLS)."""
    import ssl

    from honeypot_auditor.http2_fingerprint import match_http2_profile, parse_settings_order
    from honeypot_auditor.proxy_transport import create_connection

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass
    data = b""
    err = ""
    try:
        sock = create_connection(host, port, settings.timeout_seconds)
        tls = ctx.wrap_socket(sock, server_hostname=host)
        if tls.selected_alpn_protocol() != "h2":
            tls.close()
            return [
                skipped_indicator(
                    "deep.http2_settings",
                    "HTTP/2 SETTINGS order fingerprint",
                    "stack_fingerprint",
                    "ALPN h2 not negotiated",
                    protocol="http2",
                )
            ]
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        tls.sendall(preface)
        while len(data) < 8192:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
        tls.close()
    except OSError as exc:
        err = str(exc)
    if err or not data:
        return [
            skipped_indicator(
                "deep.http2_settings",
                "HTTP/2 SETTINGS order fingerprint",
                "stack_fingerprint",
                closed_reason(err) if err else "no HTTP/2 response",
                protocol="http2",
            )
        ]
    order = parse_settings_order(data)
    if not order:
        return [
            skipped_indicator(
                "deep.http2_settings",
                "HTTP/2 SETTINGS order fingerprint",
                "stack_fingerprint",
                "no HTTP/2 SETTINGS frame (ALPN h2 not negotiated or cleartext only)",
                protocol="http2",
            )
        ]
    lure, kind = match_http2_profile(order)
    sig = ",".join(order)
    return [
        Indicator(
            id="deep.http2_settings",
            title="HTTP/2 SETTINGS order matches lure profile",
            category="stack_fingerprint",
            triggered=kind == "lure" and bool(lure),
            protocol="http2",
            detail=f"settings_order={sig}" + (f"; lure={lure}" if lure else ""),
            evidence=sig,
            fingerprint_type="http2_settings",
            requires_corroboration=True,
            tell_tier="edge",
        )
    ]


def probe_tls_ja4s(host: str, port: int) -> list[Indicator]:
    """Deprecated alias — use probe_tls_stack."""
    out = probe_tls_stack(host, port)
    for ind in out:
        if ind.id == "deep.tls_stack":
            ind.detail = f"(alias deep.tls_ja4s) {ind.detail}"
    return out


def probe_banner_vs_stack(host: str, port: int) -> list[Indicator]:
    """Banner claims Windows/Linux but TCP TTL matches the other family."""
    raw, err = tcp_transact(host, port, b"", recv_first=True)
    if err and not raw:
        return [
            skipped_indicator(
                "deep.banner_stack",
                "TCP/IP stack traits inconsistent with service banner",
                "stack_fingerprint",
                closed_reason(err),
                protocol="tcp",
                error=err,
            )
        ]
    claimed = claimed_os_from_banner(raw.decode("latin-1", "replace"))
    if not claimed:
        return [
            skipped_indicator(
                "deep.banner_stack",
                "TCP/IP stack traits inconsistent with service banner",
                "stack_fingerprint",
                "banner does not claim an OS family",
                protocol="tcp",
            )
        ]
    out = probe_tcp_stack(host, port, claimed_os=claimed)
    for ind in out:
        if ind.id == "deep.tcp_stack":
            ind.id = "deep.banner_stack"
            ind.title = "TCP/IP stack traits inconsistent with service banner"
            ind.detail = f"claimed={claimed}; {ind.detail}"
            ind.remediation = "Align service banner with underlying TCP/IP stack traits"
    return out
