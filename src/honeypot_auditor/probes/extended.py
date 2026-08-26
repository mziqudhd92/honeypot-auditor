"""HTTP, Redis, SMTP, VNC, and SIP fingerprint engines."""

from __future__ import annotations

import secrets

from honeypot_auditor.config import (
    HTTP_DYNAMIC_HEADERS,
    REDIS_PROBE_KEY_PREFIX,
    REDIS_PROBE_VALUE,
    SIP_UA_TELLS,
    SMTP_HELO,
    SMTP_MAIL_FROM,
    SMTP_RCPT_TO,
    USER_AGENT,
)
from honeypot_auditor.models import Indicator, optional_import, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact, udp_transact
from honeypot_auditor.settings import settings

VNC_DESKTOP_TELLS = ("qemu", "raspberrypi", "localhost.localdomain")


def probe_http(host: str, port: int) -> list[Indicator]:
    requests = optional_import("requests")
    malformed = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host.encode("ascii", "replace") + b"\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 8\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"\x00{{{}}"
    )
    raw, err = tcp_transact(host, port, malformed, recv_first=False)
    if err and not raw:
        reason = closed_reason(err)
        return [
            skipped_indicator("http.malformed_200", "HTTP static 200 OK on malformed POST", "static_signature", reason, protocol="http", error=err),
            skipped_indicator("http.dynamic_headers", "HTTP missing dynamic Date header", "static_signature", reason, protocol="http", error=err),
        ]

    text = raw.decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0] if text else ""
    static_200 = first.startswith("HTTP/") and " 200 " in first
    header_map = _parse_headers(text)
    missing_dynamic = "date" in [h for h in HTTP_DYNAMIC_HEADERS if h not in header_map]

    if requests is not None:
        try:
            resp = requests.get(
                f"http://{host}:{port}/",
                timeout=settings.timeout_seconds,
                allow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            )
            get_headers = {k.lower(): v for k, v in resp.headers.items()}
            missing_dynamic = "date" not in get_headers
        except Exception:
            pass

    return [
        Indicator(
            id="http.malformed_200",
            title="HTTP static 200 OK on malformed POST",
            category="static_signature",
            triggered=static_200,
            protocol="http",
            detail=first or "(no status line)",
            evidence=text[:600],
        ),
        Indicator(
            id="http.dynamic_headers",
            title="HTTP missing dynamic Date header",
            category="static_signature",
            triggered=missing_dynamic,
            protocol="http",
            detail="response headers: " + ", ".join(sorted(header_map)),
            evidence=text.split("\r\n\r\n", 1)[0][:600],
        ),
    ]


def probe_redis(host: str, port: int) -> list[Indicator]:
    redis_mod = optional_import("redis")
    key = f"{REDIS_PROBE_KEY_PREFIX}{secrets.token_hex(4)}"
    if redis_mod is not None:
        try:
            client = redis_mod.Redis(
                host=host,
                port=port,
                socket_timeout=settings.timeout_seconds,
                socket_connect_timeout=settings.timeout_seconds,
            )
            client.set(key, REDIS_PROBE_VALUE)
            client.close()
            client2 = redis_mod.Redis(
                host=host,
                port=port,
                socket_timeout=settings.timeout_seconds,
                socket_connect_timeout=settings.timeout_seconds,
            )
            val = client2.get(key)
            try:
                client2.delete(key)
            except Exception:
                pass
            client2.close()
            persisted = val is not None and (
                val == REDIS_PROBE_VALUE.encode() or val == REDIS_PROBE_VALUE
            )
            return [
                Indicator(
                    id="redis.persist",
                    title="Redis key does not persist across reconnect",
                    category="state_nonpersist",
                    triggered=not persisted,
                    protocol="redis",
                    detail=f"SET {key} then GET after new connection returned {val!r}",
                )
            ]
        except Exception as exc:
            return [
                skipped_indicator(
                    "redis.persist",
                    "Redis key does not persist across reconnect",
                    "state_nonpersist",
                    closed_reason(str(exc)),
                    protocol="redis",
                    error=str(exc),
                )
            ]

    set_cmd = f"*3\r\n$3\r\nSET\r\n${len(key)}\r\n{key}\r\n${len(REDIS_PROBE_VALUE)}\r\n{REDIS_PROBE_VALUE}\r\n"
    raw, err = tcp_transact(host, port, set_cmd.encode())
    if err and not raw:
        return [
            skipped_indicator(
                "redis.persist",
                "Redis key does not persist across reconnect",
                "state_nonpersist",
                closed_reason(err),
                protocol="redis",
                error=err,
            )
        ]
    get_cmd = f"*2\r\n$3\r\nGET\r\n${len(key)}\r\n{key}\r\n"
    raw2, err2 = tcp_transact(host, port, get_cmd.encode())
    text = raw2.decode("utf-8", "replace")
    if err2 and not raw2:
        persisted = False
    else:
        persisted = REDIS_PROBE_VALUE in text and not text.startswith("$-1")
    del_cmd = f"*2\r\n$3\r\nDEL\r\n${len(key)}\r\n{key}\r\n"
    tcp_transact(host, port, del_cmd.encode())
    return [
        Indicator(
            id="redis.persist",
            title="Redis key does not persist across reconnect",
            category="state_nonpersist",
            triggered=not persisted,
            protocol="redis",
            detail=f"GET after reconnect: {text[:160]!r}",
        )
    ]


def probe_smtp(host: str, port: int) -> list[Indicator]:
    smtplib = optional_import("smtplib")
    if smtplib is None:
        return [
            skipped_indicator("smtp.open_relay", "SMTP accepts arbitrary external RCPT TO", "arbitrary_auth", "smtplib missing", protocol="smtp")
        ]
    try:
        smtp = smtplib.SMTP(timeout=settings.timeout_seconds)
        smtp.connect(host, port)
        smtp.helo(SMTP_HELO)
        smtp.mail(SMTP_MAIL_FROM)
        code, msg = smtp.rcpt(SMTP_RCPT_TO)
        try:
            smtp.quit()
        except Exception:
            pass
        accepted = 200 <= int(code) < 300
        return [
            Indicator(
                id="smtp.open_relay",
                title="SMTP accepts arbitrary external RCPT TO",
                category="arbitrary_auth",
                triggered=accepted,
                protocol="smtp",
                detail=f"RCPT TO:<{SMTP_RCPT_TO}> → {code} {msg!r}",
                evidence=str(code),
            )
        ]
    except Exception as exc:
        return [
            skipped_indicator(
                "smtp.open_relay",
                "SMTP accepts arbitrary external RCPT TO",
                "arbitrary_auth",
                closed_reason(str(exc)),
                protocol="smtp",
                error=str(exc),
            )
        ]


def probe_vnc(host: str, port: int) -> list[Indicator]:
    raw, err = tcp_transact(host, port, b"", recv_first=True)
    if err and not raw:
        return [
            skipped_indicator(
                "vnc.handshake",
                "VNC default RFB / desktop-name template",
                "static_signature",
                closed_reason(err),
                protocol="vnc",
                error=err,
            )
        ]
    banner = raw.decode("latin-1", "replace")
    if not banner.startswith("RFB "):
        return [
            Indicator(
                id="vnc.handshake",
                title="VNC default RFB / desktop-name template",
                category="static_signature",
                triggered=False,
                protocol="vnc",
                detail=banner.strip()[:120] or "(no RFB banner)",
                evidence=banner[:400],
            )
        ]
    reply, _ = tcp_transact(host, port, b"RFB 003.008\n", recv_first=True)
    blob = (raw + reply).decode("latin-1", "replace").lower()
    desktop_hit = any(tok in blob for tok in VNC_DESKTOP_TELLS)
    return [
        Indicator(
            id="vnc.handshake",
            title="VNC default RFB / desktop-name template",
            category="static_signature",
            triggered=desktop_hit,
            protocol="vnc",
            detail=(banner.strip()[:120] or "(no RFB banner)") + ("; generic desktop name" if desktop_hit else ""),
            evidence=blob[:400],
        )
    ]


def probe_sip(host: str, port: int) -> list[Indicator]:
    call_id = secrets.token_hex(6)
    probe = (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bKhpaudit;rport\r\n"
        f"From: <sip:auditor@invalid>;tag=hpaudit\r\n"
        f"To: <sip:{host}>\r\n"
        f"Call-ID: hpaudit-{call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Contact: <sip:auditor@0.0.0.0:5060>\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode()
    raw, err = udp_transact(host, port, probe)
    if err and not raw:
        raw, err = tcp_transact(host, port, probe)
    if err and not raw:
        return [
            skipped_indicator(
                "sip.user_agent",
                "SIP User-Agent matches a default template",
                "static_signature",
                closed_reason(err),
                protocol="sip",
                error=err,
            )
        ]
    text = raw.decode("latin-1", "replace")
    ua = ""
    for line in text.split("\r\n"):
        if line.lower().startswith("user-agent:"):
            ua = line.split(":", 1)[1].strip()
            break
    hit = bool(ua) and any(tell in ua.lower() for tell in SIP_UA_TELLS)
    return [
        Indicator(
            id="sip.user_agent",
            title="SIP User-Agent matches a default template",
            category="static_signature",
            triggered=hit,
            protocol="sip",
            detail=f"User-Agent: {ua or '(missing)'}",
            evidence=text[:600],
        )
    ]


def _parse_headers(response: str) -> dict:
    header_blob = response.split("\r\n\r\n", 1)[0]
    out = {}
    for line in header_blob.split("\r\n")[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip().lower()] = v.strip()
    return out
