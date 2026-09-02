"""Deep probe #4: protocol FSM / RFC edge-case conformance."""

from __future__ import annotations

import re
from contextlib import suppress

from honeypot_auditor.config import USER_AGENT
from honeypot_auditor.models import Indicator, optional_import, skipped_indicator
from honeypot_auditor.netutil import (
    closed_reason,
    is_non_routable_ip,
    parse_ftp_pasv_host,
    tcp_transact,
)
from honeypot_auditor.settings import settings


def _smtp_blob(msg: object) -> str:
    if isinstance(msg, bytes):
        return msg.decode("utf-8", "replace")
    return str(msg or "")


def probe_http_fsm(host: str, port: int) -> list[Indicator]:
    failures: list[str] = []
    evidence: list[str] = []

    # Pipelined GET + malformed method
    piped = (
        b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: keep-alive\r\n\r\n"
        b"FOOBAR / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n"
    )
    raw, err = tcp_transact(
        host, port, piped, recv_first=False, timeout=max(4.0, settings.timeout_seconds)
    )
    text = raw.decode("latin-1", "replace")
    evidence.append(f"pipeline: {text[:300]!r}")
    statuses = re.findall(r"HTTP/\d\.\d (\d{3})", text)
    if len(statuses) >= 2 and statuses[0] == statuses[1] == "200":
        failures.append("pipelined bad method returned duplicate static 200")

    # Invalid chunked Transfer-Encoding length (production stacks → 400; traps → 200)
    chunked = (
        b"POST / HTTP/1.1\r\nHost: "
        + host.encode()
        + b"\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        b"ZZ\r\nnot-hex\r\n0\r\n\r\n"
    )
    ch_raw, ch_err = tcp_transact(
        host, port, chunked, recv_first=False, timeout=max(4.0, settings.timeout_seconds)
    )
    ch_text = ch_raw.decode("latin-1", "replace")
    evidence.append(f"chunked: {ch_text[:200]!r} err={ch_err}")
    ch_status = re.search(r"HTTP/\d\.\d (\d{3})", ch_text)
    if ch_status and ch_status.group(1) == "200":
        failures.append("invalid chunked length returned 200 (expected 400)")

    # Header-order Date monotonicity via requests if available
    requests = optional_import("requests")
    dates: list[str] = []
    if requests is not None:
        import time as _time

        for _ in range(2):
            try:
                # Plain HTTP is the protocol under test; no credentials or sensitive data are sent.
                resp = requests.get(
                    f"http://{host}:{port}/",  # nosemgrep: python.lang.security.audit.insecure-transport.requests.request-with-http.request-with-http
                    timeout=settings.timeout_seconds,
                    headers={"User-Agent": USER_AGENT},
                )
                dates.append(resp.headers.get("Date", ""))
            except Exception:
                break
            _time.sleep(1.1)
        evidence.append(f"dates={dates}")
        if len(dates) == 2 and dates[0] and dates[0] == dates[1]:
            failures.append("Date header identical across requests 1s apart")

    if err and not raw and not ch_raw:
        return [
            skipped_indicator(
                "deep.http_fsm",
                "HTTP FSM / RFC edge-case conformance failure",
                "proto_conformance",
                closed_reason(err or ch_err),
                protocol="http",
                error=err or ch_err,
            )
        ]

    return [
        Indicator(
            id="deep.http_fsm",
            title="HTTP FSM / RFC edge-case conformance failure",
            category="proto_conformance",
            triggered=len(failures) >= 1,
            protocol="http",
            detail="; ".join(failures) if failures else "HTTP edge cases handled plausibly",
            evidence="\n".join(evidence)[:1500],
            requires_corroboration=len(failures) < 2,
        )
    ]


def probe_ftp_fsm(host: str, port: int) -> list[Indicator]:
    ftplib = optional_import("ftplib")
    if ftplib is None:
        return [
            skipped_indicator(
                "deep.ftp_fsm",
                "FTP PASV/FEAT FSM conformance failure",
                "proto_conformance",
                "ftplib missing",
                protocol="ftp",
            )
        ]
    failures: list[str] = []
    evidence = ""
    try:
        # FTP is intentionally the protocol under audit; no production credential is used.
        ftp = ftplib.FTP()  # nosec B321
        ftp.connect(host, port, timeout=settings.timeout_seconds)
        ftp.login()
        feat = ""
        with suppress(Exception):
            feat = ftp.sendcmd("FEAT")
        with suppress(Exception):
            rest = ftp.sendcmd("REST 0")
            if str(rest).startswith("200"):
                failures.append("REST 0 returned 200 instead of 350")
        pasv_addr = ""
        pasv_data_fail = False
        try:
            resp = ftp.sendcmd("PASV")
            pasv_addr = resp
            m = re.search(r"(\d+,\d+,\d+,\d+,\d+,\d+)", resp)
            if m:
                pasv_host = parse_ftp_pasv_host(resp) or ""
                if pasv_host and is_non_routable_ip(pasv_host):
                    failures.append(f"PASV advertises non-routable {pasv_host}")
                # Try data channel (STOR) — emulators often advertise bad PASV endpoints.
                try:
                    import io as _io

                    ftp.storbinary("STOR hpaudit_fsm_probe.txt", _io.BytesIO(b"x\n"))
                except Exception as stor_exc:
                    if "refused" in str(stor_exc).lower() or "timeout" in str(stor_exc).lower():
                        pasv_data_fail = True
                        failures.append(f"PASV data connection failed: {stor_exc}")
        except Exception as exc:
            failures.append(f"PASV failed: {exc}")
        evidence = f"FEAT={feat[:200]} PASV={pasv_addr[:120]} data_fail={pasv_data_fail}"
        ftp.quit()
    except Exception as exc:
        return [
            skipped_indicator(
                "deep.ftp_fsm",
                "FTP PASV/FEAT FSM conformance failure",
                "proto_conformance",
                closed_reason(str(exc)),
                protocol="ftp",
                error=str(exc),
            )
        ]
    return [
        Indicator(
            id="deep.ftp_fsm",
            title="FTP PASV/FEAT FSM conformance failure",
            category="proto_conformance",
            triggered=bool(failures),
            protocol="ftp",
            detail="; ".join(failures) if failures else "FTP FSM looks plausible",
            evidence=evidence,
        )
    ]


def probe_smtp_fsm(host: str, port: int) -> list[Indicator]:
    smtplib = optional_import("smtplib")
    if smtplib is None:
        return [
            skipped_indicator(
                "deep.smtp_fsm",
                "SMTP command-sequence FSM conformance failure",
                "proto_conformance",
                "smtplib missing",
                protocol="smtp",
            )
        ]
    failures: list[str] = []
    evidence = ""
    try:
        smtp = smtplib.SMTP(host, port, timeout=settings.timeout_seconds)
        code, greeting = smtp.ehlo("auditor.local")
        evidence = _smtp_blob(greeting)[:200]
        try:
            smtp.docmd("VRFY", "root")
        except smtplib.SMTPException as exc:
            if "502" not in str(exc) and "252" not in str(exc):
                failures.append(f"VRFY unexpected: {exc}")
        try:
            smtp.docmd("EXPN", "root")
        except smtplib.SMTPException:
            pass
        try:
            smtp.docmd("ETRN", "auditor.invalid")
        except smtplib.SMTPException:
            pass
        try:
            smtp.docmd("RSET")
            rcpt_code, _rcpt_msg = smtp.docmd("RCPT TO:<fake@external-domain.com>")
            if rcpt_code == 250:
                failures.append("RSET+RCPT accepted external recipient without MAIL FROM")
        except smtplib.SMTPException as exc:
            if "250" in str(exc):
                failures.append("RSET+RCPT accepted external recipient without MAIL FROM")
        with suppress(Exception):
            smtp.mail("probe@auditor.invalid")
            smtp.rcpt("sink@auditor.invalid")
            data_code, _ = smtp.docmd("DATA")
            if int(data_code) == 354:
                rset_code, _ = smtp.docmd("RSET")
                if int(rset_code) == 354:
                    failures.append("RSET during DATA did not abort (still 354)")
        smtp.quit()
    except Exception as exc:
        return [
            skipped_indicator(
                "deep.smtp_fsm",
                "SMTP command-sequence FSM conformance failure",
                "proto_conformance",
                closed_reason(str(exc)),
                protocol="smtp",
                error=str(exc),
            )
        ]
    return [
        Indicator(
            id="deep.smtp_fsm",
            title="SMTP command-sequence FSM conformance failure",
            category="proto_conformance",
            triggered=bool(failures),
            protocol="smtp",
            detail="; ".join(failures) if failures else "SMTP FSM plausible",
            evidence=evidence,
        )
    ]


def probe_telnet_fsm(host: str, port: int) -> list[Indicator]:
    """Rare IAC options, AUTH/NAWS subnegotiation, LF-only login line."""
    failures: list[str] = []
    evidence: list[str] = []
    iac = bytes(
        [
            255,
            251,
            99,
            255,
            253,
            37,
            255,
            250,
            37,
            0,
            255,
            240,
            255,
            250,
            31,
            0,
            80,
            0,
            24,
            255,
            240,
        ]
    )
    raw, err = tcp_transact(host, port, iac, recv_first=True)
    evidence.append(f"iac={raw[:120]!r} err={err}")
    if err and not raw:
        return [
            skipped_indicator(
                "deep.telnet_fsm",
                "Telnet IAC/RFC option negotiation failure",
                "proto_conformance",
                closed_reason(err),
                protocol="telnet",
                error=err,
            )
        ]
    if b"\xff\xfb\x63" in raw or b"\xff\xfd\x63" in raw:
        failures.append("accepted unknown Telnet option 99")
    if err and "reset" in err.lower():
        failures.append("connection reset on AUTH/NAWS subnegotiation")
    lf_raw, lf_err = tcp_transact(host, port, b"root\npassword\n", recv_first=True)
    evidence.append(f"lf={lf_raw[:80]!r} err={lf_err}")
    if lf_err and "reset" in lf_err.lower() and lf_raw:
        failures.append("reset on LF-only line (expected \\r\\n)")
    return [
        Indicator(
            id="deep.telnet_fsm",
            title="Telnet IAC/RFC option negotiation failure",
            category="proto_conformance",
            triggered=bool(failures),
            protocol="telnet",
            detail="; ".join(failures) if failures else "Telnet option negotiation looks plausible",
            evidence="\n".join(evidence)[:1500],
        )
    ]


def probe_state_continuity(host: str, port: int) -> list[Indicator]:
    """HTTP cookie persistence across requests on same connection."""
    if settings.safe_mode:
        return [
            skipped_indicator(
                "fsm.stateless_trap_behavior",
                "Stateful session continuity failure",
                "proto_conformance",
                "safe-mode",
                protocol="http",
            )
        ]
    req1 = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
        f"User-Agent: honeypot-auditor\r\n\r\n"
    ).encode()
    raw1, err1 = tcp_transact(
        host, port, req1, recv_first=False, timeout=max(4.0, settings.timeout_seconds)
    )
    if err1 and not raw1:
        return [
            skipped_indicator(
                "fsm.stateless_trap_behavior",
                "Stateful session continuity failure",
                "proto_conformance",
                closed_reason(err1),
                protocol="http",
                error=err1,
            )
        ]
    set_cookie = ""
    for line in raw1.decode("latin-1", "replace").split("\r\n"):
        if line.lower().startswith("set-cookie:"):
            set_cookie = line.split(":", 1)[1].strip().split(";")[0]
            break
    req2 = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
        f"User-Agent: honeypot-auditor\r\n\r\n"
    ).encode()
    if set_cookie:
        req2 = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\nCookie: {set_cookie}\r\n"
            f"Connection: close\r\nUser-Agent: honeypot-auditor\r\n\r\n"
        ).encode()
    raw2, err2 = tcp_transact(
        host, port, req2, recv_first=False, timeout=max(4.0, settings.timeout_seconds)
    )
    triggered = False
    detail = "session continuity plausible"
    if set_cookie and raw2 and b"200" in raw2[:20]:
        if set_cookie.split("=")[0] not in raw2.decode("latin-1", "replace"):
            triggered = True
            detail = "Set-Cookie issued but follow-up ignored session context"
    return [
        Indicator(
            id="fsm.stateless_trap_behavior",
            title="Stateful session continuity failure",
            category="proto_conformance",
            triggered=triggered,
            protocol="http",
            detail=detail,
            evidence=f"set_cookie={set_cookie!r} err2={err2}",
            requires_corroboration=True,
            tell_tier="origin",
            remediation="Persist session state or disable misleading Set-Cookie on decoys",
        )
    ]


_CLIENT_BANNER = b"SSH-2.0-honeypot_auditor_1.0\r\n"


def probe_ssh_fsm(host: str, port: int) -> list[Indicator]:
    """Out-of-order / garbage bytes before a proper SSH client banner."""
    if settings.safe_mode:
        return [
            skipped_indicator(
                "deep.ssh_fsm",
                "SSH FSM / out-of-order pre-KEXINIT conformance failure",
                "proto_conformance",
                "safe-mode",
                protocol="ssh",
            )
        ]
    failures: list[str] = []
    raw1, err1 = tcp_transact(
        host,
        port,
        b"GET / HTTP/1.0\r\n\r\n",
        recv_first=True,
        timeout=max(4.0, settings.timeout_seconds),
        max_bytes=4096,
    )
    text1 = raw1.decode("latin-1", "replace")
    if raw1 and "SSH-" in text1 and (b"diffie-hellman" in raw1.lower() or b"\x14" in raw1[20:]):
        failures.append("continued KEXINIT after non-SSH client preface")
    raw2, err2 = tcp_transact(
        host,
        port,
        b"\x00\x00\x00\x0c\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        recv_first=True,
        timeout=max(4.0, settings.timeout_seconds),
        max_bytes=4096,
    )
    if raw2 and b"SSH-" in raw2 and err2 == "" and len(raw2) > 64:
        if b"diffie-hellman" in raw2.lower() or raw2.count(b"\x00") > 8:
            failures.append("SSH binary pre-banner junk still yielded protocol continuation")
    if err1 and not raw1 and err2 and not raw2:
        return [
            skipped_indicator(
                "deep.ssh_fsm",
                "SSH FSM / out-of-order pre-KEXINIT conformance failure",
                "proto_conformance",
                closed_reason(err1 or err2),
                protocol="ssh",
                error=err1 or err2,
            )
        ]
    return [
        Indicator(
            id="deep.ssh_fsm",
            title="SSH FSM / out-of-order pre-KEXINIT conformance failure",
            category="proto_conformance",
            triggered=bool(failures),
            protocol="ssh",
            detail="; ".join(failures)
            if failures
            else "SSH rejects out-of-order preface plausibly",
            evidence=f"http_preface={raw1[:120]!r}; bin_preface={raw2[:120]!r}",
            requires_corroboration=True,
        )
    ]


def probe_ssh_state_continuity(host: str, port: int) -> list[Indicator]:
    """Complete banner/KEXINIT glimpse, drop TCP, reconnect — flag pathological identical timing."""
    import time as _time

    if settings.safe_mode:
        return [
            skipped_indicator(
                "fsm.stateless_trap_behavior",
                "SSH session continuity failure after abrupt drop",
                "proto_conformance",
                "safe-mode",
                protocol="ssh",
            )
        ]
    t0 = _time.monotonic()
    raw1, err1 = tcp_transact(
        host,
        port,
        _CLIENT_BANNER,
        recv_first=True,
        timeout=max(4.0, settings.timeout_seconds),
        max_bytes=8192,
    )
    elapsed1 = _time.monotonic() - t0
    if err1 and not raw1:
        return [
            skipped_indicator(
                "fsm.stateless_trap_behavior",
                "SSH session continuity failure after abrupt drop",
                "proto_conformance",
                closed_reason(err1),
                protocol="ssh",
                error=err1,
            )
        ]
    t1 = _time.monotonic()
    raw2, err2 = tcp_transact(
        host,
        port,
        _CLIENT_BANNER,
        recv_first=True,
        timeout=max(4.0, settings.timeout_seconds),
        max_bytes=8192,
    )
    elapsed2 = _time.monotonic() - t1
    if err2 and not raw2:
        return [
            Indicator(
                id="fsm.stateless_trap_behavior",
                title="SSH session continuity failure after abrupt drop",
                category="proto_conformance",
                triggered=False,
                protocol="ssh",
                detail="reconnect failed after drop",
                evidence=f"t1={elapsed1:.4f} err2={err2}",
                requires_corroboration=True,
                tell_tier="origin",
            )
        ]
    identical = raw1 == raw2 and len(raw1) > 32
    robotic = elapsed1 < 0.02 and elapsed2 < 0.02 and identical
    triggered = robotic or (identical and abs(elapsed1 - elapsed2) < 0.005)
    detail = (
        f"identical canned handshake on reconnect (t1={elapsed1 * 1000:.1f}ms t2={elapsed2 * 1000:.1f}ms)"
        if triggered
        else f"reconnect timing plausible (t1={elapsed1 * 1000:.1f}ms t2={elapsed2 * 1000:.1f}ms)"
    )
    return [
        Indicator(
            id="fsm.stateless_trap_behavior",
            title="SSH session continuity failure after abrupt drop",
            category="proto_conformance",
            triggered=triggered,
            protocol="ssh",
            detail=detail,
            evidence=f"len1={len(raw1)} len2={len(raw2)} identical={identical}",
            requires_corroboration=True,
            tell_tier="origin",
            remediation="Vary SSH handshake state across reconnects; avoid canned KEXINIT buffers",
        )
    ]
