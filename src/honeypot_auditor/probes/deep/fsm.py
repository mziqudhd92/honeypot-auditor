"""Deep probe #4: protocol FSM / RFC edge-case conformance."""

from __future__ import annotations

import re

from honeypot_auditor.config import USER_AGENT
from honeypot_auditor.models import Indicator, optional_import, skipped_indicator
from honeypot_auditor.netutil import closed_reason, is_non_routable_ip, parse_ftp_pasv_host, tcp_transact
from honeypot_auditor.settings import settings


def probe_http_fsm(host: str, port: int) -> list[Indicator]:
    failures: list[str] = []
    evidence: list[str] = []

    # Pipelined GET + malformed method
    piped = (
        b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: keep-alive\r\n\r\n"
        b"FOOBAR / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n"
    )
    raw, err = tcp_transact(host, port, piped, recv_first=False, timeout=max(4.0, settings.timeout_seconds))
    text = raw.decode("latin-1", "replace")
    evidence.append(f"pipeline: {text[:300]!r}")
    statuses = re.findall(r"HTTP/\d\.\d (\d{3})", text)
    if len(statuses) >= 2 and statuses[0] == statuses[1] == "200":
        failures.append("pipelined bad method returned duplicate static 200")

    # Header-order Date monotonicity via requests if available
    requests = optional_import("requests")
    dates: list[str] = []
    if requests is not None:
        import time as _time

        for _ in range(2):
            try:
                resp = requests.get(
                    f"http://{host}:{port}/",
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

    if err and not raw:
        return [
            skipped_indicator(
                "deep.http_fsm",
                "HTTP FSM / RFC edge-case conformance failure",
                "proto_conformance",
                closed_reason(err),
                protocol="http",
                error=err,
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
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=settings.timeout_seconds)
        ftp.login()
        feat = ""
        try:
            feat = ftp.sendcmd("FEAT")
        except Exception:
            pass
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
        evidence = greeting[:200]
        try:
            smtp.docmd("VRFY", "root")
        except smtplib.SMTPException as exc:
            if "502" not in str(exc) and "252" not in str(exc):
                failures.append(f"VRFY unexpected: {exc}")
        try:
            smtp.docmd("RSET")
            rcpt_code, _rcpt_msg = smtp.docmd("RCPT TO:<fake@external-domain.com>")
            if rcpt_code == 250:
                failures.append("RSET+RCPT accepted external recipient without MAIL FROM")
        except smtplib.SMTPException as exc:
            if "250" in str(exc):
                failures.append("RSET+RCPT accepted external recipient without MAIL FROM")
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
