"""SMTP fingerprint engine.

Strategies: arbitrary auth (AUTH any-password, open relay) · state non-persistence
(lost envelope, RSET-ignored envelope) · static signature (loopback identity,
STARTTLS capability lie).
"""

from __future__ import annotations

import base64
import ssl
from contextlib import suppress

from honeypot_auditor.config import (
    SMTP_HELO,
    SMTP_MAIL_FROM,
    SMTP_RCPT_TO,
    match_smtp_extension_monotone,
    match_smtp_lost_envelope,
    match_smtp_placeholder_identity,
    match_smtp_rset_envelope,
    match_smtp_starttls_lie,
)
from honeypot_auditor.models import Indicator, optional_import
from honeypot_auditor.netutil import closed_reason
from honeypot_auditor.probes.common import random_creds, skip_suite
from honeypot_auditor.settings import settings

_SMTP_SKIP = (
    ("smtp.open_relay", "SMTP accepts arbitrary external RCPT TO", "arbitrary_auth"),
    ("smtp.arbitrary_auth", "SMTP AUTH accepts random credentials", "arbitrary_auth"),
    ("smtp.identity", "SMTP greeting/EHLO identity is a placeholder", "static_signature"),
    ("smtp.extensions", "SMTP VRFY/EXPN/STARTTLS/ETRN replies are monotone", "static_signature"),
    (
        "smtp.starttls_lie",
        "SMTP advertises STARTTLS but the TLS handshake fails",
        "static_signature",
    ),
    ("smtp.envelope", "SMTP envelope is not stored after MAIL FROM", "state_nonpersist"),
    (
        "smtp.rset_envelope",
        "SMTP envelope survives RSET (transaction state is canned)",
        "state_nonpersist",
    ),
)


def probe_smtp(host: str, port: int) -> list[Indicator]:
    smtplib = optional_import("smtplib")
    if smtplib is None:
        return skip_suite(_SMTP_SKIP, "smtplib missing", protocol="smtp")
    greeting = ""
    ehlo_text = ""
    auth_ok = False
    auth_detail = ""
    auth_err = ""
    try:
        smtp = smtplib.SMTP(
            timeout=settings.timeout_seconds,
            # local_hostname skips smtplib's eager socket.getfqdn() — a multi-second
            # DNS stall on hosts whose name does not resolve; EHLO uses SMTP_HELO anyway.
            local_hostname=SMTP_HELO,
        )
        _code, greet_msg = smtp.connect(host, port)
        greeting = _smtp_text(greet_msg)
        try:
            _ehlo_code, ehlo_msg = smtp.ehlo(SMTP_HELO)
            ehlo_text = _smtp_text(ehlo_msg)
        except Exception:
            try:
                _helo_code, helo_msg = smtp.helo(SMTP_HELO)
                ehlo_text = _smtp_text(helo_msg)
            except Exception:
                smtp.helo(SMTP_HELO)

        user, password = random_creds()
        try:
            auth_ok, auth_detail = _smtp_try_any_auth(smtp, user, password)
        except Exception as exc:
            auth_err = closed_reason(str(exc))
            auth_detail = auth_err

        ext_replies = _smtp_extension_replies(smtp)
        ext_hit = match_smtp_extension_monotone(ext_replies)

        with suppress(Exception):
            smtp.rset()
        mail_code, mail_msg = _smtp_mail(smtp)
        code, msg = _smtp_rcpt(smtp)
        rset_code, _rset_msg = _smtp_rset(smtp)
        rcpt2_code, _rcpt2_msg = _smtp_rcpt(smtp)
        rset_hit = match_smtp_rset_envelope(mail_code, rset_code, rcpt2_code)
        with suppress(Exception):
            smtp.quit()
        tls_code, tls_error = 0, ""
        if "starttls" in ehlo_text.lower():
            tls_code, tls_error = _smtp_starttls_probe(host, port, settings.timeout_seconds)
        tls_hit = match_smtp_starttls_lie(ehlo_text, tls_code, tls_error)
        accepted = 200 <= int(code) < 300
        identity_blob = f"{greeting}\n{ehlo_text}"
        identity_hit = match_smtp_placeholder_identity(identity_blob)
        envelope_hit = match_smtp_lost_envelope(mail_code, code, _smtp_text(msg))
        return [
            Indicator(
                id="smtp.open_relay",
                title="SMTP accepts arbitrary external RCPT TO",
                category="arbitrary_auth",
                triggered=accepted,
                protocol="smtp",
                detail=f"RCPT TO:<{SMTP_RCPT_TO}> → {code} {msg!r}",
                evidence=str(code),
            ),
            Indicator(
                id="smtp.arbitrary_auth",
                title="SMTP AUTH accepts random credentials",
                category="arbitrary_auth",
                triggered=auth_ok,
                skipped=bool(auth_err) and not auth_ok,
                skip_reason=auth_err,
                protocol="smtp",
                detail=auth_detail or "AUTH not accepted with random credentials",
                evidence=user,
            ),
            Indicator(
                id="smtp.identity",
                title="SMTP greeting/EHLO identity is a placeholder",
                category="static_signature",
                triggered=bool(identity_hit),
                protocol="smtp",
                detail=identity_hit or (identity_blob.strip()[:240] or "(no greeting)"),
                evidence=identity_blob[:800],
            ),
            Indicator(
                id="smtp.extensions",
                title="SMTP VRFY/EXPN/STARTTLS/ETRN replies are monotone",
                category="static_signature",
                triggered=bool(ext_hit),
                protocol="smtp",
                detail=ext_hit or "VRFY/EXPN/STARTTLS/ETRN replies look distinct",
                evidence="; ".join(f"{cmd} {code}" for cmd, code, _ in ext_replies),
            ),
            Indicator(
                id="smtp.starttls_lie",
                title="SMTP advertises STARTTLS but the TLS handshake fails",
                category="static_signature",
                triggered=bool(tls_hit),
                protocol="smtp",
                detail=tls_hit
                or "STARTTLS handshake completed, was refused, or was not advertised",
                evidence=f"STARTTLS → {tls_code}; tls_error={tls_error!r}",
            ),
            Indicator(
                id="smtp.envelope",
                title="SMTP envelope is not stored after MAIL FROM",
                category="state_nonpersist",
                triggered=bool(envelope_hit),
                protocol="smtp",
                detail=(
                    envelope_hit
                    or f"MAIL FROM → {mail_code} {_smtp_text(mail_msg)[:80]}; RCPT → {code}"
                ),
                evidence=f"{mail_code} {_smtp_text(mail_msg)[:200]} | {code} {_smtp_text(msg)[:200]}",
            ),
            Indicator(
                id="smtp.rset_envelope",
                title="SMTP envelope survives RSET (transaction state is canned)",
                category="state_nonpersist",
                triggered=bool(rset_hit),
                protocol="smtp",
                detail=(
                    rset_hit
                    or f"RSET → {rset_code}; post-RSET RCPT → {rcpt2_code} (real MTAs: 503 need MAIL)"
                ),
                evidence=f"MAIL {mail_code} | RSET {rset_code} | RCPT {rcpt2_code}",
            ),
        ]
    except Exception as exc:
        return skip_suite(_SMTP_SKIP, closed_reason(str(exc)), protocol="smtp", error=str(exc))


def _smtp_text(msg: object) -> str:
    if msg is None:
        return ""
    if isinstance(msg, bytes):
        return msg.decode("utf-8", "replace")
    return str(msg)


def _smtp_reply(ret: object, default_code: int = 0) -> tuple[int, object]:
    if isinstance(ret, tuple) and len(ret) >= 2:
        try:
            return int(ret[0]), ret[1]
        except (TypeError, ValueError):
            return default_code, ret[1]
    return default_code, ret


def _smtp_mail(smtp) -> tuple[int, object]:
    try:
        return _smtp_reply(smtp.mail(SMTP_MAIL_FROM))
    except Exception as exc:
        return 0, str(exc)


def _smtp_rcpt(smtp) -> tuple[int, object]:
    try:
        return _smtp_reply(smtp.rcpt(SMTP_RCPT_TO))
    except Exception as exc:
        return 0, str(exc)


def _smtp_extension_replies(smtp) -> list[tuple[str, int, str]]:
    """VRFY/EXPN/ETRN/STARTTLS — real MTAs return distinct RFC codes, pots often one stub."""
    replies: list[tuple[str, int, str]] = []
    for cmd, arg in (
        ("VRFY", "root"),
        ("EXPN", "root"),
        ("ETRN", "auditor.invalid"),
        ("STARTTLS", ""),
    ):
        try:
            ret = smtp.docmd(cmd, arg) if arg else smtp.docmd(cmd)
            code, msg = _smtp_reply(ret)
            replies.append((cmd, code, _smtp_text(msg)))
        except Exception as exc:
            replies.append((cmd, 0, str(exc)))
    return replies


def _smtp_rset(smtp) -> tuple[int, object]:
    try:
        return _smtp_reply(smtp.docmd("RSET"))
    except Exception as exc:
        return 0, str(exc)


def _tls_wrap(sock, timeout: float):
    """Wrap a cleartext socket with TLS (verification off — fingerprinting only)."""
    sock.settimeout(timeout)  # bound the handshake itself, not just post-TLS reads
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    wrapped = context.wrap_socket(sock)
    wrapped.settimeout(timeout)
    return wrapped


def _smtp_starttls_probe(host: str, port: int, timeout: float) -> tuple[int, str]:
    """Fresh connection: STARTTLS then a TLS handshake attempt.

    Returns (reply_code, tls_error). Uses its own session so a botched
    handshake cannot poison the main envelope/relay probes. Verification is
    disabled by design (fingerprinting, not trust).
    """
    smtplib = optional_import("smtplib")
    if smtplib is None:
        return 0, ""
    try:
        st = smtplib.SMTP(timeout=timeout, local_hostname="hpaudit-auditor.invalid")
        st.connect(host, port)
    except Exception:
        return 0, ""
    try:
        code, _msg = _smtp_reply(st.docmd("STARTTLS"))
        starttls_code = int(code)
    except Exception:
        return 0, ""
    if starttls_code != 220:
        with suppress(Exception):
            st.quit()
        return starttls_code, ""
    try:
        _tls_wrap(st.sock, timeout)
        return starttls_code, ""
    except Exception as exc:
        return starttls_code, closed_reason(str(exc))
    finally:
        with suppress(Exception):
            st.close()


def _smtp_try_any_auth(smtp, user: str, password: str) -> tuple[bool, str]:
    """Random USER/PASS via AUTH PLAIN (or login). Real MTAs reject; lures often 235 any password."""
    blob = base64.b64encode(b"\0" + user.encode() + b"\0" + password.encode()).decode("ascii")
    with suppress(Exception):
        code, msg = smtp.docmd("AUTH", f"PLAIN {blob}")
        if 200 <= int(code) < 300:
            return True, f"AUTH PLAIN accepted random {user}:**** → {code}"
        if int(code) in {502, 503, 504}:
            pass
        else:
            return False, f"AUTH PLAIN rejected → {code} {_smtp_text(msg)[:80]}"
    try:
        smtp.login(user, password)
        return True, f"AUTH login accepted random {user}:****"
    except Exception as exc:
        return False, f"AUTH rejected random creds ({closed_reason(str(exc))})"
