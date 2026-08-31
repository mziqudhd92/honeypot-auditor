"""FTP fingerprint engine.

Strategies: arbitrary auth (stock decoy login) · state non-persistence (PASV mismatch, canned 530, STOR) · static signature (stock 220).
"""

from __future__ import annotations

import io
import secrets

from honeypot_auditor.config import (
    FTP_LURE_ACCOUNTS,
    FTP_PROBE_BODY,
    FTP_PROBE_PREFIX,
    FTP_SYST_TELLS,
    FTP_WELCOME_TELLS,
    match_ftp_auth_lure,
    match_ftp_command_desert,
    match_ftp_port_bounce,
    match_ftp_stale_banner,
)
from honeypot_auditor.models import Indicator, optional_import, skipped_indicator
from honeypot_auditor.netutil import closed_reason, is_non_routable_ip, parse_ftp_pasv_host
from honeypot_auditor.probes.common import random_creds, skip_suite
from honeypot_auditor.settings import settings

_FTP_SKIP = (
    ("ftp.persist", "FTP upload does not persist across reconnect", "state_nonpersist"),
    ("ftp.banner", "FTP welcome is a stock/default 220 or emulator template", "static_signature"),
    ("ftp.auth_lure", "FTP canned auth reject (fake login FSM)", "state_nonpersist"),
    ("ftp.arbitrary_auth", "FTP accepts random or stock decoy credentials", "arbitrary_auth"),
    ("ftp.bounce", "FTP PORT accepts an external bounce address", "static_signature"),
    ("ftp.desert", "FTP command set is a shallow unknown-command desert", "state_nonpersist"),
)


def probe_ftp(host: str, port: int) -> list[Indicator]:
    ftplib = optional_import("ftplib")
    if ftplib is None:
        return skip_suite(_FTP_SKIP, "ftplib missing", protocol="ftp")

    welcome = ""
    user_resp = ""
    pass_resp = ""
    login_user = ""
    login_pass = ""
    auth_kind = ""
    auth_user = ""
    pasv_private = False
    pasv_resp = ""
    syst_line = ""
    bounce_hit = None
    bounce_attempted = False
    desert_hit = None
    desert_evidence = ""
    cmd_tells: list[str] = []
    upload_names: list[str] = []
    upload_ok = False
    upload_err = ""

    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=settings.timeout_seconds)
        welcome = ftp.getwelcome() or ""
        desert_hit, desert_evidence = _ftp_desert_probe(ftp)
        ftp, welcome, login_ok, auth_kind, login_user, login_pass, user_resp, pass_resp = _ftp_walk_auth(
            ftplib, host, port, ftp, welcome
        )
        auth_user = login_user
        if not login_ok:
            return _ftp_suite(
                skipped_indicator(
                    "ftp.persist",
                    "FTP upload does not persist across reconnect",
                    "state_nonpersist",
                    "login rejected (persist skipped)",
                    protocol="ftp",
                ),
                welcome,
                user_resp=user_resp,
                pass_resp=pass_resp,
                auth_kind=auth_kind,
                auth_user=auth_user,
                auth_pass=login_pass,
                bounce_hit=bounce_hit,
                bounce_attempted=False,
                desert_hit=desert_hit,
                desert_evidence=desert_evidence,
            )
        ftp.timeout = settings.timeout_seconds

        try:
            pasv_resp = str(ftp.sendcmd("PASV") or "")
            pasv_host = parse_ftp_pasv_host(pasv_resp)
            if pasv_host and is_non_routable_ip(pasv_host):
                pasv_private = True
                cmd_tells.append(f"PASV advertises non-routable {pasv_host}")
            if pasv_host and pasv_host != host:
                pasv_private = True
                cmd_tells.append(f"PASV address mismatch {pasv_host} vs {host}")
        except Exception as exc:
            cmd_tells.append(f"PASV error: {exc}")

        try:
            ftp.sendcmd("FEAT")
        except Exception:
            pass

        try:
            syst_line = ftp.sendcmd("SYST")
        except Exception:
            pass

        try:
            bounce_resp = str(ftp.sendcmd("PORT 8,8,8,8,0,53") or "")
            bounce_attempted = True
            bounce_hit = match_ftp_port_bounce(bounce_resp)
            if bounce_hit:
                cmd_tells.append(bounce_hit)
        except Exception as exc:
            bounce_attempted = True
            cmd_tells.append(f"PORT {closed_reason(str(exc))}")

        try:
            ftp.sendcmd("REST 0")
        except Exception:
            pass

        for cmd in ("NLST", "MLSD"):
            try:
                ftp.sendcmd(cmd)
            except Exception as exc:
                msg = str(exc)
                if "502" in msg or "504" in msg or "not implemented" in msg.lower():
                    cmd_tells.append(f"{cmd} unsupported")

        try:
            ftp.voidcmd("TYPE A")
        except Exception:
            cmd_tells.append("TYPE A rejected")

        try:
            ftp.sendcmd("TYPE I")
        except Exception:
            pass

        _ftp_cwd_probe_dir(ftp)
        for _ in range(2):
            name = f"{FTP_PROBE_PREFIX}{secrets.token_hex(4)}.txt"
            upload_names.append(name)
            try:
                resp = ftp.storbinary(f"STOR {name}", io.BytesIO(FTP_PROBE_BODY))
                if resp and "226" in resp:
                    upload_ok = True
                    try:
                        size_resp = str(ftp.sendcmd(f"SIZE {name}") or "")
                        if not size_resp.startswith("213"):
                            cmd_tells.append(f"STOR 226 but SIZE {size_resp[:40]!r}")
                    except Exception as exc:
                        cmd_tells.append(f"STOR 226 but SIZE failed: {closed_reason(str(exc))}")
            except Exception as exc:
                upload_err = closed_reason(str(exc))
                cmd_tells.append(f"STOR {name} failed: {upload_err}")

        try:
            ftp.quit()
        except Exception as exc:
            q = closed_reason(str(exc))
            cmd_tells.append(f"QUIT {q}")
    except Exception as exc:
        return _ftp_suite(
            skipped_indicator(
                "ftp.persist",
                "FTP upload does not persist across reconnect",
                "state_nonpersist",
                f"FTP session failed: {closed_reason(str(exc))}",
                protocol="ftp",
                error=str(exc),
            ),
            welcome,
            exc=exc,
            syst_line=syst_line,
            cmd_tells=cmd_tells,
            pasv_private=pasv_private,
            user_resp=user_resp,
            pass_resp=pass_resp,
            auth_kind=auth_kind,
            auth_user=auth_user,
            auth_pass=login_pass,
            bounce_hit=bounce_hit,
            bounce_attempted=bounce_attempted,
            desert_hit=desert_hit,
            desert_evidence=desert_evidence,
        )

    banner_ind = _ftp_banner_indicator(
        welcome,
        syst_line=syst_line,
        cmd_tells=cmd_tells,
        pasv_private=pasv_private,
    )
    lure_ind = _ftp_auth_lure_indicator(user_resp, pass_resp)
    auth_ind = _ftp_arbitrary_auth_indicator(auth_kind, auth_user, login_pass)

    persisted_any = False
    verify_notes: list[str] = []
    try:
        ftp2 = ftplib.FTP()
        ftp2.connect(host, port, timeout=settings.timeout_seconds)
        _ftp_login(ftp2, login_user, login_pass)
        ftp2.timeout = settings.timeout_seconds
        try:
            ftp2.sendcmd("TYPE I")
        except Exception:
            pass
        _ftp_cwd_probe_dir(ftp2)
        for name in upload_names:
            try:
                mdtm = ftp2.sendcmd(f"MDTM {name}")
                if mdtm.startswith("213"):
                    persisted_any = True
                    verify_notes.append(f"{name} MDTM ok")
            except Exception as exc:
                verify_notes.append(f"{name} missing ({exc})")
            try:
                size_resp = ftp2.sendcmd(f"SIZE {name}")
                if str(size_resp).startswith("213"):
                    persisted_any = True
                    verify_notes.append(f"{name} SIZE ok")
            except Exception as exc:
                verify_notes.append(f"{name} SIZE missing ({exc})")
        try:
            listing = ftp2.sendcmd("LIST")
            if listing and upload_names and any(n in listing for n in upload_names):
                persisted_any = True
                verify_notes.append("LIST shows uploaded name")
        except Exception as exc:
            verify_notes.append(f"LIST failed ({exc})")
        try:
            for name in upload_names:
                if persisted_any:
                    try:
                        ftp2.delete(name)
                    except Exception:
                        pass
        except Exception:
            pass
        ftp2.quit()
    except Exception as exc:
        if pasv_private or not upload_ok:
            return _ftp_suite(
                Indicator(
                    id="ftp.persist",
                    title="FTP upload does not persist across reconnect",
                    category="state_nonpersist",
                    triggered=True,
                    protocol="ftp",
                    detail=(
                        f"non-routable PASV data path; upload surface not verifiable ({closed_reason(str(exc))})"
                        if pasv_private
                        else f"STOR failed and reconnect verify failed: {closed_reason(str(exc))}"
                    ),
                    evidence=" | ".join(cmd_tells)[:800],
                ),
                welcome,
                banner_ind=banner_ind,
                lure_ind=lure_ind,
                auth_ind=auth_ind,
                bounce_hit=bounce_hit,
                bounce_attempted=bounce_attempted,
                desert_hit=desert_hit,
                desert_evidence=desert_evidence,
            )
        return _ftp_suite(
            skipped_indicator(
                "ftp.persist",
                "FTP upload does not persist across reconnect",
                "state_nonpersist",
                f"reconnect verify failed: {closed_reason(str(exc))}",
                protocol="ftp",
                error=str(exc),
            ),
            welcome,
            banner_ind=banner_ind,
            lure_ind=lure_ind,
            auth_ind=auth_ind,
            bounce_hit=bounce_hit,
            bounce_attempted=bounce_attempted,
            desert_hit=desert_hit,
            desert_evidence=desert_evidence,
        )

    fake_upload_surface = pasv_private or (not upload_ok and bool(upload_names))
    non_persist = fake_upload_surface or (upload_ok and not persisted_any) or (bool(upload_names) and not persisted_any)
    persist_detail = "; ".join(
        x
        for x in [
            pasv_resp.strip() if pasv_private else "",
            upload_err or "",
            "; ".join(verify_notes[:4]),
        ]
        if x
    )[:240]

    return _ftp_suite(
        Indicator(
            id="ftp.persist",
            title="FTP upload does not persist across reconnect",
            category="state_nonpersist",
            triggered=non_persist,
            protocol="ftp",
            detail=(
                persist_detail
                or (
                    f"uploaded {len(upload_names)} probe file(s); none verified after reconnect"
                    if non_persist
                    else f"probe file verified on reconnect ({verify_notes[0] if verify_notes else 'ok'})"
                )
            ),
            evidence=" | ".join(cmd_tells + verify_notes)[:800],
        ),
        welcome,
        banner_ind=banner_ind,
        lure_ind=lure_ind,
        auth_ind=auth_ind,
        bounce_hit=bounce_hit,
        bounce_attempted=bounce_attempted,
        desert_hit=desert_hit,
        desert_evidence=desert_evidence,
    )


def _ftp_open(ftplib, host: str, port: int):
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=settings.timeout_seconds)
    ftp.timeout = settings.timeout_seconds
    return ftp, ftp.getwelcome() or ""


def _ftp_close(ftp) -> None:
    try:
        ftp.quit()
    except Exception:
        try:
            ftp.close()
        except Exception:
            pass


def _ftp_walk_auth(ftplib, host: str, port: int, ftp, welcome: str):
    """Anonymous, then random, then a short stock decoy list (test with empty password, …)."""
    rand_user, rand_pass = random_creds()
    attempts: list[tuple[str, str, str]] = [
        ("anonymous", "anonymous", "guest@"),
        ("random", rand_user, rand_pass),
        *(("lure", u, p) for u, p in FTP_LURE_ACCOUNTS),
    ]
    user_blob = ""
    pass_blob = ""
    for kind, user, password in attempts:
        if ftp is None:
            ftp, w = _ftp_open(ftplib, host, port)
            welcome = welcome or w
        user_resp, pass_resp, ok = _ftp_try_login(ftp, user, password)
        user_blob = f"{user_blob}\n{user_resp}".strip()
        pass_blob = f"{pass_blob}\n{pass_resp}".strip()
        if ok:
            return ftp, welcome, True, kind, user, password, user_blob, pass_blob
        if _ftp_session_dead(user_resp, pass_resp):
            _ftp_close(ftp)
            ftp = None
    return ftp, welcome, False, "", "", "", user_blob, pass_blob


def _ftp_session_dead(user_resp: str, pass_resp: str) -> bool:
    blob = f"{user_resp} {pass_resp}".lower()
    return any(t in blob for t in ("timed out", "reset", "not connected", "eof", "421", "broken pipe"))


def _ftp_try_login(ftp, user: str, password: str) -> tuple[str, str, bool]:
    user_resp = ""
    pass_resp = ""
    try:
        user_resp = str(ftp.sendcmd(f"USER {user}"))
    except Exception as exc:
        return str(exc), pass_resp, False
    try:
        pass_cmd = f"PASS {password}" if password else "PASS"
        pass_resp = str(ftp.sendcmd(pass_cmd))
        return user_resp, pass_resp, True
    except Exception as exc:
        return user_resp, str(exc), False


def _ftp_login(ftp, username: str = "", password: str = "") -> None:
    if username:
        ftp.login(username, password)
        return
    try:
        ftp.login()
    except Exception:
        ftp.login("anonymous", "guest@")


def _ftp_cwd_probe_dir(ftp) -> None:
    for path in ("incoming", "/incoming", "/"):
        try:
            ftp.cwd(path)
            return
        except Exception:
            continue


def _ftp_banner_hit(
    welcome: str,
    syst_line: str = "",
    cmd_tells: list[str] | None = None,
    *,
    pasv_private: bool = False,
) -> str | None:
    stale = match_ftp_stale_banner(welcome)
    if stale:
        return stale
    for tell in FTP_WELCOME_TELLS:
        if tell.lower() in (welcome or "").lower():
            return tell
    for tell in FTP_SYST_TELLS:
        if tell.lower() in (syst_line or "").lower():
            return tell
    if pasv_private and (welcome or syst_line):
        return "non-routable PASV endpoint"
    if cmd_tells and sum("unsupported" in t or "TYPE A rejected" in t for t in cmd_tells) >= 2:
        return "FTP command surface inconsistent with production servers"
    return None


def _ftp_desert_probe(ftp) -> tuple[str | None, str]:
    """Pre-auth FEAT/PWD/PASV/NOOP — shallow emulators answer 500 Unknown Command for all."""
    responses: dict[str, str] = {}
    for cmd in ("FEAT", "PWD", "PASV", "NOOP"):
        try:
            responses[cmd] = str(ftp.sendcmd(cmd) or "")
        except Exception as exc:
            responses[cmd] = str(exc)
    hit = match_ftp_command_desert(responses)
    evidence = " | ".join(f"{k}={v[:50]}" for k, v in responses.items())
    return hit, evidence


def _ftp_suite(
    persist: Indicator,
    welcome: str,
    *,
    banner_ind: Indicator | None = None,
    lure_ind: Indicator | None = None,
    auth_ind: Indicator | None = None,
    exc: Exception | None = None,
    syst_line: str = "",
    cmd_tells: list[str] | None = None,
    pasv_private: bool = False,
    user_resp: str = "",
    pass_resp: str = "",
    auth_kind: str = "",
    auth_user: str = "",
    auth_pass: str = "",
    bounce_hit: str | None = None,
    bounce_attempted: bool = False,
    desert_hit: str | None = None,
    desert_evidence: str = "",
) -> list[Indicator]:
    banner = banner_ind or _ftp_banner_indicator(
        welcome,
        exc=exc,
        syst_line=syst_line,
        cmd_tells=cmd_tells,
        pasv_private=pasv_private,
    )
    lure = lure_ind or _ftp_auth_lure_indicator(user_resp, pass_resp, exc=exc)
    auth = auth_ind or _ftp_arbitrary_auth_indicator(auth_kind, auth_user, auth_pass)
    bounce = Indicator(
        id="ftp.bounce",
        title="FTP PORT accepts an external bounce address",
        category="static_signature",
        triggered=bool(bounce_hit),
        skipped=not bounce_attempted,
        skip_reason="" if bounce_attempted else "PORT not issued (no login)",
        protocol="ftp",
        detail=bounce_hit or "PORT to an unrelated address was not accepted",
    )
    desert = Indicator(
        id="ftp.desert",
        title="FTP command set is a shallow unknown-command desert",
        category="state_nonpersist",
        triggered=bool(desert_hit),
        skipped=not desert_evidence and not desert_hit,
        skip_reason="" if desert_evidence or desert_hit else "command desert not probed",
        protocol="ftp",
        detail=desert_hit or "FEAT/PWD/PASV/NOOP are not a uniform 500 desert",
        evidence=desert_evidence[:800],
    )
    return [persist, banner, lure, auth, bounce, desert]


def _ftp_banner_indicator(
    welcome: str,
    *,
    banner_hit: str | None = None,
    exc: Exception | None = None,
    syst_line: str = "",
    cmd_tells: list[str] | None = None,
    pasv_private: bool = False,
) -> Indicator:
    hit = banner_hit
    if hit is None:
        hit = _ftp_banner_hit(welcome, syst_line, cmd_tells, pasv_private=pasv_private)
    detail_parts = [welcome[:120] if welcome else ""]
    if syst_line:
        detail_parts.append(str(syst_line).strip()[:80])
    if cmd_tells:
        detail_parts.append("; ".join(cmd_tells[:3]))
    detail = " | ".join(p for p in detail_parts if p) or (closed_reason(str(exc)) if exc else "(no welcome)")
    if welcome or hit:
        return Indicator(
            id="ftp.banner",
            title="FTP welcome is a stock/default 220 or emulator template",
            category="static_signature",
            triggered=bool(hit),
            protocol="ftp",
            detail=detail[:240],
            evidence=hit or "",
        )
    return skipped_indicator(
        "ftp.banner",
        "FTP welcome is a stock/default 220 or emulator template",
        "static_signature",
        closed_reason(str(exc)) if exc else "no welcome banner",
        protocol="ftp",
        error=str(exc) if exc else "",
    )


def _ftp_auth_lure_indicator(user_resp: str, pass_resp: str, *, exc: Exception | None = None) -> Indicator:
    hit = match_ftp_auth_lure(user_resp, pass_resp)
    transcript = f"{user_resp}\n{pass_resp}".strip()
    if not transcript and not hit:
        return skipped_indicator(
            "ftp.auth_lure",
            "FTP canned auth reject (fake login FSM)",
            "state_nonpersist",
            closed_reason(str(exc)) if exc else "no USER/PASS transcript",
            protocol="ftp",
            error=str(exc) if exc else "",
        )
    return Indicator(
        id="ftp.auth_lure",
        title="FTP canned auth reject (fake login FSM)",
        category="state_nonpersist",
        triggered=bool(hit),
        protocol="ftp",
        detail=(f"canned auth {hit!r}" if hit else "no canned USER/PASS lure"),
        evidence=transcript[:800],
    )


def _ftp_arbitrary_auth_indicator(kind: str, user: str, password: str = "") -> Indicator:
    triggered = kind in {"random", "lure"}
    if kind == "lure":
        pw = "empty password" if not password else "****"
        detail = f"stock decoy account {user} accepted ({pw}; anonymous/random rejected)"
    elif kind == "random":
        detail = f"random {user}:**** accepted"
    elif kind == "anonymous":
        detail = "anonymous login accepted (not a decoy-account tell)"
    else:
        detail = "anonymous, random, and stock decoy accounts rejected"
    return Indicator(
        id="ftp.arbitrary_auth",
        title="FTP accepts random or stock decoy credentials",
        category="arbitrary_auth",
        triggered=triggered,
        protocol="ftp",
        detail=detail,
        evidence=user if triggered else kind,
    )
