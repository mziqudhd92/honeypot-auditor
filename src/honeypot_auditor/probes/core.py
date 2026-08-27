"""SSH, Telnet, SMB, and FTP fingerprint engines."""

from __future__ import annotations

import io
import secrets

from honeypot_auditor.config import (
    FTP_PROBE_BODY,
    FTP_PROBE_PREFIX,
    FTP_SYST_TELLS,
    FTP_WELCOME_TELLS,
    PROBE_PASSWORD_TEMPLATE,
    PROBE_USERNAME_TEMPLATE,
    SMB_NATIVE_OS_TELLS,
    SMB_SMB1_DIALECTS,
    match_cpuinfo_signature,
    match_ssh_banner,
    match_uname_signature,
)
from honeypot_auditor.models import Indicator, optional_import, skipped_indicator
from honeypot_auditor.netutil import (
    closed_reason,
    is_non_routable_ip,
    parse_ftp_pasv_host,
    tcp_transact,
)
from honeypot_auditor.settings import settings


def probe_ssh(host: str, port: int) -> list[Indicator]:
    paramiko = optional_import("paramiko")
    if paramiko is None:
        return [
            skipped_indicator("ssh.banner", "SSH static banner signature", "static_signature", "paramiko not installed", protocol="ssh"),
            skipped_indicator("ssh.arbitrary_auth", "SSH arbitrary credential acceptance", "arbitrary_auth", "paramiko not installed", protocol="ssh"),
            skipped_indicator("ssh.uname", "SSH uname/cpuinfo emulator signature", "static_signature", "paramiko not installed", protocol="ssh"),
        ]

    user, password = _random_creds()
    banner = ""
    auth_ok = False
    uname = ""
    cpuinfo = ""
    err = ""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=settings.timeout_seconds,
                banner_timeout=settings.timeout_seconds,
                auth_timeout=settings.timeout_seconds,
                allow_agent=False,
                look_for_keys=False,
            )
            auth_ok = True
        except paramiko.AuthenticationException:
            auth_ok = False
        except Exception as exc:
            err = str(exc)
        transport = client.get_transport()
        if transport is not None:
            banner = transport.remote_version or ""
        if auth_ok:
            uname = _ssh_exec(client, "uname -a")
            cpuinfo = _ssh_exec(client, "cat /proc/cpuinfo")
    except Exception as exc:
        err = str(exc)
    finally:
        try:
            client.close()
        except Exception:
            pass

    if err and not banner:
        reason = closed_reason(err)
        return [
            skipped_indicator("ssh.banner", "SSH static banner signature", "static_signature", reason, protocol="ssh", error=err),
            skipped_indicator("ssh.arbitrary_auth", "SSH arbitrary credential acceptance", "arbitrary_auth", reason, protocol="ssh", error=err),
            skipped_indicator("ssh.uname", "SSH uname/cpuinfo emulator signature", "static_signature", reason, protocol="ssh", error=err),
        ]

    banner_hit = match_ssh_banner(banner)
    cpu_hit = match_cpuinfo_signature(cpuinfo)
    uname_hit = match_uname_signature(uname)
    static_bits = []
    if banner_hit:
        static_bits.append(f"banner={banner_hit}")
    if uname_hit:
        static_bits.append(f"uname={uname_hit}")
    if cpu_hit:
        static_bits.append(f"cpuinfo={cpu_hit}")

    uname_ind = (
        Indicator(
            id="ssh.uname",
            title="SSH uname/cpuinfo emulator signature",
            category="static_signature",
            triggered=bool(uname_hit or cpu_hit),
            protocol="ssh",
            detail="; ".join(static_bits) if static_bits else ((uname or cpuinfo or "")[:240] or "no exec output"),
            evidence=(uname + "\n" + cpuinfo)[:1500],
        )
        if auth_ok
        else skipped_indicator(
            "ssh.uname",
            "SSH uname/cpuinfo emulator signature",
            "static_signature",
            "no session (auth failed)",
            protocol="ssh",
        )
    )

    return [
        Indicator(
            id="ssh.banner",
            title="SSH static banner signature",
            category="static_signature",
            triggered=bool(banner_hit),
            protocol="ssh",
            detail=banner or "(no banner)",
            evidence=banner_hit or "",
        ),
        Indicator(
            id="ssh.arbitrary_auth",
            title="SSH arbitrary credential acceptance",
            category="arbitrary_auth",
            triggered=auth_ok,
            protocol="ssh",
            detail=(
                f"random {user}:**** accepted"
                if auth_ok
                else f"random {user}:**** rejected (not an any-password handler)"
            ),
            evidence=user,
        ),
        uname_ind,
    ]


def probe_telnet(host: str, port: int) -> list[Indicator]:
    user, password = _random_creds()
    banner_raw, banner_err = tcp_transact(host, port, b"", recv_first=True)
    if banner_err and not banner_raw:
        reason = closed_reason(banner_err)
        return [
            skipped_indicator("telnet.arbitrary_auth", "Telnet arbitrary credential acceptance", "arbitrary_auth", reason, protocol="telnet", error=banner_err),
            skipped_indicator("telnet.uname", "Telnet uname/cpuinfo emulator signature", "static_signature", reason, protocol="telnet", error=banner_err),
        ]

    auth_ok, session_out, auth_err = _telnet_login_and_probe(host, port, user, password)
    if auth_err and not banner_raw and not auth_ok:
        reason = closed_reason(auth_err)
        return [
            skipped_indicator("telnet.arbitrary_auth", "Telnet arbitrary credential acceptance", "arbitrary_auth", reason, protocol="telnet", error=auth_err),
            skipped_indicator("telnet.uname", "Telnet uname/cpuinfo emulator signature", "static_signature", reason, protocol="telnet", error=auth_err),
        ]

    uname_hit = match_uname_signature(session_out)
    cpu_hit = match_cpuinfo_signature(session_out)
    return [
        Indicator(
            id="telnet.arbitrary_auth",
            title="Telnet arbitrary credential acceptance",
            category="arbitrary_auth",
            triggered=bool(auth_ok),
            protocol="telnet",
            detail=(
                f"random {user}:**** accepted"
                if auth_ok
                else f"random {user}:**** not accepted"
            ),
        ),
        Indicator(
            id="telnet.uname",
            title="Telnet uname/cpuinfo emulator signature",
            category="static_signature",
            triggered=bool(uname_hit or cpu_hit),
            protocol="telnet",
            skipped=not auth_ok,
            skip_reason="" if auth_ok else "no session (auth failed)",
            detail=(uname_hit or cpu_hit or session_out[:240] or "no exec output"),
            evidence=session_out[:1500],
        )
        if auth_ok
        else skipped_indicator(
            "telnet.uname",
            "Telnet uname/cpuinfo emulator signature",
            "static_signature",
            "no session (auth failed)",
            protocol="telnet",
        ),
    ]


def probe_smb(host: str, port: int) -> list[Indicator]:
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        return [
            skipped_indicator(
                "smb.dialect",
                "SMB dialect / native-OS emulator anomaly",
                "static_signature",
                "impacket not installed (pip install honeypot-auditor[full])",
                protocol="smb",
            )
        ]

    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=max(1, int(settings.timeout_seconds)))
        dialect = ""
        native_os = ""
        share_names: list[str] = []
        try:
            conn.login("", "")
        except Exception:
            try:
                conn.login("Guest", "")
            except Exception as exc:
                return _smb_session_failure_indicator(host, port, exc)
        try:
            dialect = str(conn.getDialect() or "")
        except Exception:
            dialect = ""
        try:
            native_os = str(getattr(conn, "getServerOS", lambda: "")() or "")
        except Exception:
            native_os = ""
        try:
            for share in conn.listShares() or []:
                name = share.get("shi1_netname") if isinstance(share, dict) else None
                if isinstance(name, bytes):
                    name = name.decode("utf-8", "replace")
                if name:
                    share_names.append(str(name).rstrip("\x00"))
        except Exception:
            pass
        try:
            conn.logoff()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
    except Exception as exc:
        return _smb_session_failure_indicator(host, port, exc)

    smb1 = dialect in SMB_SMB1_DIALECTS or dialect.upper().startswith("SMB 1") or dialect == "1"
    os_hit = any(tell.lower() in native_os.lower() for tell in SMB_NATIVE_OS_TELLS if native_os)
    triggered = bool(smb1 or os_hit)
    return [
        Indicator(
            id="smb.dialect",
            title="SMB dialect / native-OS emulator anomaly",
            category="static_signature",
            triggered=triggered,
            protocol="smb",
            detail=f"dialect={dialect or '?'} native_os={native_os or '?'} shares={share_names[:8]}",
            evidence=f"{dialect}|{native_os}",
        )
    ]


def _smb_session_failure_indicator(host: str, port: int, exc: Exception) -> list[Indicator]:
    err = str(exc)
    framing_anomaly = any(
        tok in err.lower()
        for tok in ("unpack requires", "ntlm", "protocol", "not supported", "connection reset")
    )
    if framing_anomaly:
        return [
            Indicator(
                id="smb.dialect",
                title="SMB dialect / native-OS emulator anomaly",
                category="static_signature",
                triggered=True,
                protocol="smb",
                detail=f"SMB listener up but session setup failed: {err[:160]}",
                evidence=err[:200],
            )
        ]
    raw, _ = tcp_transact(host, port, b"", recv_first=True, timeout=min(2.0, settings.timeout_seconds))
    smb_listener = bool(raw) and (raw[:1] == b"\x00" or b"SMB" in raw[:64])
    if not smb_listener:
        return [
            skipped_indicator(
                "smb.dialect",
                "SMB dialect / native-OS emulator anomaly",
                "static_signature",
                f"NTLM session not established: {err[:160]}",
                protocol="smb",
                error=err,
            )
        ]
    return [
        Indicator(
            id="smb.dialect",
            title="SMB dialect / native-OS emulator anomaly",
            category="static_signature",
            triggered=True,
            protocol="smb",
            detail=f"SMB listener up but session setup failed: {err[:160]}",
            evidence=raw[:120].hex() if raw else err[:200],
        )
    ]


def probe_ftp(host: str, port: int) -> list[Indicator]:
    ftplib = optional_import("ftplib")
    if ftplib is None:
        return [
            skipped_indicator("ftp.persist", "FTP upload does not persist across reconnect", "state_nonpersist", "ftplib missing", protocol="ftp"),
            skipped_indicator("ftp.banner", "FTP welcome banner matches emulator template", "static_signature", "ftplib missing", protocol="ftp"),
        ]

    welcome = ""
    pasv_private = False
    pasv_resp = ""
    syst_line = ""
    cmd_tells: list[str] = []
    upload_names: list[str] = []
    upload_ok = False
    upload_err = ""

    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=settings.timeout_seconds)
        welcome = ftp.getwelcome() or ""
        _ftp_login(ftp)
        ftp.timeout = settings.timeout_seconds

        try:
            pasv_resp = ftp.sendcmd("PASV")
            pasv_host = parse_ftp_pasv_host(pasv_resp)
            if pasv_host and is_non_routable_ip(pasv_host):
                pasv_private = True
                cmd_tells.append(f"PASV advertises non-routable {pasv_host}")
        except Exception as exc:
            cmd_tells.append(f"PASV error: {exc}")

        try:
            syst_line = ftp.sendcmd("SYST")
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
            except Exception as exc:
                upload_err = closed_reason(str(exc))
                cmd_tells.append(f"STOR {name} failed: {upload_err}")

        ftp.quit()
    except Exception as exc:
        return [
            skipped_indicator(
                "ftp.persist",
                "FTP upload does not persist across reconnect",
                "state_nonpersist",
                f"FTP session failed: {closed_reason(str(exc))}",
                protocol="ftp",
                error=str(exc),
            ),
            _ftp_banner_indicator(welcome, exc=exc, syst_line=syst_line, cmd_tells=cmd_tells, pasv_private=pasv_private),
        ]

    banner_hit = _ftp_banner_hit(welcome, syst_line, cmd_tells, pasv_private=pasv_private)
    banner_ind = _ftp_banner_indicator(
        welcome,
        banner_hit=banner_hit,
        syst_line=syst_line,
        cmd_tells=cmd_tells,
        pasv_private=pasv_private,
    )

    persisted_any = False
    verify_notes: list[str] = []
    try:
        ftp2 = ftplib.FTP()
        ftp2.connect(host, port, timeout=settings.timeout_seconds)
        _ftp_login(ftp2)
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
            return [
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
                banner_ind,
            ]
        return [
            skipped_indicator(
                "ftp.persist",
                "FTP upload does not persist across reconnect",
                "state_nonpersist",
                f"reconnect verify failed: {closed_reason(str(exc))}",
                protocol="ftp",
                error=str(exc),
            ),
            banner_ind,
        ]

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

    return [
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
        banner_ind,
    ]


def _ftp_login(ftp) -> None:
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
            title="FTP welcome banner matches emulator template",
            category="static_signature",
            triggered=bool(hit),
            protocol="ftp",
            detail=detail[:240],
            evidence=hit or "",
        )
    return skipped_indicator(
        "ftp.banner",
        "FTP welcome banner matches emulator template",
        "static_signature",
        closed_reason(str(exc)) if exc else "no welcome banner",
        protocol="ftp",
        error=str(exc) if exc else "",
    )


def _random_creds() -> tuple[str, str]:
    n = 10 + secrets.randbelow(89)
    return PROBE_USERNAME_TEMPLATE.format(n=n), PROBE_PASSWORD_TEMPLATE.format(n=n + 69)


def _ssh_exec(client, command: str) -> str:
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=settings.timeout_seconds)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        return (out or err).strip()
    except Exception as exc:
        return f"(exec failed: {exc})"


def _telnet_login_and_probe(host: str, port: int, user: str, password: str) -> tuple[bool, str, str]:
    """Sync telnet probe (safe inside asyncio.to_thread workers)."""
    payload = (
        user.encode() + b"\r\n" + password.encode() + b"\r\n"
        + b"uname -a\r\ncat /proc/cpuinfo\r\n"
    )
    data, err = tcp_transact(host, port, payload, recv_first=True)
    text = data.decode("utf-8", "replace")
    return _looks_like_shell(text), text, err


def _looks_like_shell(text: str) -> bool:
    low = (text or "").lower()
    if any(x in low for x in ("login incorrect", "authentication failed", "access denied")):
        return False
    if match_uname_signature(text) or "processor\t:" in low or "processor :" in low:
        return True
    return any(tok in text for tok in ("$ ", "# ", ":~$", "~$"))
