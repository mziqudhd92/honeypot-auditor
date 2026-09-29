"""SMB / NTLM helpers built on impacket (optional [full] extra)."""

from __future__ import annotations

import secrets
import threading
from contextlib import suppress
from typing import Any

_NTLM_HOOK_LOCK = threading.Lock()

STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034


class _AbortAuth(Exception):
    """Stop impacket login after capturing the NTLM Type-2 challenge."""


def optional_impacket():
    try:
        import impacket  # noqa: F401
        from impacket.smbconnection import SessionError, SMBConnection

        return SMBConnection, SessionError
    except ImportError:
        return None, None


def capture_ntlm_challenge(host: str, port: int, *, timeout: int) -> dict[str, Any] | None:
    """Run SESSION_SETUP until Type-2 is parsed; return challenge bytes and AV metadata."""
    SMBConnection, _SessionError = optional_impacket()
    if SMBConnection is None:
        return None
    from impacket import ntlm

    meta: dict[str, Any] = {}
    real_type3 = ntlm.getNTLMSSPType3

    def _stop_after_type2(_type1, type2, *_args, **_kwargs):
        challenge = ntlm.NTLMAuthChallenge(type2)
        meta["challenge"] = challenge["challenge"]
        meta["target_info"] = challenge.get("TargetInfoFields", b"")[:512]
        meta["version"] = challenge.get("Version", b"")
        if challenge["TargetInfoFields_len"] > 0:
            meta["av_pairs"] = ntlm.AV_PAIRS(
                challenge["TargetInfoFields"][: challenge["TargetInfoFields_len"]]
            )
        raise _AbortAuth()

    with _NTLM_HOOK_LOCK:
        ntlm.getNTLMSSPType3 = _stop_after_type2
        conn = None
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
            try:
                conn.login("Guest", "hpaudit-invalid")
            except _AbortAuth:
                pass
            except Exception as exc:
                meta["login_error"] = str(exc)
            try:
                meta["native_os"] = str(conn.getServerOS() or "")
            except Exception:
                meta["native_os"] = ""
            return meta if meta.get("challenge") else None
        except Exception:
            return None
        finally:
            ntlm.getNTLMSSPType3 = real_type3
            if conn is not None:
                with suppress(Exception):
                    conn.close()


def collect_ntlm_challenges(host: str, port: int, *, timeout: int, count: int = 2) -> list[bytes]:
    challenges: list[bytes] = []
    for _ in range(count):
        meta = capture_ntlm_challenge(host, port, timeout=timeout)
        if meta and meta.get("challenge"):
            challenges.append(meta["challenge"])
    return challenges


def probe_bogus_pipe(host: str, port: int, *, timeout: int) -> tuple[int | None, str, bool]:
    """Open a random IPC$ pipe. Returns (NTSTATUS or None, detail, accepted)."""
    pipe_r, _ghost_r = probe_pipe_and_ghost_share(host, port, timeout=timeout)
    return pipe_r


def probe_ghost_share(host: str, port: int, *, timeout: int) -> tuple[int | None, str, bool]:
    """TREE_CONNECT a random share name. Returns (NTSTATUS or None, detail, accepted)."""
    _pipe_r, ghost_r = probe_pipe_and_ghost_share(host, port, timeout=timeout)
    return ghost_r


def probe_pipe_and_ghost_share(
    host: str, port: int, *, timeout: int
) -> tuple[tuple[int | None, str, bool], tuple[int | None, str, bool]]:
    """Bogus IPC$ pipe + ghost share TREE_CONNECT on one session (fewer round-trips)."""
    SMBConnection, SessionError = optional_impacket()
    no_imp = (None, "impacket not installed", False)
    if SMBConnection is None:
        return no_imp, no_imp

    pipe = f"hpaudit_{secrets.token_hex(4)}"
    share = f"hpaudit_{secrets.token_hex(4)}"
    conn = None
    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
        login_error = ""
        for user, password in (("", ""), ("Guest", "")):
            try:
                conn.login(user, password)
                break
            except Exception as exc:
                login_error = str(exc)
        else:
            detail = "no SMB session for pipe/ghost probe"
            if login_error:
                detail += f" ({login_error})"
            skipped = (None, detail, False)
            return skipped, skipped

        pipe_result: tuple[int | None, str, bool]
        ipc = f"\\\\{host}\\IPC$"
        try:
            tid = conn.connectTree(ipc)
            try:
                conn.openFile(
                    tid,
                    pipe,
                    desiredAccess=0x120089,
                    shareMode=0x7,
                    creationOption=0,
                    fileAttributes=0,
                    creationDisposition=0x1,
                )
                pipe_result = (None, f"bogus pipe {pipe} opened", True)
            except SessionError as exc:
                code = exc.get_error_code()
                pipe_result = (code, f"NTSTATUS 0x{code:08X}", False)
            finally:
                with suppress(Exception):
                    conn.disconnectTree(tid)
        except SessionError as exc:
            code = exc.get_error_code()
            pipe_result = (code, f"IPC$ NTSTATUS 0x{code:08X}", False)
        except Exception as exc:
            pipe_result = (None, str(exc), False)

        ghost_result: tuple[int | None, str, bool]
        unc = f"\\\\{host}\\{share}"
        try:
            tid = conn.connectTree(unc)
            with suppress(Exception):
                conn.disconnectTree(tid)
            ghost_result = (None, f"ghost share {share} TREE_CONNECT accepted", True)
        except SessionError as exc:
            code = exc.get_error_code()
            ghost_result = (code, f"NTSTATUS 0x{code:08X}", False)
        except Exception as exc:
            ghost_result = (None, str(exc), False)

        return pipe_result, ghost_result
    except Exception as exc:
        failed = (None, str(exc), False)
        return failed, failed
    finally:
        if conn is not None:
            with suppress(Exception):
                conn.logoff()
            with suppress(Exception):
                conn.close()


def probe_arbitrary_logins(
    host: str, port: int, *, timeout: int, creds: list[tuple[str, str]]
) -> tuple[int, list[str]]:
    """Try synthetic logins. Returns (success_count, per-attempt notes)."""
    SMBConnection, _SessionError = optional_impacket()
    if SMBConnection is None:
        return 0, ["impacket not installed"]

    ok = 0
    notes: list[str] = []
    for label_i, (user, password) in enumerate(creds):
        label = "low-entropy" if label_i == 0 else "high-entropy"
        conn = None
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
            conn.login(user, password)
            ok += 1
            notes.append(f"{label}: login accepted")
        except Exception as exc:
            notes.append(f"{label}: rejected ({str(exc)[:80]})")
        finally:
            if conn is not None:
                with suppress(Exception):
                    conn.logoff()
                with suppress(Exception):
                    conn.close()
    return ok, notes


def smb_connection_summary(host: str, port: int, *, timeout: int) -> dict[str, Any]:
    """Dialect, native OS, and share list via impacket login."""
    SMBConnection, _SessionError = optional_impacket()
    if SMBConnection is None:
        return {}
    conn = None
    out: dict[str, Any] = {"dialect": "", "native_os": "", "shares": []}
    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
        login_error = ""
        for user, password in (("", ""), ("Guest", "")):
            try:
                conn.login(user, password)
                break
            except Exception as exc:
                login_error = str(exc)
        else:
            out["login_error"] = login_error or "session not established"
            return out
        try:
            out["dialect"] = str(conn.getDialect() or "")
        except Exception as exc:
            out["dialect_error"] = str(exc)
        try:
            out["native_os"] = str(conn.getServerOS() or "")
        except Exception as exc:
            out["native_os_error"] = str(exc)
        try:
            shares = []
            for share in conn.listShares() or []:
                name = share.get("shi1_netname") if isinstance(share, dict) else None
                if isinstance(name, bytes):
                    name = name.decode("utf-8", "replace")
                if name:
                    shares.append(str(name).rstrip("\x00"))
            out["shares"] = shares
        except Exception as exc:
            out["shares_error"] = str(exc)
        return out
    except Exception as exc:
        out["login_error"] = str(exc)
        return out
    finally:
        if conn is not None:
            with suppress(Exception):
                conn.logoff()
            with suppress(Exception):
                conn.close()


def smb_negotiate_facts(host: str, port: int, *, timeout: int) -> dict[str, Any]:
    """Dialect and capability flags after impacket negotiate (offers SMB 3.1.1)."""
    SMBConnection, _SessionError = optional_impacket()
    if SMBConnection is None:
        return {}
    conn = None
    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
        smb = conn.getSMBServer()
        dialect = smb.getDialect()
        connection = getattr(smb, "_Connection", {}) or {}
        return {
            "dialect": dialect,
            "supports_encryption": bool(connection.get("SupportsEncryption")),
            "supports_preauth": bool(connection.get("PreauthIntegrityHashValue")),
            "native_os": str(conn.getServerOS() or ""),
        }
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        if conn is not None:
            with suppress(Exception):
                conn.close()
