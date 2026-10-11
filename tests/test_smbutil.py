"""SMB / NTLM helper tests — impacket paths exercised against fake connections.

No network: ``optional_impacket`` is patched to return hand-rolled
SMBConnection/SessionError stand-ins, and the NTLM Type-2 challenge is built
with impacket's own structure classes so the capture hook parses real bytes.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from honeypot_auditor import smbutil

_STATUS_NOT_FOUND = smbutil.STATUS_OBJECT_NAME_NOT_FOUND


class _FakeSessionError(Exception):
    """Stand-in for impacket's SessionError (only get_error_code is used)."""

    def __init__(self, code: int = _STATUS_NOT_FOUND, message: str = "not found"):
        super().__init__(message)
        self._code = code

    def get_error_code(self) -> int:
        return self._code


def _fake_conn_pair(cls):
    return patch.object(smbutil, "optional_impacket", return_value=(cls, _FakeSessionError))


# --------------------------------------------------------------------------
# NTLM challenge capture
# --------------------------------------------------------------------------
def _make_type2(challenge: bytes = b"SERVRCH1", *, with_av: bool = True) -> bytes:
    ntlm = pytest.importorskip("impacket.ntlm")

    av = ntlm.AV_PAIRS()
    if with_av:
        av[ntlm.NTLMSSP_AV_DOMAINNAME] = "HONEYPOT".encode("utf-16le")
        av[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = "hp.example".encode("utf-16le")
        ti = av.getData()
    else:
        ti = b""
    msg = ntlm.NTLMAuthChallenge()
    msg["message_type"] = 2
    msg["challenge"] = challenge
    msg["flags"] = (
        ntlm.NTLMSSP_NEGOTIATE_NTLM
        | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO
        | ntlm.NTLMSSP_NEGOTIATE_UNICODE
    )
    msg["domain_name"] = b""
    msg["TargetInfoFields"] = ti
    msg["Version"] = b""
    # fixed part (signature + headers, no Version) is 48 bytes — variable
    # data (domain_name + TargetInfoFields) starts right after it.
    msg["domain_offset"] = 48
    msg["TargetInfoFields_offset"] = 48
    return msg.getData()


class _NtlmSMB:
    """Fake SMBConnection that feeds the installed NTLM hook a Type-2 blob."""

    type2 = b""
    os_name: str | None = "Unix (Samba 4.1)"
    login_error: Exception | None = None
    ctor_error: Exception | None = None
    closed = False

    def __init__(self, host, remote_name, sess_port=445, timeout=5):
        if type(self).ctor_error:
            raise type(self).ctor_error

    def login(self, user, password):
        from impacket import ntlm

        if type(self).login_error:
            raise type(self).login_error
        ntlm.getNTLMSSPType3(b"type1", type(self).type2)  # hook raises _AbortAuth

    def getServerOS(self):
        if type(self).os_name is None:
            raise RuntimeError("OS not available")
        return type(self).os_name

    def close(self):
        type(self).closed = True


@pytest.fixture()
def ntlm_server(monkeypatch):
    """Patch optional_impacket with _NtlmSMB and reset its knobs per test."""
    monkeypatch.setattr(_NtlmSMB, "type2", _make_type2())
    monkeypatch.setattr(_NtlmSMB, "os_name", "Unix (Samba 4.1)")
    monkeypatch.setattr(_NtlmSMB, "login_error", None)
    monkeypatch.setattr(_NtlmSMB, "ctor_error", None)
    monkeypatch.setattr(_NtlmSMB, "closed", False)
    monkeypatch.setattr(smbutil, "optional_impacket", lambda: (_NtlmSMB, _FakeSessionError))
    return _NtlmSMB


def test_capture_ntlm_challenge_without_impacket():
    with patch.object(smbutil, "optional_impacket", return_value=(None, None)):
        assert smbutil.capture_ntlm_challenge("h", 445, timeout=1) is None


def test_capture_ntlm_challenge_parses_av_pairs(ntlm_server):
    meta = smbutil.capture_ntlm_challenge("h", 445, timeout=1)
    assert meta is not None
    assert meta["challenge"] == b"SERVRCH1"
    assert meta["native_os"] == "Unix (Samba 4.1)"
    av = meta.get("av_pairs")
    assert av is not None
    # AV_PAIRS values are (length, content) tuples keyed by AV id (2 = NbDomainName)
    assert av[2] == (16, "HONEYPOT".encode("utf-16le"))
    assert ntlm_server.closed


def test_capture_ntlm_challenge_without_av_pairs(ntlm_server, monkeypatch):
    monkeypatch.setattr(ntlm_server, "type2", _make_type2(with_av=False))
    meta = smbutil.capture_ntlm_challenge("h", 445, timeout=1)
    assert meta is not None
    assert "av_pairs" not in meta


def test_capture_ntlm_challenge_records_login_error(ntlm_server, monkeypatch):
    monkeypatch.setattr(ntlm_server, "login_error", RuntimeError("STATUS_ACCOUNT_DISABLED"))
    meta = smbutil.capture_ntlm_challenge("h", 445, timeout=1)
    assert meta is None  # hook never ran → no challenge → None


def test_capture_ntlm_challenge_tolerates_getServerOS_failure(ntlm_server, monkeypatch):
    monkeypatch.setattr(ntlm_server, "os_name", None)
    meta = smbutil.capture_ntlm_challenge("h", 445, timeout=1)
    assert meta is not None and meta["native_os"] == ""


def test_capture_ntlm_challenge_constructor_failure(ntlm_server, monkeypatch):
    from impacket import ntlm

    monkeypatch.setattr(ntlm_server, "ctor_error", ConnectionRefusedError("refused"))
    assert smbutil.capture_ntlm_challenge("h", 445, timeout=1) is None
    # the hook must be restored even when the connection never opened
    assert ntlm.getNTLMSSPType3 is not None


def test_collect_ntlm_challenges_dedupes_attempts(ntlm_server):
    challenges = smbutil.collect_ntlm_challenges("h", 445, timeout=1, count=3)
    assert challenges == [b"SERVRCH1"] * 3


def test_collect_ntlm_challenges_skips_failed_captures(ntlm_server, monkeypatch):
    monkeypatch.setattr(smbutil, "capture_ntlm_challenge", lambda host, port, timeout: None)
    assert smbutil.collect_ntlm_challenges("h", 445, timeout=1, count=2) == []


# --------------------------------------------------------------------------
# Bogus pipe / ghost share probes
# --------------------------------------------------------------------------
class _ProbeSMB:
    """Fake SMBConnection for pipe/ghost/login probing via knob class attrs."""

    login_fails = False
    ipc_error: Exception | None = None
    open_error: Exception | None = None
    ghost_error: Exception | None = None
    ctor_error: Exception | None = None
    logoffs = 0

    def __init__(self, host, remote_name, sess_port=445, timeout=5):
        if type(self).ctor_error:
            raise type(self).ctor_error

    def login(self, user, password):
        if type(self).login_fails:
            raise _FakeSessionError(0xC0000022, "STATUS_ACCESS_DENIED")

    def connectTree(self, unc):
        if unc.endswith("\\IPC$"):
            if type(self).ipc_error:
                raise type(self).ipc_error
            return 0x100
        if type(self).ghost_error:
            raise type(self).ghost_error
        return 0x200

    def openFile(self, tid, name, **kwargs):
        if type(self).open_error:
            raise type(self).open_error

    def disconnectTree(self, tid):
        pass

    def logoff(self):
        type(self).logoffs += 1

    def close(self):
        pass


@pytest.fixture()
def probe_server(monkeypatch):
    for knob in ("login_fails", "ipc_error", "open_error", "ghost_error", "ctor_error"):
        monkeypatch.setattr(_ProbeSMB, knob, getattr(_ProbeSMB, knob))
    monkeypatch.setattr(_ProbeSMB, "logoffs", 0)
    monkeypatch.setattr(smbutil, "optional_impacket", lambda: (_ProbeSMB, _FakeSessionError))
    return _ProbeSMB


def test_pipe_and_ghost_without_impacket():
    with patch.object(smbutil, "optional_impacket", return_value=(None, None)):
        pipe_r, ghost_r = smbutil.probe_pipe_and_ghost_share("h", 445, timeout=1)
    assert pipe_r == ghost_r == (None, "impacket not installed", False)


def test_pipe_and_ghost_happy_path(probe_server):
    pipe_r, ghost_r = smbutil.probe_pipe_and_ghost_share("h", 445, timeout=1)
    assert pipe_r[2] is True and pipe_r[1].startswith("bogus pipe ")
    assert ghost_r[2] is True and ghost_r[1].startswith("ghost share ")
    assert probe_server.logoffs == 1


def test_bogus_pipe_and_ghost_share_wrappers(probe_server, monkeypatch):
    seen = {}

    def fake_combined(host, port, *, timeout):
        seen["args"] = (host, port, timeout)
        return (None, "pipe-detail", True), (0xC0000034, "ghost-detail", False)

    monkeypatch.setattr(smbutil, "probe_pipe_and_ghost_share", fake_combined)
    assert smbutil.probe_bogus_pipe("h", 445, timeout=2) == (None, "pipe-detail", True)
    assert smbutil.probe_ghost_share("h", 445, timeout=2) == (0xC0000034, "ghost-detail", False)
    assert seen["args"] == ("h", 445, 2)


def test_pipe_and_ghost_when_no_session(probe_server, monkeypatch):
    monkeypatch.setattr(probe_server, "login_fails", True)
    pipe_r, ghost_r = smbutil.probe_pipe_and_ghost_share("h", 445, timeout=1)
    assert pipe_r == ghost_r
    assert pipe_r[0] is None and pipe_r[2] is False
    assert "no SMB session" in pipe_r[1] and "STATUS_ACCESS_DENIED" in pipe_r[1]


def test_pipe_rejected_with_ntstatus(probe_server, monkeypatch):
    monkeypatch.setattr(
        probe_server, "open_error", _FakeSessionError(_STATUS_NOT_FOUND, "bad pipe")
    )
    pipe_r, _ghost_r = smbutil.probe_pipe_and_ghost_share("h", 445, timeout=1)
    assert pipe_r == (_STATUS_NOT_FOUND, f"NTSTATUS 0x{_STATUS_NOT_FOUND:08X}", False)


def test_ipc_tree_rejected_with_ntstatus(probe_server, monkeypatch):
    monkeypatch.setattr(probe_server, "ipc_error", _FakeSessionError(0xC0000035, "no IPC"))
    pipe_r, _ghost_r = smbutil.probe_pipe_and_ghost_share("h", 445, timeout=1)
    assert pipe_r[0] == 0xC0000035 and pipe_r[1].startswith("IPC$ NTSTATUS")


def test_ipc_tree_generic_error(probe_server, monkeypatch):
    monkeypatch.setattr(probe_server, "ipc_error", RuntimeError("tree boom"))
    pipe_r, _ghost_r = smbutil.probe_pipe_and_ghost_share("h", 445, timeout=1)
    assert pipe_r == (None, "tree boom", False)


def test_ghost_share_rejected_with_ntstatus(probe_server, monkeypatch):
    monkeypatch.setattr(probe_server, "ghost_error", _FakeSessionError(0xC00000CC, "bad share"))
    _pipe_r, ghost_r = smbutil.probe_pipe_and_ghost_share("h", 445, timeout=1)
    assert ghost_r[0] == 0xC00000CC and ghost_r[1].startswith("NTSTATUS")


def test_ghost_share_generic_error(probe_server, monkeypatch):
    monkeypatch.setattr(probe_server, "ghost_error", RuntimeError("ghost boom"))
    _pipe_r, ghost_r = smbutil.probe_pipe_and_ghost_share("h", 445, timeout=1)
    assert ghost_r == (None, "ghost boom", False)


def test_pipe_and_ghost_constructor_failure(probe_server, monkeypatch):
    monkeypatch.setattr(probe_server, "ctor_error", ConnectionRefusedError("refused"))
    pipe_r, ghost_r = smbutil.probe_pipe_and_ghost_share("h", 445, timeout=1)
    assert pipe_r == ghost_r == (None, "refused", False)


# --------------------------------------------------------------------------
# Synthetic logins
# --------------------------------------------------------------------------
class _LoginSMB:
    ok_passwords: frozenset[str] = frozenset()

    def __init__(self, host, remote_name, sess_port=445, timeout=5):
        pass

    def login(self, user, password):
        if password not in type(self).ok_passwords:
            raise _FakeSessionError(0xC000006A, "wrong password")

    def logoff(self):
        pass

    def close(self):
        pass


def test_arbitrary_logins_without_impacket():
    with patch.object(smbutil, "optional_impacket", return_value=(None, None)):
        ok, notes = smbutil.probe_arbitrary_logins("h", 445, timeout=1, creds=[("u", "p")])
    assert ok == 0 and notes == ["impacket not installed"]


def test_arbitrary_logins_count_accepted(monkeypatch):
    monkeypatch.setattr(_LoginSMB, "ok_passwords", frozenset({"admin"}))
    monkeypatch.setattr(smbutil, "optional_impacket", lambda: (_LoginSMB, _FakeSessionError))
    ok, notes = smbutil.probe_arbitrary_logins(
        "h", 445, timeout=1, creds=[("admin", "admin"), ("svc", "h4rd")]
    )
    assert ok == 1
    assert notes[0].startswith("low-entropy: login accepted")
    assert notes[1].startswith("high-entropy: rejected")


# --------------------------------------------------------------------------
# Connection summary / negotiate facts
# --------------------------------------------------------------------------
class _SummarySMB:
    login_fails = False
    ctor_error: Exception | None = None
    dialect: object = 0x0311
    dialect_error: Exception | None = None
    os_name: str | None = "Windows 5.1"
    os_error: Exception | None = None
    shares: object = None
    shares_error: Exception | None = None
    negotiate_ctor_error: Exception | None = None
    smb_server_error: Exception | None = None
    connection_obj: object = None

    def __init__(self, host, remote_name, sess_port=445, timeout=5):
        if type(self).ctor_error or (sess_port == 139 and type(self).negotiate_ctor_error):
            raise (type(self).ctor_error or type(self).negotiate_ctor_error)

    def login(self, user, password):
        if type(self).login_fails:
            raise _FakeSessionError(0xC0000022, "guest disabled")

    def getDialect(self):
        if type(self).dialect_error:
            raise type(self).dialect_error
        return type(self).dialect

    def getServerOS(self):
        if type(self).os_error:
            raise type(self).os_error
        return type(self).os_name

    def listShares(self):
        if type(self).shares_error:
            raise type(self).shares_error
        return type(self).shares

    def getSMBServer(self):
        if type(self).smb_server_error:
            raise type(self).smb_server_error
        connection_obj = type(self).connection_obj

        class _Inner:
            def getDialect(self):
                return 0x0311

        inner = _Inner()
        inner._Connection = connection_obj
        return inner

    def logoff(self):
        pass

    def close(self):
        pass


@pytest.fixture()
def summary_server(monkeypatch):
    monkeypatch.setattr(_SummarySMB, "login_fails", False)
    monkeypatch.setattr(_SummarySMB, "ctor_error", None)
    monkeypatch.setattr(_SummarySMB, "dialect", 0x0311)
    monkeypatch.setattr(_SummarySMB, "dialect_error", None)
    monkeypatch.setattr(_SummarySMB, "os_name", "Windows 5.1")
    monkeypatch.setattr(_SummarySMB, "os_error", None)
    monkeypatch.setattr(_SummarySMB, "shares", None)
    monkeypatch.setattr(_SummarySMB, "shares_error", None)
    monkeypatch.setattr(_SummarySMB, "negotiate_ctor_error", None)
    monkeypatch.setattr(_SummarySMB, "smb_server_error", None)
    monkeypatch.setattr(_SummarySMB, "connection_obj", None)
    monkeypatch.setattr(smbutil, "optional_impacket", lambda: (_SummarySMB, _FakeSessionError))
    return _SummarySMB


def test_connection_summary_without_impacket():
    with patch.object(smbutil, "optional_impacket", return_value=(None, None)):
        assert smbutil.smb_connection_summary("h", 445, timeout=1) == {}


def test_connection_summary_login_refused(summary_server, monkeypatch):
    monkeypatch.setattr(summary_server, "login_fails", True)
    out = smbutil.smb_connection_summary("h", 445, timeout=1)
    assert "guest disabled" in out["login_error"]
    assert out["shares"] == []


def test_connection_summary_filters_share_names(summary_server, monkeypatch):
    monkeypatch.setattr(
        summary_server,
        "shares",
        [
            {"shi1_netname": b"public\x00"},
            {"shi1_netname": "plain"},
            {"shi1_netname": b""},
            "not-a-dict",
        ],
    )
    out = smbutil.smb_connection_summary("h", 445, timeout=1)
    assert out["shares"] == ["public", "plain"]
    assert out["dialect"] == str(0x0311) and out["native_os"] == "Windows 5.1"


def test_connection_summary_collects_partial_errors(summary_server, monkeypatch):
    monkeypatch.setattr(summary_server, "dialect_error", RuntimeError("no dialect"))
    monkeypatch.setattr(summary_server, "os_error", RuntimeError("no os"))
    monkeypatch.setattr(summary_server, "shares_error", RuntimeError("no shares"))
    out = smbutil.smb_connection_summary("h", 445, timeout=1)
    assert out["dialect_error"] and out["native_os_error"] and out["shares_error"]


def test_connection_summary_constructor_failure(summary_server, monkeypatch):
    monkeypatch.setattr(summary_server, "ctor_error", ConnectionRefusedError("refused"))
    out = smbutil.smb_connection_summary("h", 445, timeout=1)
    assert out["login_error"] == "refused"


def test_negotiate_facts_without_impacket():
    with patch.object(smbutil, "optional_impacket", return_value=(None, None)):
        assert smbutil.smb_negotiate_facts("h", 445, timeout=1) == {}


def test_negotiate_facts_reports_capabilities(summary_server, monkeypatch):
    monkeypatch.setattr(
        summary_server,
        "connection_obj",
        {"SupportsEncryption": True, "PreauthIntegrityHashValue": b"\x01\x02"},
    )
    facts = smbutil.smb_negotiate_facts("h", 445, timeout=1)
    assert facts["supports_encryption"] is True
    assert facts["supports_preauth"] is True
    assert facts["native_os"] == "Windows 5.1"


def test_negotiate_facts_without_capabilities(summary_server):
    facts = smbutil.smb_negotiate_facts("h", 445, timeout=1)
    assert facts["supports_encryption"] is False
    assert facts["supports_preauth"] is False


def test_negotiate_facts_errors_are_reported(summary_server, monkeypatch):
    monkeypatch.setattr(summary_server, "smb_server_error", RuntimeError("negotiate boom"))
    assert smbutil.smb_negotiate_facts("h", 445, timeout=1) == {"error": "negotiate boom"}
    monkeypatch.setattr(summary_server, "smb_server_error", None)
    monkeypatch.setattr(summary_server, "negotiate_ctor_error", ConnectionRefusedError("no smb"))
    assert smbutil.smb_negotiate_facts("h", 139, timeout=1) == {"error": "no smb"}


def test_optional_impacket_returns_real_classes_when_installed():
    conn_cls, err_cls = smbutil.optional_impacket()
    if conn_cls is None:  # environment without the [full] extra — skip silently
        pytest.skip("impacket not installed")
    assert conn_cls.__name__ == "SMBConnection"
    assert err_cls.__name__ == "SessionError"
