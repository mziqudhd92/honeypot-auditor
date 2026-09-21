"""SIP fingerprint engine.

Strategies: arbitrary auth (fake Digest accepted with 200), state non-persistence
(CSeq/Call-ID binding), static signature (default User-Agent template, Via
received/rport coherence, response CSeq echo). Nonce reuse alone is not scored.
"""

from __future__ import annotations

import re
import secrets

from honeypot_auditor.config import SIP_UA_TELLS, USER_AGENT
from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact, udp_transact
from honeypot_auditor.probes.common import (
    entropy_varied_creds,
    is_safe_mode,
    jittered_reconnect_pause,
    skip_suite,
)

_SIP_SKIP = (
    ("sip.user_agent", "SIP User-Agent matches a default template", "static_signature"),
    (
        "sip.via_coherence",
        "SIP response Via lacks received/rport or branch echo",
        "static_signature",
    ),
    (
        "sip.cseq_echo",
        "SIP response CSeq does not echo the request transaction",
        "static_signature",
    ),
    (
        "sip.arbitrary_auth",
        "SIP REGISTER accepts fake Digest or reuses nonce/realm",
        "arbitrary_auth",
    ),
    (
        "sip.state_nonpersist",
        "SIP CSeq/Call-ID binding is not monotonic after re-REGISTER",
        "state_nonpersist",
    ),
)

_STATUS_RE = re.compile(r"^SIP/2\.0\s+(\d{3})", re.IGNORECASE | re.MULTILINE)
_WWW_AUTH_RE = re.compile(r"(?im)^WWW-Authenticate:\s*(.+)$")
_NONCE_RE = re.compile(r'nonce\s*=\s*"([^"]+)"', re.IGNORECASE)
_REALM_RE = re.compile(r'realm\s*=\s*"([^"]+)"', re.IGNORECASE)
_CSEQ_RE = re.compile(r"(?im)^CSeq:\s*(\d+)\s+(\S+)")

# OPTIONS Via sent-by is 0.0.0.0:5060 with ;rport, so a conformant response
# Via must echo our branch and add received=<src-ip> / rport=<src-port>
# (RFC 3261 §8.2.6.2, RFC 3581 §4). The branch keeps a fixed prefix so the
# substring check still matches while remaining unique per transaction.
_VIA_BRANCH_PREFIX = "z9hG4bKhpaudit"
_VIA_BRANCH_TOKEN = "z9hg4bkhpaudit"  # nosec B105 — Via magic-cookie prefix, not a password
_RPORT_ECHO_RE = re.compile(r"rport\s*=\s*\d+", re.IGNORECASE)


def _sip_exchange(host: str, port: int, payload: bytes) -> tuple[bytes, str]:
    raw, err = udp_transact(host, port, payload)
    if err and not raw:
        raw, err = tcp_transact(host, port, payload)
    return raw, err


def _status_code(text: str) -> int:
    m = _STATUS_RE.search(text or "")
    return int(m.group(1)) if m else 0


def _header(text: str, name: str) -> str:
    prefix = name.lower() + ":"
    for line in (text or "").split("\r\n"):
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def _parse_challenge(text: str) -> tuple[str, str]:
    m = _WWW_AUTH_RE.search(text or "")
    if not m:
        return "", ""
    blob = m.group(1)
    nonce_m = _NONCE_RE.search(blob)
    realm_m = _REALM_RE.search(blob)
    return (
        nonce_m.group(1) if nonce_m else "",
        realm_m.group(1) if realm_m else "",
    )


def _via_assessment(text: str) -> tuple[bool, str]:
    """Score the response Via against the request's sent-by/branch/rport.

    The request Via sent-by is 0.0.0.0:5060 (never the real source), so a
    conformant server must copy the Via and add received=<src-ip> plus
    rport=<src-port> because the request carried ;rport. Verbatim echoes and
    missing Via headers are skin tells.
    """
    via = _header(text, "Via")
    if not via:
        return True, "response carries no Via header to echo the request path"
    low = via.lower()
    missing: list[str] = []
    if _VIA_BRANCH_TOKEN not in low:
        missing.append("branch echo")
    if "received=" not in low:
        missing.append("received=<source-ip>")
    if not _RPORT_ECHO_RE.search(low):
        missing.append("rport=<source-port>")
    if missing:
        return True, f"response Via lacks {' and '.join(missing)}: {via!r}"
    return False, f"Via echoes branch with received/rport: {via!r}"


def _cseq_assessment(responses: list[tuple[str, int]]) -> tuple[bool, str]:
    """Score response CSeq echo (RFC 3261 §8.2.6.2: must equal the request's).

    Each entry is (response_text, request_cseq). Skins replaying one canned 200
    echo the wrong sequence number or omit CSeq entirely.
    """
    notes: list[str] = []
    for text, want in responses:
        if not text:
            continue
        got = _CSEQ_RE.search(text)
        if not got:
            notes.append(f"CSeq header missing (request was {want} OPTIONS)")
        elif int(got.group(1)) != want or got.group(2).upper() != "OPTIONS":
            notes.append(f"response CSeq {got.group(1)} {got.group(2)} != request {want} OPTIONS")
    if notes:
        return True, "; ".join(notes)
    checked = len([1 for t, _ in responses if t])
    return False, f"CSeq echoed on {checked} OPTIONS response(s)"


def _options(host: str, call_id: str, cseq: int = 1) -> bytes:
    return (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 0.0.0.0:5060;branch={_VIA_BRANCH_PREFIX}{secrets.token_hex(3)};rport\r\n"
        f"From: <sip:auditor@invalid>;tag=hpaudit\r\n"
        f"To: <sip:{host}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} OPTIONS\r\n"
        f"Contact: <sip:auditor@0.0.0.0:5060>\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode()


def _register(
    host: str,
    *,
    call_id: str,
    cseq: int,
    user: str,
    password: str,
    realm: str = "invalid",
    nonce: str = "hpa-nonce",
) -> bytes:
    uri = f"sip:{host}"
    fake_resp = secrets.token_hex(16)
    auth = (
        f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
        f'uri="{uri}", response="{fake_resp}", algorithm=MD5'
    )
    return (
        f"REGISTER {uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK{secrets.token_hex(4)};rport\r\n"
        f"From: <sip:{user}@invalid>;tag=hpa{secrets.token_hex(3)}\r\n"
        f"To: <sip:{user}@{host}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} REGISTER\r\n"
        f"Contact: <sip:{user}@0.0.0.0:5060>\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Authorization: {auth}\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode()


def probe_sip(host: str, port: int) -> list[Indicator]:
    call_id = f"hpaudit-{secrets.token_hex(6)}"
    # Distinct CSeq numbers per OPTIONS transaction so a canned single-response
    # skin cannot pass the CSeq echo check by accident.
    raw, err = _sip_exchange(host, port, _options(host, call_id, cseq=7))
    if err and not raw:
        return skip_suite(_SIP_SKIP, closed_reason(err), protocol="sip", error=err)

    text = raw.decode("latin-1", "replace")
    if not text.strip().upper().startswith("SIP/"):
        return skip_suite(_SIP_SKIP, "not a SIP speaker", protocol="sip")

    ua = _header(text, "User-Agent") or _header(text, "Server")
    ua_hit = bool(ua) and any(tell in ua.lower() for tell in SIP_UA_TELLS)
    via_hit, via_detail = _via_assessment(text)

    if is_safe_mode():
        out: list[Indicator] = []
        for iid, title, cat in _SIP_SKIP:
            if iid == "sip.user_agent":
                out.append(
                    Indicator(
                        id=iid,
                        title=title,
                        category=cat,
                        triggered=ua_hit,
                        protocol="sip",
                        detail=f"User-Agent: {ua or '(missing)'}",
                        evidence=text[:600],
                    )
                )
            else:
                out.extend(
                    skip_suite(
                        ((iid, title, cat),),
                        "safe-mode: handshake-only probe",
                        protocol="sip",
                    )
                )
        return out

    low, high = entropy_varied_creds()
    challenges: list[tuple[str, str]] = []
    opt_nonce, opt_realm = _parse_challenge(text)
    if opt_nonce or opt_realm:
        challenges.append((opt_nonce, opt_realm))

    # Second OPTIONS/REGISTER challenge observation (fresh Call-ID, new CSeq).
    call_id2 = f"hpaudit-{secrets.token_hex(6)}"
    raw_opt2, _ = _sip_exchange(host, port, _options(host, call_id2, cseq=9))
    text_opt2 = raw_opt2.decode("latin-1", "replace")
    n2, r2 = _parse_challenge(text_opt2)
    if n2 or r2:
        challenges.append((n2, r2))
    cseq_hit, cseq_detail = _cseq_assessment([(text, 7), (text_opt2, 9)])

    reg_ok = 0
    reg_notes: list[str] = []
    call_reg = f"hpaudit-reg-{secrets.token_hex(4)}"
    for idx, (user, password) in enumerate((low, high), start=1):
        realm = opt_realm or r2 or "invalid"
        nonce = opt_nonce or n2 or f"hpa-{secrets.token_hex(4)}"
        raw_reg, _ = _sip_exchange(
            host,
            port,
            _register(
                host,
                call_id=f"{call_reg}-{idx}",
                cseq=1,
                user=user,
                password=password,
                realm=realm,
                nonce=nonce,
            ),
        )
        t_reg = raw_reg.decode("latin-1", "replace")
        code = _status_code(t_reg)
        if code == 200:
            reg_ok += 1
            reg_notes.append(f"{user}: 200 without valid Digest")
        else:
            cn, cr = _parse_challenge(t_reg)
            if cn or cr:
                challenges.append((cn, cr))
            reg_notes.append(f"{user}: {code or 'no-status'}")

    static_nonce = False
    if len(challenges) >= 2:
        # Identical nonce+realm across distinct sessions.
        a, b = challenges[0], challenges[1]
        if a[0] and b[0] and a == b:
            static_nonce = True

    # Nonce reuse across two rapid challenges is normal (nonce lifetime).
    # Only a 200 to an invalid Digest response is an auth façade.
    auth_hit = reg_ok >= 2
    if auth_hit:
        auth_detail = "two REGISTER with fake Digest both returned 200"
    elif static_nonce:
        auth_detail = (
            f"nonce/realm reused across sessions ({challenges[0]}); "
            f"not scored (registrars reuse nonces). "
            + ("; ".join(reg_notes) if reg_notes else "")
        )
    else:
        auth_detail = "; ".join(reg_notes) or "Digest challenges differed / REGISTER rejected"

    # --- state: re-REGISTER after jitter ---
    state_hit = False
    state_detail = "CSeq/Call-ID binding looks monotonic"
    bind_call = f"hpaudit-bind-{secrets.token_hex(4)}"
    user_s, pass_s = low
    raw1, _ = _sip_exchange(
        host,
        port,
        _register(host, call_id=bind_call, cseq=1, user=user_s, password=pass_s),
    )
    code1 = _status_code(raw1.decode("latin-1", "replace"))
    jittered_reconnect_pause()
    raw2, _ = _sip_exchange(
        host,
        port,
        _register(host, call_id=bind_call, cseq=2, user=user_s, password=pass_s),
    )
    t2 = raw2.decode("latin-1", "replace")
    code2 = _status_code(t2)
    # Binding vanishes with canned OK: first non-200 (or 401/407), second 200 with same Call-ID
    # without advancing dialog state; or CSeq ignored (200 then lower CSeq still 200 identically).
    if code1 == 200 and code2 == 200:
        # Re-REGISTER with same Call-ID should keep binding; canned identical bodies = façade.
        if raw1 and raw2 and raw1 == raw2:
            state_hit = True
            state_detail = "identical canned 200 REGISTER replies across CSeq advance"
        else:
            state_detail = "re-REGISTER with advanced CSeq retained binding"
    elif code1 in (401, 407, 403) and code2 == 200:
        state_hit = True
        state_detail = "REGISTER binding appeared as canned 200 after prior challenge/reject"
    elif code1 == 200 and code2 in (0, 404, 481):
        state_hit = True
        state_detail = f"REGISTER binding vanished after reconnect (status={code2})"
    elif code2 and code1 and code2 < code1 and code2 == 200:
        state_hit = True
        state_detail = "CSeq binding not monotonic (later REGISTER got canned OK)"

    return [
        Indicator(
            id="sip.user_agent",
            title="SIP User-Agent matches a default template",
            category="static_signature",
            triggered=ua_hit,
            protocol="sip",
            detail=f"User-Agent: {ua or '(missing)'}",
            evidence=text[:600],
        ),
        Indicator(
            id="sip.via_coherence",
            title="SIP response Via lacks received/rport or branch echo",
            category="static_signature",
            triggered=via_hit,
            protocol="sip",
            detail=via_detail,
            evidence=(_header(text, "Via") or "(missing)")[:200],
            requires_corroboration=True if via_hit else False,
            fidelity="high",
            remediation=(
                "Copy the request Via into responses and add received=/rport= "
                "when sent-by differs from the source (RFC 3261 §8.2.6.2, RFC 3581)"
            ),
        ),
        Indicator(
            id="sip.cseq_echo",
            title="SIP response CSeq does not echo the request transaction",
            category="static_signature",
            triggered=cseq_hit,
            protocol="sip",
            detail=cseq_detail,
            evidence="; ".join(
                (m.group(0) if (m := _CSEQ_RE.search(t)) else "(missing)")
                for t, _ in ((text, 7), (text_opt2, 9))
                if t
            ),
            requires_corroboration=True if cseq_hit else False,
            fidelity="high",
            remediation=(
                "Echo the request CSeq number and method in every response "
                "(RFC 3261 §8.2.6.2)"
            ),
        ),
        Indicator(
            id="sip.arbitrary_auth",
            title="SIP REGISTER accepts fake Digest or reuses nonce/realm",
            category="arbitrary_auth",
            triggered=auth_hit,
            protocol="sip",
            detail=auth_detail,
            evidence="; ".join(f"{n}/{r}" for n, r in challenges[:3]),
            fidelity="decisive" if auth_hit else "medium",
            remediation="Reject Digest responses that fail HA1/HA2 verification; rotate nonce per challenge",
        ),
        Indicator(
            id="sip.state_nonpersist",
            title="SIP CSeq/Call-ID binding is not monotonic after re-REGISTER",
            category="state_nonpersist",
            triggered=state_hit,
            protocol="sip",
            detail=state_detail,
            evidence=f"cseq1={code1} cseq2={code2}",
            fidelity="high" if state_hit else "medium",
            remediation="Track Call-ID/CSeq dialog state across REGISTER refreshes",
        ),
    ]
