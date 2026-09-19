"""Memcached ASCII protocol fingerprint engine.

Strategies: arbitrary auth (dual entropy-varied ASCII ``set`` acceptance +
binary/SASL frame evidence) · state non-persistence (set then reconnect get
miss / stats ignore write) · static signature (VERSION/stats framing ·
unknown-command ERROR fidelity · get-miss END · canned stats clones · stock
VERSION lures · verbosity/noreply façades).

Never sends flush_all, stats reset, or slab reassign. Probe keys use an
``hpa_`` prefix, short TTL, and are deleted after checks when STORED.
Bare ``verbosity`` (wrong arity → ERROR) remains the non-destructive
stand-in for flush-accept stubs among static tells.
"""

from __future__ import annotations

import re
import secrets
import struct

from honeypot_auditor.models import Indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import (
    entropy_varied_creds,
    is_safe_mode,
    jittered_reconnect_pause,
    rtt_evidence,
    skip_suite,
)

_MC_SKIP = (
    (
        "memcached.arbitrary_auth",
        "Memcached accepts two entropy-varied ASCII set writes",
        "arbitrary_auth",
    ),
    (
        "memcached.state_nonpersist",
        "Memcached probe key does not persist across reconnect",
        "state_nonpersist",
    ),
    (
        "memcached.version_framing",
        "Memcached VERSION reply violates ASCII framing",
        "static_signature",
    ),
    (
        "memcached.stats_framing",
        "Memcached stats reply violates STAT/END framing",
        "static_signature",
    ),
    (
        "memcached.unknown_command",
        "Memcached accepts an unrecognized command",
        "static_signature",
    ),
    (
        "memcached.get_miss",
        "Memcached returns VALUE for a missing key",
        "static_signature",
    ),
    (
        "memcached.stats_clone",
        "Memcached returns bitwise-identical stats replies",
        "static_signature",
    ),
    (
        "memcached.stock_version",
        "Memcached VERSION matches a stock honeypot lure",
        "static_signature",
    ),
    (
        "memcached.flush_stub",
        "Memcached accepts bare verbosity (flush-stub stand-in)",
        "static_signature",
    ),
    (
        "memcached.noreply_facade",
        "Memcached answers a noreply command instead of staying quiet",
        "static_signature",
    ),
)

_SAFE_ONLY = frozenset({"memcached.version_framing"})

# Memcached ASCII reply tokens (not credentials — Bandit B105 false positive on "ERROR").
_MC_ERROR = "ERROR"
_MC_CLIENT_ERROR = "CLIENT_ERROR"
_MC_SERVER_ERROR = "SERVER_ERROR"

_ASCII_PREFIXES = (
    "VERSION",
    "STAT",
    "END",
    _MC_ERROR,
    _MC_CLIENT_ERROR,
    _MC_SERVER_ERROR,
    "OK",
    "VALUE",
    "STORED",
    "NOT_STORED",
    "EXISTS",
    "NOT_FOUND",
    "DELETED",
    "TOUCHED",
)

# Decisive lure tokens — rare outside honeypots.
_STOCK_VERSIONS_DECISIVE = frozenset(
    {
        "honeypot",
        "memcached-honeypot",
        "fake",
        "0.0.0",
        "1.0.0-honeypot",
    }
)
# Long-EOL / frozen decoy numbers often baked into skins.
_STOCK_VERSIONS_FROZEN = frozenset(
    {
        "1.2.6",
        "1.4.4",
        "1.4.5",
        "1.4.13",
    }
)
# Still common on real installs — corroboration-gated.
_STOCK_VERSIONS_GENERIC = frozenset(
    {
        "1.4.15",
        "1.4.25",
        "1.5.6",
        "1.5.22",
        "1.6.9",
        "1.6.12",
        "1.6.15",
    }
)

_VERSION_LINE_RE = re.compile(r"^VERSION\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_STAT_LINE_RE = re.compile(r"^STAT\s+\S+", re.IGNORECASE | re.MULTILINE)

# Minimal binary SASL list-mechs request (24-byte header, magic 0x80 opcode 0x21).
_BINARY_SASL_LIST = struct.pack(">BBHBBHIIQ", 0x80, 0x21, 0, 0, 0, 0, 0, 1, 0)


def _cmd(text: str) -> bytes:
    return f"{text}\r\n".encode("ascii")


def _mc_call(host: str, port: int, command: str) -> tuple[bytes, str]:
    return tcp_transact(host, port, _cmd(command))


def _mc_set(host: str, port: int, key: str, value: bytes, *, exptime: int = 5) -> tuple[bytes, str]:
    payload = (
        f"set {key} 0 {exptime} {len(value)}\r\n".encode("ascii")
        + value
        + b"\r\n"
    )
    return tcp_transact(host, port, payload)


def _safe_key(prefix: str, label: str) -> str:
    body = re.sub(r"[^A-Za-z0-9_.-]", "", label)[:24] or "x"
    return f"{prefix}{body}"


def _decode(raw: bytes) -> str:
    return (raw or b"").decode("utf-8", "replace")


def _first_token(text: str) -> str:
    line = (text or "").lstrip().split("\r\n", 1)[0].split("\n", 1)[0].strip()
    if not line:
        return ""
    return line.split(None, 1)[0].upper()


def _looks_like_memcached(raw: bytes) -> bool:
    text = _decode(raw).lstrip()
    if not text:
        return False
    token = _first_token(text)
    return token in {p.upper() for p in _ASCII_PREFIXES}


def _is_error(raw: bytes) -> bool:
    return _first_token(_decode(raw)) == _MC_ERROR


def _is_stored(raw: bytes) -> bool:
    return _first_token(_decode(raw)) == "STORED"


def _is_get_miss(raw: bytes) -> bool:
    text = _decode(raw)
    if not text.strip():
        return False
    token = _first_token(text)
    if token == "END":
        return True
    # END after empty VALUE block is still a miss shape; VALUE means a hit.
    return token != "VALUE" and bool(re.search(r"(?im)^END\s*$", text)) and "VALUE " not in text.upper()


def _is_version_framed(raw: bytes) -> bool:
    text = _decode(raw).strip()
    if not text:
        return False
    # Single primary line must be VERSION <token>; tolerate trailing empty.
    first = text.split("\r\n", 1)[0].split("\n", 1)[0].strip()
    return bool(_VERSION_LINE_RE.match(first))


def _parse_version_token(raw: bytes) -> str:
    m = _VERSION_LINE_RE.search(_decode(raw))
    return m.group(1) if m else ""


def _is_stats_framed(raw: bytes) -> bool:
    text = _decode(raw)
    if not text.strip():
        return False
    # Real stats: zero-or-more STAT lines, then END. Reject VERSION/OK-only façades.
    lead = _first_token(text)
    if lead in {"VERSION", "OK", "VALUE", "STORED"}:
        return False
    if lead == _MC_ERROR:
        # stats should not ERROR on a healthy speaker
        return False
    has_end = bool(re.search(r"(?im)^END\s*$", text))
    has_stat = bool(_STAT_LINE_RE.search(text))
    # Empty slab is rare but END alone is framed; typical replies have STAT+END.
    return has_end and (has_stat or text.strip().upper() == "END")


def _stock_version_assessment(token: str) -> tuple[str, bool, str]:
    """Return (detail, requires_corroboration, fidelity) or ("", False, "") if clear."""
    if not token:
        return "", False, ""
    low = token.lower()
    if low in {v.lower() for v in _STOCK_VERSIONS_DECISIVE}:
        return f"decisive lure VERSION {token}", False, "decisive"
    if low in {v.lower() for v in _STOCK_VERSIONS_FROZEN}:
        return f"frozen/EOL lure VERSION {token}", False, "high"
    if low in {v.lower() for v in _STOCK_VERSIONS_GENERIC}:
        return f"generic stock VERSION {token}", True, "medium"
    # Substring decisive tokens inside longer strings.
    for lure in _STOCK_VERSIONS_DECISIVE:
        if lure.lower() in low:
            return f"decisive lure VERSION {token}", False, "decisive"
    return "", False, ""


def _ind(
    *,
    id: str,
    title: str,
    category: str,
    triggered: bool,
    detail: str,
    evidence: str = "",
    skipped: bool = False,
    skip_reason: str = "",
    error: str = "",
    fidelity: str = "medium",
    remediation: str = "",
    requires_corroboration: bool = False,
) -> Indicator:
    return Indicator(
        id=id,
        title=title,
        category=category,
        triggered=triggered,
        skipped=skipped,
        skip_reason=skip_reason,
        error=error,
        protocol="memcached",
        detail=detail,
        evidence=evidence,
        fidelity=fidelity,
        remediation=remediation,
        requires_corroboration=requires_corroboration,
    )


def probe_memcached(host: str, port: int) -> list[Indicator]:
    ver_raw, ver_err = _mc_call(host, port, "version")
    if (ver_err and not ver_raw) or not _looks_like_memcached(ver_raw):
        reason = closed_reason(ver_err) if ver_err else "not a Memcached ASCII speaker"
        return skip_suite(_MC_SKIP, reason, protocol="memcached", error=ver_err)

    version_framed = _is_version_framed(ver_raw)
    version_hit = not version_framed
    ver_token = _parse_version_token(ver_raw)
    stock_detail, stock_requires, stock_fidelity = _stock_version_assessment(ver_token)
    stock_hit = bool(stock_detail)

    if is_safe_mode():
        out: list[Indicator] = []
        for iid, title, cat in _MC_SKIP:
            if iid in _SAFE_ONLY:
                out.append(
                    _ind(
                        id=iid,
                        title=title,
                        category=cat,
                        triggered=version_hit,
                        detail=(
                            "VERSION reply is not a well-formed VERSION <token> line"
                            if version_hit
                            else "VERSION framing looks compliant"
                        ),
                        evidence=_decode(ver_raw)[:160],
                        fidelity="high" if version_hit else "medium",
                        remediation="Reply to 'version' with 'VERSION <semver>\\r\\n'",
                    )
                )
            else:
                out.extend(
                    skip_suite(
                        ((iid, title, cat),),
                        "safe-mode: handshake-only probe",
                        protocol="memcached",
                    )
                )
        return out

    stats1_raw, stats1_err = _mc_call(host, port, "stats")
    unknown_raw, _ = _mc_call(host, port, "foo")
    miss_key = f"hpaudit_{secrets.token_hex(4)}"
    get_raw, _ = _mc_call(host, port, f"get {miss_key}")
    stats2_raw, stats2_err = _mc_call(host, port, "stats")
    verbosity_raw, _ = _mc_call(host, port, "verbosity")
    noreply_raw, _ = _mc_call(host, port, "verbosity 0 noreply")

    stats_framed = _is_stats_framed(stats1_raw) if stats1_raw or not stats1_err else False
    stats_framing_hit = bool(stats1_raw) and not stats_framed
    if stats1_err and not stats1_raw:
        stats_framing_hit = False

    unknown_hit = bool(unknown_raw) and not _is_error(unknown_raw)
    get_text = _decode(get_raw)
    get_miss_hit = bool(get_raw) and (
        _first_token(get_text) == "VALUE" or "VALUE " in get_text.upper()
    )

    clone_skipped = bool(stats1_err and not stats1_raw) or bool(stats2_err and not stats2_raw)
    clone_hit = (
        not clone_skipped
        and bool(stats1_raw)
        and bool(stats2_raw)
        and stats1_raw == stats2_raw
    )

    flush_hit = bool(verbosity_raw) and not _is_error(verbosity_raw)
    noreply_hit = bool(noreply_raw.strip())

    # --- arbitrary_auth: dual entropy-varied ASCII set + binary/SASL evidence ---
    (low_user, _low_pass), (high_user, _high_pass) = entropy_varied_creds()
    auth_keys: list[str] = []
    auth_stored = 0
    auth_notes: list[str] = []
    auth_err = ""
    for label, user in (("low-entropy", low_user), ("high-entropy", high_user)):
        key = _safe_key("hpa_a_", user)
        set_raw, set_err = _mc_set(host, port, key, b"x", exptime=5)
        if set_err and not set_raw:
            auth_err = auth_err or set_err
            auth_notes.append(f"{label}: set unanswered ({set_err})")
            continue
        if _is_stored(set_raw):
            auth_stored += 1
            auth_keys.append(key)
            auth_notes.append(f"{label}: set STORED key={key}")
            _mc_call(host, port, f"delete {key}")
        else:
            auth_notes.append(f"{label}: set {_first_token(_decode(set_raw)) or 'empty'}")

    bin_raw, bin_err = tcp_transact(host, port, _BINARY_SASL_LIST)
    bin_note = ""
    if auth_stored == 2:
        if bin_err and not bin_raw:
            bin_note = f"; binary/SASL frame closed ({closed_reason(bin_err)})"
        elif bin_raw:
            if bin_raw[:1] == b"\x81":
                bin_note = "; binary/SASL frame answered with binary magic"
            elif _is_error(bin_raw) or not _looks_like_memcached(bin_raw):
                bin_note = (
                    f"; binary/SASL mishandled "
                    f"(ascii_token={_first_token(_decode(bin_raw))!r} or garbage)"
                )
            else:
                bin_note = f"; binary/SASL reply={_first_token(_decode(bin_raw))!r}"

    auth_skipped = auth_stored == 0 and bool(auth_err) and all(
        "unanswered" in n for n in auth_notes
    )
    auth_hit = auth_stored == 2
    auth_detail = (
        f"two entropy-varied ASCII set writes both STORED{bin_note}"
        if auth_hit
        else ("; ".join(auth_notes) if auth_notes else "dual set not evaluated")
    )

    # --- state_nonpersist: set → pause → get miss / stats ignore ---
    state_key = f"hpa_s_{secrets.token_hex(4)}"
    stats_before, _ = _mc_call(host, port, "stats")
    state_set_raw, state_set_err = _mc_set(host, port, state_key, b"y", exptime=30)
    state_skipped = False
    state_hit = False
    state_detail = "state persistence not evaluated"
    state_err = ""
    if state_set_err and not state_set_raw:
        state_skipped = True
        state_err = state_set_err
        state_detail = closed_reason(state_set_err)
    elif not _is_stored(state_set_raw):
        state_skipped = True
        state_detail = (
            f"set rejected before persistence check "
            f"({_first_token(_decode(state_set_raw)) or 'empty'})"
        )
    else:
        stats_after, _ = _mc_call(host, port, "stats")
        pause_s = jittered_reconnect_pause()
        got_raw, got_err = _mc_call(host, port, f"get {state_key}")
        notes: list[str] = []
        if got_err and not got_raw:
            notes.append(f"get after reconnect failed: {closed_reason(got_err)}")
        elif _is_get_miss(got_raw):
            notes.append(f"get {state_key} returned END miss after STORED")
        stats_ignore = (
            bool(stats_before)
            and bool(stats_after)
            and stats_before == stats_after
        )
        if stats_ignore:
            notes.append("stats reply unchanged after successful set (write ignored)")
        state_hit = bool(notes)
        state_detail = (
            "; ".join(notes)
            if notes
            else f"key {state_key} persisted across reconnect"
        )
        rtt_note = rtt_evidence(pause_s * 1000.0)
        if rtt_note and state_hit:
            state_detail = f"{state_detail}; pause_{rtt_note}"
        _mc_call(host, port, f"delete {state_key}")

    return [
        _ind(
            id="memcached.arbitrary_auth",
            title="Memcached accepts two entropy-varied ASCII set writes",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason=closed_reason(auth_err) if auth_skipped else "",
            error=auth_err if auth_skipped else "",
            detail=auth_detail,
            evidence=",".join(auth_keys) if auth_hit else "",
            fidelity="decisive" if auth_hit else "medium",
            remediation="Require SASL/authz before accepting arbitrary set writes",
        ),
        _ind(
            id="memcached.state_nonpersist",
            title="Memcached probe key does not persist across reconnect",
            category="state_nonpersist",
            triggered=state_hit,
            skipped=state_skipped,
            skip_reason=state_detail if state_skipped else "",
            error=state_err,
            detail=state_detail,
            fidelity="high" if state_hit else "medium",
            remediation="Persist set values across connections; advance stats on writes",
        ),
        _ind(
            id="memcached.version_framing",
            title="Memcached VERSION reply violates ASCII framing",
            category="static_signature",
            triggered=version_hit,
            detail=(
                "VERSION reply is not a well-formed VERSION <token> line"
                if version_hit
                else "VERSION framing looks compliant"
            ),
            evidence=_decode(ver_raw)[:160],
            fidelity="high" if version_hit else "medium",
            remediation="Reply to 'version' with 'VERSION <semver>\\r\\n'",
        ),
        _ind(
            id="memcached.stats_framing",
            title="Memcached stats reply violates STAT/END framing",
            category="static_signature",
            triggered=stats_framing_hit,
            skipped=bool(stats1_err) and not stats1_raw,
            skip_reason=closed_reason(stats1_err) if stats1_err and not stats1_raw else "",
            error=stats1_err if stats1_err and not stats1_raw else "",
            detail=(
                "stats reply is not STAT…/END shaped"
                if stats_framing_hit
                else "stats framing looks compliant"
            ),
            evidence=_decode(stats1_raw)[:200],
            fidelity="high" if stats_framing_hit else "medium",
            remediation="Reply to 'stats' with STAT key value lines terminated by END",
        ),
        _ind(
            id="memcached.unknown_command",
            title="Memcached accepts an unrecognized command",
            category="static_signature",
            triggered=unknown_hit,
            detail=(
                "unrecognized command did not return ERROR"
                if unknown_hit
                else "unrecognized command returned ERROR"
            ),
            evidence=_decode(unknown_raw)[:120],
            fidelity="high" if unknown_hit else "medium",
            remediation="Return ERROR\\r\\n for unknown ASCII commands",
        ),
        _ind(
            id="memcached.get_miss",
            title="Memcached returns VALUE for a missing key",
            category="static_signature",
            triggered=get_miss_hit,
            detail=(
                f"get {miss_key} returned VALUE instead of END"
                if get_miss_hit
                else "missing-key get returned END (or non-VALUE)"
            ),
            evidence=get_text[:160],
            fidelity="high" if get_miss_hit else "medium",
            remediation="Return END\\r\\n for get misses; never invent VALUE bodies",
        ),
        _ind(
            id="memcached.stats_clone",
            title="Memcached returns bitwise-identical stats replies",
            category="static_signature",
            triggered=clone_hit,
            skipped=clone_skipped,
            skip_reason=(
                closed_reason(stats1_err or stats2_err) if clone_skipped else ""
            ),
            detail=(
                "two independent stats replies were bitwise-identical"
                if clone_hit
                else "stats replies differed across calls"
            ),
            evidence=(
                f"stats1={stats1_raw[:64]!r} stats2={stats2_raw[:64]!r}"
                if stats1_raw or stats2_raw
                else ""
            ),
            fidelity="decisive" if clone_hit else "medium",
            remediation="Advance counters (cmd_get, uptime, connections) between stats replies",
        ),
        _ind(
            id="memcached.stock_version",
            title="Memcached VERSION matches a stock honeypot lure",
            category="static_signature",
            triggered=stock_hit,
            detail=stock_detail or "VERSION token does not match stock lure list",
            evidence=ver_token or _decode(ver_raw)[:80],
            fidelity=stock_fidelity if stock_hit else "medium",
            requires_corroboration=stock_requires if stock_hit else False,
            remediation="Advertise a real Memcached release version, not a canned lure string",
        ),
        _ind(
            id="memcached.flush_stub",
            title="Memcached accepts bare verbosity (flush-stub stand-in)",
            category="static_signature",
            triggered=flush_hit,
            detail=(
                "bare verbosity returned success instead of ERROR "
                "(non-destructive stand-in for flush_all acceptance)"
                if flush_hit
                else "bare verbosity correctly returned ERROR"
            ),
            evidence=_decode(verbosity_raw)[:120],
            fidelity="high" if flush_hit else "medium",
            remediation="Return ERROR for wrong-arity verbosity; never accept flush_all blindly",
        ),
        _ind(
            id="memcached.noreply_facade",
            title="Memcached answers a noreply command instead of staying quiet",
            category="static_signature",
            triggered=noreply_hit,
            detail=(
                "verbosity 0 noreply returned a body instead of staying quiet"
                if noreply_hit
                else "noreply command stayed quiet"
            ),
            evidence=_decode(noreply_raw)[:120],
            fidelity="high" if noreply_hit else "medium",
            remediation="Honor noreply: send no response line for quiet commands",
        ),
    ]
