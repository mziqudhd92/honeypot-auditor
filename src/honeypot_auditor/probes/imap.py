"""IMAP fingerprint engine.

Strategies: repeated arbitrary LOGIN · pre-auth SELECT/LIST state bypass ·
greeting and unknown-command conformance · stock Exchange lure banners ·
identical auth-failed NO/BAD blankets (CAPABILITY / LIST / unknown).
Never reads, deletes, or modifies mailboxes.

RFC 3501 notes:
- Greetings are * OK | * PREAUTH | * BYE (§7.1).
- CAPABILITY is legal in Not Authenticated; LIST/SELECT require Authenticated.
- PREAUTH means already Authenticated — do not score SELECT OK as a lure.
- Port 993 uses implicit TLS (IMAPS); 143 is cleartext (optional STARTTLS not required).
"""

from __future__ import annotations

import re
from collections import defaultdict
from contextlib import closing

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason
from honeypot_auditor.probes.common import is_safe_mode, random_creds, skip_suite
from honeypot_auditor.proxy_transport import create_connection, create_tls_connection
from honeypot_auditor.settings import settings

_IMAP_SKIP = (
    ("imap.arbitrary_auth", "IMAP accepts two random LOGIN pairs", "arbitrary_auth"),
    (
        "imap.preauth_state",
        "IMAP accepts mailbox commands before authentication",
        "state_nonpersist",
    ),
    ("imap.greeting", "IMAP greeting violates response framing", "static_signature"),
    (
        "imap.unknown_command",
        "IMAP accepts an unrecognized command",
        "static_signature",
    ),
    (
        "imap.auth_failed_blanket",
        "IMAP returns the same auth-failed NO/BAD for distinct pre-auth commands",
        "static_signature",
    ),
    (
        "imap.stock_banner",
        "IMAP greeting matches a stock honeypot lure banner",
        "static_signature",
    ),
)

_MAX_RESPONSE_BYTES = 1024
_RECV_CHUNK = 256
_TAG = "A001"
_TLS_PORTS = frozenset({993})

# Exact / near-exact lure strings (fingerprint, not RFC violations).
_IMAP_STOCK_GREETINGS = (
    "The Microsoft Exchange IMAP4 service is ready",
    "Microsoft Exchange IMAP4rev1 server ready",
)

# Credential/lure phrasing — not legitimate "please authenticate first" state text.
_AUTH_FAILED_BODY_RE = re.compile(
    r"authentication\s+failed|login\s+failed|invalid\s+credentials",
    re.IGNORECASE,
)


class _LineReader:
    def __init__(self, sock) -> None:
        self._sock = sock
        self._buf = bytearray()

    def readline(self) -> str:
        while b"\r\n" not in self._buf and len(self._buf) < _MAX_RESPONSE_BYTES:
            need = min(_RECV_CHUNK, _MAX_RESPONSE_BYTES - len(self._buf))
            if need <= 0:
                break
            chunk = self._sock.recv(need)
            if not chunk:
                break
            self._buf.extend(chunk)
        nl = self._buf.find(b"\r\n")
        if nl == -1:
            line = bytes(self._buf[:_MAX_RESPONSE_BYTES])
            self._buf.clear()
            return line.decode("utf-8", "replace").rstrip("\r\n")
        line = bytes(self._buf[:nl])
        del self._buf[: nl + 2]
        return line.decode("utf-8", "replace")


def _read_line(sock) -> str:
    return _LineReader(sock).readline()


def _open_socket(host: str, port: int):
    timeout = settings.timeout_seconds
    if int(port) in _TLS_PORTS:
        return create_tls_connection(host, port, timeout)
    return create_connection(host, port, timeout)


def _send_tagged(reader: _LineReader, sock, tag: str, command: str) -> list[str]:
    sock.sendall(f"{tag} {command}\r\n".encode("ascii", "replace"))
    lines: list[str] = []
    while len(lines) < 32:
        line = reader.readline()
        if not line:
            break
        lines.append(line)
        upper = line.upper()
        if upper.startswith(f"{tag} ") or upper.startswith("* BYE"):
            break
    return lines


def _completion_line(lines: list[str], tag: str) -> str:
    prefix = f"{tag} ".upper()
    for line in lines:
        if line.upper().startswith(prefix):
            return line
    return lines[-1] if lines else ""


def _is_ok_completion(line: str, tag: str) -> bool:
    parts = (line or "").split(None, 2)
    return len(parts) >= 2 and parts[0].upper() == tag.upper() and parts[1].upper() == "OK"


def _is_no_or_bad(line: str, tag: str) -> bool:
    parts = (line or "").split(None, 2)
    return (
        len(parts) >= 2
        and parts[0].upper() == tag.upper()
        and parts[1].upper() in ("NO", "BAD")
    )


def _greeting_kind(greeting: str) -> str:
    upper = (greeting or "").strip().upper()
    if upper.startswith("* OK"):
        return "ok"
    if upper.startswith("* PREAUTH"):
        return "preauth"
    if upper.startswith("* BYE"):
        return "bye"
    return "invalid"


def _greeting_text(greeting: str) -> str:
    text = (greeting or "").strip()
    upper = text.upper()
    if upper.startswith("* OK"):
        text = text[4:].strip()
    elif upper.startswith("* PREAUTH"):
        text = text[9:].strip()
    elif upper.startswith("* BYE"):
        text = text[5:].strip()
    return text


def _normalize_fail_body(line: str, tag: str) -> str:
    text = (line or "").strip()
    prefix = f"{tag} ".upper()
    if text.upper().startswith(prefix):
        parts = text.split(None, 2)
        text = parts[2] if len(parts) > 2 else ""
    return " ".join(text.lower().split())


def _is_auth_themed_fail(line: str, tag: str) -> bool:
    if not _is_no_or_bad(line, tag):
        return False
    return bool(_AUTH_FAILED_BODY_RE.search(_normalize_fail_body(line, tag)))


def _stock_banner_match(greeting: str) -> str:
    body = _greeting_text(greeting)
    lower = body.lower()
    for lure in _IMAP_STOCK_GREETINGS:
        if lure.lower() == lower or lure.lower() in lower:
            return lure
    return ""


def _blanket_auth_failed(replies: dict[str, str]) -> tuple[bool, str, str]:
    """Primary tell: identical credential-lure NO/BAD including CAPABILITY."""
    primary = ("CAPABILITY", "LIST", "XZPQ")
    auth_errs: dict[str, str] = {}
    for name in primary:
        reply = replies.get(name, "")
        if _is_auth_themed_fail(reply, _TAG):
            auth_errs[name] = _normalize_fail_body(reply, _TAG)
    if "CAPABILITY" not in auth_errs or len(auth_errs) < 2:
        return (
            False,
            "no identical auth-failed NO/BAD including CAPABILITY across pre-auth commands",
            "",
        )
    by_body: dict[str, list[str]] = defaultdict(list)
    for name, body in auth_errs.items():
        by_body[body].append(name)
    for body, names in by_body.items():
        if len(names) >= 2 and "CAPABILITY" in names:
            labeled = ", ".join(names)
            return (
                True,
                f"identical auth-themed failure on {labeled}: {body!r}",
                "; ".join(f"{n}={replies[n]!r}" for n in names),
            )
    return False, "auth-themed failures were not identical with CAPABILITY", ""


def _read_greeting(host: str, port: int) -> tuple[str, str]:
    try:
        with closing(_open_socket(host, port)) as sock:
            return _read_line(sock), ""
    except OSError as exc:
        return "", closed_reason(str(exc))


def _single_command(host: str, port: int, command: str) -> tuple[list[str], str, str]:
    try:
        with closing(_open_socket(host, port)) as sock:
            reader = _LineReader(sock)
            greeting = reader.readline()
            if not greeting:
                return [], "", "no IMAP greeting"
            kind = _greeting_kind(greeting)
            if kind == "invalid":
                return [], "", f"malformed greeting: {greeting!r}"
            if kind == "bye":
                return [], "", "server rejected connection (BYE greeting)"
            lines = _send_tagged(reader, sock, _TAG, command)
            return lines, _completion_line(lines, _TAG), ""
    except OSError as exc:
        return [], "", closed_reason(str(exc))


def _try_login(host: str, port: int, username: str, password: str) -> tuple[bool, str, str]:
    try:
        with closing(_open_socket(host, port)) as sock:
            reader = _LineReader(sock)
            greeting = reader.readline()
            kind = _greeting_kind(greeting)
            if kind != "ok":
                return False, f"greeting={greeting!r}", ""
            user_q = '"' + username.replace("\\", "\\\\").replace('"', '\\"') + '"'
            pass_q = '"' + password.replace("\\", "\\\\").replace('"', '\\"') + '"'
            lines = _send_tagged(reader, sock, _TAG, f"LOGIN {user_q} {pass_q}")
            completion = _completion_line(lines, _TAG)
            accepted = _is_ok_completion(completion, _TAG)
            if accepted:
                # RFC 3501 §6.1.3 — tidy logout; ignore reply errors.
                try:
                    _send_tagged(reader, sock, "A002", "LOGOUT")
                except OSError:
                    pass
            return accepted, f"LOGIN={completion!r}", ""
    except OSError as exc:
        return False, "", closed_reason(str(exc))


def _greeting_indicator(greeting: str) -> Indicator:
    kind = _greeting_kind(greeting)
    valid = kind in ("ok", "preauth", "bye")
    detail = {
        "ok": "untagged OK greeting received",
        "preauth": "untagged PREAUTH greeting received (already authenticated)",
        "bye": "untagged BYE greeting received (connection rejected)",
        "invalid": f"expected '* OK', '* PREAUTH', or '* BYE' greeting; received {greeting!r}",
    }[kind if valid else "invalid"]
    return Indicator(
        id="imap.greeting",
        title="IMAP greeting violates response framing",
        category="static_signature",
        triggered=not valid,
        protocol="imap",
        detail=detail,
        evidence=greeting[:_MAX_RESPONSE_BYTES],
        remediation="Emit a standards-conformant, service-specific IMAP greeting",
    )


def _stock_banner_indicator(greeting: str) -> Indicator:
    match = _stock_banner_match(greeting)
    return Indicator(
        id="imap.stock_banner",
        title="IMAP greeting matches a stock honeypot lure banner",
        category="static_signature",
        triggered=bool(match),
        protocol="imap",
        detail=(
            f"stock lure greeting matched: {match!r}"
            if match
            else "greeting does not match known IMAP lure banners"
        ),
        evidence=greeting[:_MAX_RESPONSE_BYTES],
        remediation="Replace canned Exchange/IMAP lure banners with deployment-specific text",
        fingerprint_type="imap_stock_banner",
        requires_corroboration=True,
        tell_tier="origin",
        fidelity="medium",
    )


def _preauth_state_triggered(state_replies: dict[str, str]) -> bool:
    """SELECT OK before LOGIN is the decisive authenticated-state tell."""
    return _is_ok_completion(state_replies.get("SELECT", ""), _TAG)


def _handshake_only_suite(
    greeting_ind: Indicator,
    stock_ind: Indicator,
    reason: str,
) -> list[Indicator]:
    return [
        skipped_indicator(*_IMAP_SKIP[0], reason, protocol="imap"),
        skipped_indicator(*_IMAP_SKIP[1], reason, protocol="imap"),
        greeting_ind,
        skipped_indicator(*_IMAP_SKIP[3], reason, protocol="imap"),
        skipped_indicator(*_IMAP_SKIP[4], reason, protocol="imap"),
        stock_ind,
    ]


def probe_imap(host: str, port: int) -> list[Indicator]:
    greeting, greeting_error = _read_greeting(host, port)
    if not greeting:
        reason = greeting_error or "no IMAP greeting"
        return skip_suite(_IMAP_SKIP, reason, protocol="imap", error=greeting_error)

    greeting_ind = _greeting_indicator(greeting)
    stock_ind = _stock_banner_indicator(greeting)
    kind = _greeting_kind(greeting)

    if greeting_ind.triggered:
        return _handshake_only_suite(
            greeting_ind, stock_ind, "IMAP response checks skipped after malformed greeting"
        )
    if kind == "bye":
        return _handshake_only_suite(
            greeting_ind, stock_ind, "server rejected connection (BYE greeting)"
        )
    if is_safe_mode():
        return _handshake_only_suite(greeting_ind, stock_ind, "safe-mode: handshake-only probe")

    # PREAUTH: client is already Authenticated (§3.2) — SELECT OK is expected.
    if kind == "preauth":
        reason = "PREAUTH greeting: already authenticated (RFC 3501); LOGIN/SELECT not lure-scored"
        state_replies: dict[str, str] = {}
        state_errors: list[str] = []
        # Still sample CAPABILITY / LIST / unknown for Exchange-style auth-failed blankets.
        # LIST OK is expected under PREAUTH and is not scored as preauth_state.
        for command in ('CAPABILITY', 'LIST "" *', "XZPQ"):
            key = command.split()[0]
            _, completion, error = _single_command(host, port, command)
            if completion:
                state_replies[key] = completion
            elif error:
                state_errors.append(f"{key}: {error}")

        unknown_completion = state_replies.get("XZPQ", "")
        unknown_skipped = "XZPQ" not in state_replies
        unknown_hit = _is_ok_completion(unknown_completion, _TAG)
        unknown_detail = (
            "unrecognized XZPQ command returned OK"
            if unknown_hit
            else (
                "unrecognized XZPQ command returned NO/BAD"
                if _is_no_or_bad(unknown_completion, _TAG)
                else f"unrecognized XZPQ command reply: {unknown_completion!r}"
            )
        )
        blanket_hit, blanket_detail, blanket_evidence = _blanket_auth_failed(state_replies)
        blanket_skipped = "CAPABILITY" not in state_replies

        return [
            skipped_indicator(*_IMAP_SKIP[0], reason, protocol="imap"),
            skipped_indicator(*_IMAP_SKIP[1], reason, protocol="imap"),
            greeting_ind,
            Indicator(
                id="imap.unknown_command",
                title="IMAP accepts an unrecognized command",
                category="static_signature",
                triggered=unknown_hit,
                skipped=unknown_skipped,
                skip_reason="; ".join(state_errors) if unknown_skipped else "",
                error="; ".join(state_errors),
                protocol="imap",
                detail=unknown_detail,
                evidence=unknown_completion,
                remediation="Return tagged BAD for unrecognized IMAP commands",
            ),
            Indicator(
                id="imap.auth_failed_blanket",
                title="IMAP returns the same auth-failed NO/BAD for distinct pre-auth commands",
                category="static_signature",
                triggered=blanket_hit,
                skipped=blanket_skipped,
                skip_reason="; ".join(state_errors) if blanket_skipped else "",
                protocol="imap",
                detail=blanket_detail,
                evidence=blanket_evidence,
                remediation=(
                    "Return distinct, state-appropriate NO/BAD text for mailbox-only "
                    "commands, unknown verbs, and capability refusals — not a canned "
                    "'Authentication failed' lure"
                ),
                fingerprint_type="imap_auth_failed_blanket",
                requires_corroboration=False,
                tell_tier="origin",
                fidelity="high",
            ),
            stock_ind,
        ]

    state_replies = {}
    state_errors = []
    # CAPABILITY is legal pre-auth; LIST/SELECT should fail until authenticated.
    for command in ('CAPABILITY', 'LIST "" *', "SELECT INBOX"):
        key = command.split()[0]
        _, completion, error = _single_command(host, port, command)
        if completion:
            state_replies[key] = completion
        elif error:
            state_errors.append(f"{key}: {error}")

    _, unknown_completion, unknown_error = _single_command(host, port, "XZPQ")
    unknown_skipped = not unknown_completion
    unknown_hit = _is_ok_completion(unknown_completion, _TAG)
    if unknown_completion:
        state_replies["XZPQ"] = unknown_completion
    unknown_detail = (
        "unrecognized XZPQ command returned OK"
        if unknown_hit
        else (
            "unrecognized XZPQ command returned NO/BAD"
            if _is_no_or_bad(unknown_completion, _TAG)
            else f"unrecognized XZPQ command reply: {unknown_completion!r}"
        )
    )

    state_triggered = _preauth_state_triggered(state_replies)
    state_skipped = "SELECT" not in state_replies and "LIST" not in state_replies
    state_hits = [
        name
        for name, reply in state_replies.items()
        if name in ("SELECT", "LIST") and _is_ok_completion(reply, _TAG)
    ]

    blanket_hit, blanket_detail, blanket_evidence = _blanket_auth_failed(state_replies)
    blanket_skipped = "CAPABILITY" not in state_replies

    attempts = [random_creds(), random_creds()]
    accepted_users: list[str] = []
    auth_evidence: list[str] = []
    auth_errors: list[str] = []
    for username, password in attempts:
        accepted, transcript, error = _try_login(host, port, username, password)
        if accepted:
            accepted_users.append(username)
        if transcript:
            auth_evidence.append(f"{username}: {transcript}")
        if error:
            auth_errors.append(f"{username}: {error}")
    auth_hit = len(accepted_users) == len(attempts)
    auth_skipped = not auth_evidence and bool(auth_errors)

    if state_triggered:
        state_detail = (
            f"authenticated-state bypass: SELECT returned OK before LOGIN "
            f"({', '.join(state_hits)})"
        )
    elif state_hits:
        state_detail = (
            f"LIST returned OK before auth but SELECT did not "
            f"(not scored alone): {', '.join(state_hits)}"
        )
    else:
        state_detail = "SELECT and LIST were rejected before authentication"

    return [
        Indicator(
            id="imap.arbitrary_auth",
            title="IMAP accepts two random LOGIN pairs",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason="; ".join(auth_errors) if auth_skipped else "",
            error="; ".join(auth_errors),
            protocol="imap",
            detail=(
                "two independent random LOGIN pairs were accepted"
                if auth_hit
                else "random LOGIN pairs were not both accepted"
            ),
            evidence=",".join(accepted_users) if auth_hit else "; ".join(auth_evidence),
            remediation="Reject synthetic accounts before granting mailbox access",
            fidelity="decisive" if auth_hit else "medium",
        ),
        Indicator(
            id="imap.preauth_state",
            title="IMAP accepts mailbox commands before authentication",
            category="state_nonpersist",
            triggered=state_triggered,
            skipped=state_skipped,
            skip_reason="; ".join(state_errors) if state_skipped else "",
            error="; ".join(state_errors),
            protocol="imap",
            detail=state_detail,
            evidence="; ".join(
                f"{name}={reply!r}"
                for name, reply in state_replies.items()
                if name in ("SELECT", "LIST", "CAPABILITY")
            ),
            remediation="Enforce IMAP authentication before SELECT mailbox access",
        ),
        greeting_ind,
        Indicator(
            id="imap.unknown_command",
            title="IMAP accepts an unrecognized command",
            category="static_signature",
            triggered=unknown_hit,
            skipped=unknown_skipped,
            skip_reason=unknown_error if unknown_skipped else "",
            error=unknown_error,
            protocol="imap",
            detail=unknown_detail,
            evidence=unknown_completion,
            remediation="Return tagged BAD for unrecognized IMAP commands",
        ),
        Indicator(
            id="imap.auth_failed_blanket",
            title="IMAP returns the same auth-failed NO/BAD for distinct pre-auth commands",
            category="static_signature",
            triggered=blanket_hit,
            skipped=blanket_skipped,
            skip_reason="; ".join(state_errors) if blanket_skipped else "",
            protocol="imap",
            detail=blanket_detail,
            evidence=blanket_evidence,
            remediation=(
                "Return distinct, state-appropriate NO/BAD text for mailbox-only "
                "commands, unknown verbs, and capability refusals — not a canned "
                "'Authentication failed' lure"
            ),
            fingerprint_type="imap_auth_failed_blanket",
            requires_corroboration=False,
            tell_tier="origin",
            fidelity="high",
        ),
        stock_ind,
    ]


__all__ = ["probe_imap"]
