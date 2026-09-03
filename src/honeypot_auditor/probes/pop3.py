"""POP3 fingerprint engine.

Strategies: repeated arbitrary authentication · authorization/transaction state
separation · greeting and unknown-command conformance · stock lure banners ·
identical auth-failed -ERR blankets (incl. CAPA).  The probe never reads,
deletes, or otherwise modifies mail.
"""

from __future__ import annotations

import re
from collections import defaultdict
from contextlib import closing

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason
from honeypot_auditor.probes.common import is_safe_mode, random_creds, skip_suite
from honeypot_auditor.proxy_transport import create_connection
from honeypot_auditor.settings import settings

_POP3_SKIP = (
    ("pop3.arbitrary_auth", "POP3 accepts two random credential pairs", "arbitrary_auth"),
    (
        "pop3.preauth_state",
        "POP3 accepts transaction commands before authentication",
        "state_nonpersist",
    ),
    ("pop3.greeting", "POP3 greeting violates response framing", "static_signature"),
    (
        "pop3.unknown_command",
        "POP3 accepts an unrecognized command",
        "static_signature",
    ),
    (
        "pop3.auth_failed_blanket",
        "POP3 returns the same auth-failed -ERR for distinct pre-auth commands",
        "static_signature",
    ),
    (
        "pop3.stock_banner",
        "POP3 greeting matches a stock honeypot lure banner",
        "static_signature",
    ),
)

_MAX_RESPONSE_BYTES = 512
_RECV_CHUNK = 256

# Exact / near-exact lure strings (fingerprint, not RFC violations).
_POP3_STOCK_GREETINGS = (
    "Microsoft Exchange POP3 service is ready",
)

# Auth-themed -ERR bodies that should not be identical across STAT/CAPA/unknown.
_AUTH_FAILED_BODY_RE = re.compile(
    r"authentication\s+failed|auth(?:entication)?\s+required|authenticate\s+first",
    re.IGNORECASE,
)


class _LineReader:
    """Buffered CRLF reader — larger recv chunks with leftover carry across commands."""

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
    """Read one bounded POP3 response line (single-shot; no leftover reuse)."""
    return _LineReader(sock).readline()


def _send_command(reader: _LineReader, sock, command: str) -> str:
    sock.sendall(command.encode("ascii") + b"\r\n")
    return reader.readline()


def _is_positive(response: str) -> bool:
    return response.startswith("+OK")


def _is_negative(response: str) -> bool:
    return response.startswith("-ERR")


def _greeting_text(greeting: str) -> str:
    text = (greeting or "").strip()
    if text.upper().startswith("+OK"):
        text = text[3:].strip()
    return text


def _normalize_err_body(response: str) -> str:
    text = (response or "").strip()
    if text.upper().startswith("-ERR"):
        text = text[4:].strip()
    return " ".join(text.lower().split())


def _is_auth_themed_err(response: str) -> bool:
    if not _is_negative(response):
        return False
    return bool(_AUTH_FAILED_BODY_RE.search(_normalize_err_body(response)))


def _stock_banner_match(greeting: str) -> str:
    body = _greeting_text(greeting)
    lower = body.lower()
    for lure in _POP3_STOCK_GREETINGS:
        if lure.lower() == lower or lure.lower() in lower:
            return lure
    return ""


def _blanket_auth_failed(replies: dict[str, str]) -> tuple[bool, str, str]:
    """Primary behavioral tell: identical auth-themed -ERR across distinct pre-auth cmds.

    CAPA + STAT/HPAU are the preferred drivers (RFC 2449 CAPA is optional, but answering
    it with the same 'Authentication failed' lure as TRANSACTION/unknown commands is not
    a realistic capability refusal).
    """
    primary = ("STAT", "CAPA", "HPAU")
    auth_errs: dict[str, str] = {}
    for name in primary:
        reply = replies.get(name, "")
        if reply and _is_auth_themed_err(reply):
            auth_errs[name] = reply
    if len(auth_errs) < 2:
        return False, "no identical auth-failed -ERR blanket across pre-auth commands", ""

    groups: dict[str, list[str]] = defaultdict(list)
    for name, reply in auth_errs.items():
        groups[_normalize_err_body(reply)].append(name)

    best_body = ""
    best_cmds: list[str] = []
    for body, cmds in groups.items():
        if len(cmds) > len(best_cmds):
            best_body, best_cmds = body, cmds

    if len(best_cmds) < 2:
        return False, "auth-themed -ERR bodies differ across commands", ""

    # Prefer groups that include CAPA (primary classification driver).
    capa_groups = [(b, c) for b, c in groups.items() if "CAPA" in c and len(c) >= 2]
    if capa_groups:
        best_body, best_cmds = max(capa_groups, key=lambda item: len(item[1]))
    elif "CAPA" in replies and _is_negative(replies["CAPA"]) and "CAPA" not in best_cmds:
        # CAPA returned some -ERR but not auth-themed / not matching — not this tell.
        if not _is_auth_themed_err(replies["CAPA"]):
            return (
                False,
                "CAPA -ERR is not auth-themed; not scoring blanket",
                "",
            )

    detail = (
        f"identical auth-themed -ERR on {', '.join(sorted(best_cmds))} "
        f"(body={best_body!r})"
    )
    evidence = "; ".join(f"{name}={replies[name]!r}" for name in sorted(best_cmds))
    return True, detail, evidence


def _single_command(host: str, port: int, command: str) -> tuple[str, str, str]:
    """Open a fresh authorization-state session and issue one command."""
    try:
        with closing(create_connection(host, port, settings.timeout_seconds)) as sock:
            reader = _LineReader(sock)
            greeting = reader.readline()
            if not _is_positive(greeting):
                return greeting, "", "server did not issue a positive POP3 greeting"
            return greeting, _send_command(reader, sock, command), ""
    except OSError as exc:
        return "", "", closed_reason(str(exc))


def _read_greeting(host: str, port: int) -> tuple[str, str]:
    try:
        with closing(create_connection(host, port, settings.timeout_seconds)) as sock:
            return _LineReader(sock).readline(), ""
    except OSError as exc:
        return "", closed_reason(str(exc))


def _try_login(host: str, port: int, username: str, password: str) -> tuple[bool, str, str]:
    """Try one synthetic account without accessing the resulting maildrop."""
    try:
        with closing(create_connection(host, port, settings.timeout_seconds)) as sock:
            reader = _LineReader(sock)
            greeting = reader.readline()
            if not _is_positive(greeting):
                return False, f"greeting={greeting!r}", ""
            user_reply = _send_command(reader, sock, f"USER {username}")
            credential_reply = ""
            if _is_positive(user_reply):
                credential_reply = _send_command(reader, sock, f"PASS {password}")
            accepted = _is_positive(credential_reply)
            if accepted:
                _send_command(reader, sock, "QUIT")
            return accepted, f"USER={user_reply!r}; PASS={credential_reply!r}", ""
    except OSError as exc:
        return False, "", closed_reason(str(exc))


def _greeting_indicator(greeting: str) -> Indicator:
    valid = _is_positive(greeting)
    return Indicator(
        id="pop3.greeting",
        title="POP3 greeting violates response framing",
        category="static_signature",
        triggered=not valid,
        protocol="pop3",
        detail=(
            "positive +OK greeting received"
            if valid
            else f"expected uppercase +OK greeting; received {greeting!r}"
        ),
        evidence=greeting[:_MAX_RESPONSE_BYTES],
        remediation="Emit a standards-conformant, service-specific POP3 greeting",
    )


def _stock_banner_indicator(greeting: str) -> Indicator:
    match = _stock_banner_match(greeting)
    return Indicator(
        id="pop3.stock_banner",
        title="POP3 greeting matches a stock honeypot lure banner",
        category="static_signature",
        triggered=bool(match),
        protocol="pop3",
        detail=(
            f"stock lure greeting matched: {match!r}"
            if match
            else "greeting does not match known POP3 lure banners"
        ),
        evidence=greeting[:_MAX_RESPONSE_BYTES],
        remediation="Replace canned Exchange/POP3 lure banners with deployment-specific text",
        fingerprint_type="pop3_stock_banner",
        requires_corroboration=True,
        tell_tier="origin",
        fidelity="medium",
    )


def _preauth_state_triggered(state_replies: dict[str, str]) -> bool:
    """STAT is the decisive TRANSACTION-state tell; NOOP alone does not trigger.

    RFC 1939 lists both under TRANSACTION, but some stacks answer NOOP loosely
    in AUTHORIZATION. Require STAT +OK so odd servers are less likely to FP.
    """
    return _is_positive(state_replies.get("STAT", ""))


def probe_pop3(host: str, port: int) -> list[Indicator]:
    greeting, greeting_error = _read_greeting(host, port)
    if not greeting:
        reason = greeting_error or "no POP3 greeting"
        return skip_suite(_POP3_SKIP, reason, protocol="pop3", error=greeting_error)

    greeting_ind = _greeting_indicator(greeting)
    stock_ind = _stock_banner_indicator(greeting)
    if greeting_ind.triggered:
        reason = "POP3 response checks skipped after malformed greeting"
        return [
            skipped_indicator(*_POP3_SKIP[0], reason, protocol="pop3"),
            skipped_indicator(*_POP3_SKIP[1], reason, protocol="pop3"),
            greeting_ind,
            skipped_indicator(*_POP3_SKIP[3], reason, protocol="pop3"),
            skipped_indicator(*_POP3_SKIP[4], reason, protocol="pop3"),
            stock_ind,
        ]
    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        return [
            skipped_indicator(*_POP3_SKIP[0], reason, protocol="pop3"),
            skipped_indicator(*_POP3_SKIP[1], reason, protocol="pop3"),
            greeting_ind,
            skipped_indicator(*_POP3_SKIP[3], reason, protocol="pop3"),
            skipped_indicator(*_POP3_SKIP[4], reason, protocol="pop3"),
            stock_ind,
        ]

    state_replies: dict[str, str] = {}
    state_errors: list[str] = []
    # STAT/NOOP: RFC 1939 TRANSACTION-only. CAPA: RFC 2449 optional (AUTHORIZATION OK).
    for command in ("STAT", "NOOP", "CAPA"):
        _, reply, error = _single_command(host, port, command)
        if reply:
            state_replies[command] = reply
        elif error:
            state_errors.append(f"{command}: {error}")
    state_hits = [name for name, reply in state_replies.items() if _is_positive(reply)]
    state_triggered = _preauth_state_triggered(state_replies)
    state_skipped = "STAT" not in state_replies and "NOOP" not in state_replies

    _, unknown_reply, unknown_error = _single_command(host, port, "HPAU")
    unknown_skipped = not unknown_reply
    unknown_hit = _is_positive(unknown_reply)
    if unknown_reply:
        state_replies["HPAU"] = unknown_reply

    blanket_hit, blanket_detail, blanket_evidence = _blanket_auth_failed(state_replies)
    blanket_skipped = not any(k in state_replies for k in ("STAT", "CAPA", "HPAU"))

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
        state_detail = f"authorization-state bypass: STAT returned +OK ({', '.join(state_hits)})"
    elif state_hits:
        state_detail = (
            f"NOOP/CAPA returned +OK before auth but STAT did not "
            f"(not scored alone): {', '.join(state_hits)}"
        )
    else:
        state_detail = "STAT and NOOP were rejected before authentication"

    return [
        Indicator(
            id="pop3.arbitrary_auth",
            title="POP3 accepts two random credential pairs",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason="; ".join(auth_errors) if auth_skipped else "",
            error="; ".join(auth_errors),
            protocol="pop3",
            detail=(
                "two independent random USER/PASS pairs entered the transaction state"
                if auth_hit
                else "random USER/PASS pairs were not both accepted"
            ),
            evidence=",".join(accepted_users) if auth_hit else "; ".join(auth_evidence),
            remediation="Reject synthetic accounts before granting maildrop access",
        ),
        Indicator(
            id="pop3.preauth_state",
            title="POP3 accepts transaction commands before authentication",
            category="state_nonpersist",
            triggered=state_triggered,
            skipped=state_skipped,
            skip_reason="; ".join(state_errors) if state_skipped else "",
            error="; ".join(state_errors),
            protocol="pop3",
            detail=state_detail,
            evidence="; ".join(
                f"{name}={reply!r}"
                for name, reply in state_replies.items()
                if name in ("STAT", "NOOP", "CAPA")
            ),
            remediation="Enforce AUTHORIZATION and TRANSACTION state boundaries",
        ),
        greeting_ind,
        Indicator(
            id="pop3.unknown_command",
            title="POP3 accepts an unrecognized command",
            category="static_signature",
            triggered=unknown_hit,
            skipped=unknown_skipped,
            skip_reason=unknown_error if unknown_skipped else "",
            error=unknown_error,
            protocol="pop3",
            detail=(
                "unrecognized HPAU command returned +OK"
                if unknown_hit
                else "unrecognized HPAU command returned a negative response"
            ),
            evidence=unknown_reply,
            remediation="Return uppercase -ERR for unrecognized commands",
        ),
        Indicator(
            id="pop3.auth_failed_blanket",
            title="POP3 returns the same auth-failed -ERR for distinct pre-auth commands",
            category="static_signature",
            triggered=blanket_hit,
            skipped=blanket_skipped,
            skip_reason="; ".join(state_errors) if blanket_skipped else "",
            protocol="pop3",
            detail=blanket_detail,
            evidence=blanket_evidence,
            remediation=(
                "Return distinct, state-appropriate -ERR text for TRANSACTION-only "
                "commands, unknown verbs, and unimplemented CAPA — not a canned "
                "'Authentication failed' lure"
            ),
            fingerprint_type="pop3_auth_failed_blanket",
            requires_corroboration=False,
            tell_tier="origin",
            fidelity="high",
        ),
        stock_ind,
    ]


__all__ = ["probe_pop3"]
