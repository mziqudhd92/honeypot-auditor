"""Docker Engine HTTP API fingerprint engine.

Protocol non-compliance strategies (read-only — never create/start containers,
pull images, exec, or write volumes/networks):
  · arbitrary_auth — anonymous GET /version challenged 401/403, then two
    entropy-varied Basic credentials both return Engine version JSON
  · state_nonpersist — /version Version mismatches /info ServerVersion after
    reconnect
  · static_signature — stock ApiVersion/Version/GitCommit lures; unknown path
    returns version/info-shaped 200; DELETE/PUT on ``/_ping`` method stubs;
    ``/info`` missing required fields or echoing ``/version``; ``/containers/json``
    version-echo facade; ping/version framing

Ports 2375 / lab 12375 (plain HTTP). TLS port 2376 is out of scope for v1.

See docs/tcp/DOCKER.md and Docker Engine API docs (System ping, version, info).
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from honeypot_auditor.config import effective_user_agent
from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason, tcp_transact
from honeypot_auditor.probes.common import (
    entropy_varied_creds,
    is_safe_mode,
    jittered_reconnect_pause,
    rtt_evidence,
    skip_suite,
)
from honeypot_auditor.settings import settings

_DOCKER_SKIP = (
    (
        "docker.arbitrary_auth",
        "Docker accepts two entropy-varied Basic credentials on /version",
        "arbitrary_auth",
    ),
    (
        "docker.state_nonpersist",
        "Docker /version metadata mismatches /info ServerVersion",
        "state_nonpersist",
    ),
    (
        "docker.ping_framing",
        "Docker /_ping response is not plain-text OK",
        "static_signature",
    ),
    (
        "docker.version_framing",
        "Docker /version response is not a valid Engine version document",
        "static_signature",
    ),
    (
        "docker.path_facade",
        "Docker answers unknown API paths with a version/info-shaped 200",
        "static_signature",
    ),
    (
        "docker.method_stub",
        "Docker ignores HTTP method on /_ping (DELETE/PUT stub)",
        "static_signature",
    ),
    (
        "docker.stock_version",
        "Docker version metadata matches a stock honeypot lure",
        "static_signature",
    ),
    (
        "docker.info_stub",
        "Docker /info is missing required fields or echoes /version",
        "static_signature",
    ),
    (
        "docker.containers_stub",
        "Docker /containers/json is not a container list (version/info echo)",
        "static_signature",
    ),
    (
        "docker.tls_hint_mismatch",
        "Docker TLS transport hints disagree with plain-HTTP Engine API",
        "static_signature",
    ),
)

# Decisive lure tokens — rare outside honeypots; score without corroboration.
# Anti-drift: no product-named honeypot IOCs as decisive alone.
_STOCK_GITCOMMITS_DECISIVE = frozenset(
    {
        "deadbeef",
        "0000000",
        "1111111",
        "abcdef0",
        "honeypot",
        "testcommit",
        "ffffff",
    }
)
_STOCK_VERSIONS_DECISIVE = frozenset(
    {
        "0.0.0",
        "0.0.1",
        "honeypot",
        "fake-docker",
        "docker-honeypot",
    }
)
_STOCK_APIVERSIONS_DECISIVE = frozenset(
    {
        "0.0",
        "99.99",
    }
)

# Generic / still-deployed values — common on real daemons; corroboration-gated.
_STOCK_APIVERSIONS_GENERIC = frozenset(
    {
        "1.0",  # too common historically to score alone (was decisive → FP risk)
        "1.24",
        "1.25",
        "1.37",
        "1.38",
        "1.39",
        "1.40",
        "1.41",
        "1.42",
    }
)
_STOCK_VERSIONS_GENERIC = frozenset(
    {
        "18.06.0",
        "18.09.0",
        "18.09.7",
        "19.03.0",
        "19.03.8",
        "19.03.12",
        "20.10.0",
        "20.10.5",
        "20.10.7",
        "20.10.12",
        "20.10.14",
        "20.10.17",
        "20.10.21",
    }
)

_INFO_REQUIRED_FIELDS = frozenset(
    {
        "ID",
        "Containers",
        "Images",
        "Driver",
        "Name",
        "ServerVersion",
    }
)

# Extra keys that distinguish a real Engine /version document from thin JSON.
_VERSION_SHAPE_FIELDS = frozenset(
    {
        "GitCommit",
        "GoVersion",
        "Os",
        "Arch",
        "MinAPIVersion",
        "Platform",
        "KernelVersion",
        "BuildTime",
    }
)

_TLS_SKIP_REASON = "TLS Engine API port 2376 out of scope for v1"


def _http_exchange(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    extra_headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> tuple[int, dict[str, str], bytes, str]:
    """Minimal HTTP/1.1 exchange over TCP. Returns (status, headers, body, error)."""
    hdrs = {
        "Host": f"{host}:{port}",
        "User-Agent": effective_user_agent(),
        "Accept": "*/*",
        "Connection": "close",
    }
    if extra_headers:
        hdrs.update(extra_headers)
    if body:
        hdrs.setdefault("Content-Type", "application/json")
        hdrs["Content-Length"] = str(len(body))
    request = (
        f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    ).encode("ascii", "replace") + body
    raw, err = tcp_transact(host, port, request, recv_first=False, timeout=settings.timeout_seconds)
    if err and not raw:
        return 0, {}, b"", closed_reason(err)
    if not raw:
        return 0, {}, b"", "empty HTTP response"
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return 0, {}, rest, "missing status line"
    status_line = lines[0].decode("latin-1", "replace")
    parts = status_line.split()
    status = 0
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        try:
            status = int(parts[1])
        except ValueError:
            status = 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.decode("latin-1", "replace").strip().lower()] = value.decode(
            "latin-1", "replace"
        ).strip()
    return status, headers, rest, ""


def _parse_json(body: bytes) -> dict[str, Any] | list[Any] | None:
    if not body:
        return None
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, (dict, list)):
        return data
    return None


def _as_dict(data: dict[str, Any] | list[Any] | None) -> dict[str, Any] | None:
    return data if isinstance(data, dict) else None


def _is_ping_ok(status: int, body: bytes) -> bool:
    if status != 200:
        return False
    text = body.decode("utf-8", "replace").strip()
    return text == "OK"


def _is_docker_version(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    api = doc.get("ApiVersion")
    version = doc.get("Version")
    if not (
        isinstance(api, str)
        and bool(api.strip())
        and isinstance(version, str)
        and bool(version.strip())
    ):
        return False
    # Require additional Engine shape so thin {"ApiVersion","Version"} JSON
    # (e.g. ApiVersion=1.0 lure stubs) is not treated as a Docker speaker.
    extras = sum(1 for key in _VERSION_SHAPE_FIELDS if key in doc)
    return extras >= 2


def _is_docker_info(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    # Must not be a bare version document.
    if _is_docker_version(doc) and "ID" not in doc and "Containers" not in doc:
        return False
    present = sum(1 for key in _INFO_REQUIRED_FIELDS if key in doc)
    return present >= 4


def _stock_version_assessment(doc: dict[str, Any]) -> tuple[str | None, bool]:
    """Return ``(detail, requires_corroboration)`` for stock lure metadata.

    Decisive tokens (canned GitCommit, absurd/frozen Version/ApiVersion) score
    alone. Common still-deployed ApiVersion/Version values only contribute when
    another category hit corroborates them — or when mixed with a decisive token
    on the same version document.
    """
    api = str(doc.get("ApiVersion") or "").strip()
    version = str(doc.get("Version") or "").strip()
    commit = str(doc.get("GitCommit") or "").strip().lower()
    hits: list[str] = []
    decisive = False

    if commit in _STOCK_GITCOMMITS_DECISIVE:
        hits.append(f"GitCommit={commit}")
        decisive = True
    elif commit and len(commit) < 6:
        hits.append(f"GitCommit={commit}")

    ver_l = version.lower()
    if ver_l in _STOCK_VERSIONS_DECISIVE or version in _STOCK_VERSIONS_DECISIVE:
        hits.append(f"Version={version}")
        decisive = True
    elif version in _STOCK_VERSIONS_GENERIC:
        hits.append(f"Version={version}")

    if api in _STOCK_APIVERSIONS_DECISIVE:
        hits.append(f"ApiVersion={api}")
        decisive = True
    elif api in _STOCK_APIVERSIONS_GENERIC:
        hits.append(f"ApiVersion={api}")

    if not hits:
        return None, False
    requires = not decisive
    return "; ".join(hits), requires


def _looks_like_api_not_found(status: int, doc: dict[str, Any] | None) -> bool:
    if status in {400, 404, 405}:
        return True
    if not doc:
        return status >= 400
    message = str(doc.get("message") or "").lower()
    if "not found" in message or "page not found" in message:
        return True
    return False


def _looks_like_version_or_info(doc: dict[str, Any] | None) -> bool:
    if not doc:
        return False
    return _is_docker_version(doc) or _is_docker_info(doc)


def _basic_auth_header(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _state_version_info_mismatch(
    version: dict[str, Any],
    *,
    info_doc: dict[str, Any] | None,
    info_status: int,
) -> tuple[bool, str]:
    """Return (hit, detail) when /version and /info advertise different Engine versions."""
    ver = _normalize_engine_version(str(version.get("Version") or ""))
    if info_status != 200 or not info_doc:
        return False, "info unavailable for version coherence check"
    server = _normalize_engine_version(str(info_doc.get("ServerVersion") or ""))
    if not ver or not server:
        return False, "Version/ServerVersion missing on one side"
    if ver != server:
        return True, (
            f"/version Version={version.get('Version')!r} vs "
            f"/info ServerVersion={info_doc.get('ServerVersion')!r}"
        )
    return False, f"Version coherent with ServerVersion ({ver})"


def _normalize_engine_version(raw: str) -> str:
    """Compare Engine versions on major.minor.patch; ignore -ce / build suffixes."""
    text = (raw or "").strip().lower()
    if not text:
        return ""
    # Drop common distro/build suffixes: 24.0.7-ce, 20.10.12+azure, …
    for sep in ("-", "+", "_"):
        if sep in text:
            text = text.split(sep, 1)[0]
    parts = text.split(".")
    nums: list[str] = []
    for part in parts[:3]:
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        nums.append(str(int(digits)))
    return ".".join(nums) if nums else text


def probe_docker(host: str, port: int) -> list[Indicator]:
    ping_status, _ping_hdrs, ping_body, ping_err = _http_exchange(host, port, "GET", "/_ping")
    if ping_err and not ping_body and ping_status == 0:
        return skip_suite(_DOCKER_SKIP, ping_err, protocol="docker", error=ping_err)

    ping_ok = _is_ping_ok(ping_status, ping_body)
    ping_hit = not ping_ok
    if ping_ok:
        ping_detail = "GET /_ping returned plain-text OK"
    else:
        ping_detail = (
            "GET /_ping did not return plain-text OK "
            f"(status={ping_status}, body={ping_body[:80]!r})"
        )

    ver_status, _ver_hdrs, ver_body, ver_err = _http_exchange(host, port, "GET", "/version")
    version = _as_dict(_parse_json(ver_body))
    version_ok = _is_docker_version(version)
    auth_from_challenge = False
    auth_ok = 0
    auth_notes: list[str] = []
    auth_err = ""
    auth_skipped = False
    low_user = ""
    high_user = ""

    # Security-gated Engine faces challenge GET /version. A skin that then
    # accepts any Basic credential and returns version JSON is an auth bypass.
    # An already-open anonymous version document is not a bypass.
    if (not version_ok or version is None) and ver_status in (401, 403):
        anon_status = ver_status
        (low_user, low_pass), (high_user, high_pass) = entropy_varied_creds()
        unlocked: tuple[int, bytes] | None = None
        for label, user, password in (
            ("low-entropy", low_user, low_pass),
            ("high-entropy", high_user, high_pass),
        ):
            a_status, _a_hdrs, a_body, a_err = _http_exchange(
                host,
                port,
                "GET",
                "/version",
                extra_headers=_basic_auth_header(user, password),
            )
            if a_err and a_status == 0 and not a_body:
                auth_err = auth_err or a_err
                auth_notes.append(f"{label}: unanswered ({a_err})")
                continue
            a_doc = _as_dict(_parse_json(a_body))
            if a_status == 200 and _is_docker_version(a_doc):
                auth_ok += 1
                unlocked = (a_status, a_body)
                version = a_doc
                auth_notes.append(f"{label}: Basic unlocked /version (status=200)")
            else:
                auth_notes.append(f"{label}: Basic status={a_status}")
        if auth_ok == 2 and unlocked is not None and version is not None and _is_docker_version(
            version
        ):
            ver_status, ver_body = unlocked
            version_ok = True
            auth_from_challenge = True
            version_detail = (
                f"anonymous GET /version was {anon_status}; version unlocked by arbitrary Basic "
                f"ApiVersion={version.get('ApiVersion')!r} Version={version.get('Version')!r}"
            )
        else:
            version_detail = (
                "GET /version challenged "
                f"(status={anon_status}); Basic did not unlock Engine version "
                f"({'; '.join(auth_notes) or 'no Basic attempts'})"
            )
    elif version is not None and version_ok:
        version_detail = (
            f"version ok ApiVersion={version.get('ApiVersion')!r} "
            f"Version={version.get('Version')!r}"
        )
    else:
        version_detail = (
            "GET /version did not return a Docker Engine version document "
            f"(status={ver_status}, json_keys={sorted(version)[:8] if version else []})"
        )

    # Non-speaker: no usable version document → framing only (plus ping result).
    # Medium fidelity: avoid dual high-signal static hits on random HTTP :2375.
    if not version_ok or version is None:
        out: list[Indicator] = []
        for spec in _DOCKER_SKIP:
            if spec[0] == "docker.ping_framing":
                out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=ping_hit and bool(ping_body or ping_status),
                        skipped=not ping_body and ping_status == 0 and bool(ping_err),
                        skip_reason=ping_err if not ping_body and ping_status == 0 else "",
                        protocol="docker",
                        detail=ping_detail
                        if (ping_body or ping_status)
                        else ping_err or "not a Docker speaker",
                        evidence=(ping_body[:400].decode("utf-8", "replace") if ping_body else ""),
                        remediation="Return HTTP 200 with plain-text body OK on GET /_ping",
                        fidelity="medium",
                    )
                )
            elif spec[0] == "docker.version_framing":
                out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=bool(ver_body) or ver_status > 0,
                        skipped=not ver_body and ver_status == 0,
                        skip_reason=ver_err if not ver_body and ver_status == 0 else "",
                        protocol="docker",
                        detail=version_detail
                        if (ver_body or ver_status)
                        else ver_err or "not a Docker speaker",
                        evidence=(ver_body[:400].decode("utf-8", "replace") if ver_body else ""),
                        remediation="Return Docker Engine version JSON on GET /version",
                        fidelity="medium",
                    )
                )
            elif spec[0] == "docker.tls_hint_mismatch":
                out.append(
                    skipped_indicator(
                        *spec,
                        _TLS_SKIP_REASON,
                        protocol="docker",
                    )
                )
            else:
                out.append(
                    skipped_indicator(
                        *spec,
                        "not a Docker Engine HTTP speaker",
                        protocol="docker",
                        error=ver_err or ping_err,
                    )
                )
        return out

    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        safe_out: list[Indicator] = []
        for spec in _DOCKER_SKIP:
            if spec[0] == "docker.ping_framing":
                safe_out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=ping_hit,
                        protocol="docker",
                        detail=ping_detail,
                        evidence=(ping_body[:400].decode("utf-8", "replace") if ping_body else ""),
                        remediation="Return HTTP 200 with plain-text body OK on GET /_ping",
                    )
                )
            elif spec[0] == "docker.version_framing":
                safe_out.append(
                    Indicator(
                        id=spec[0],
                        title=spec[1],
                        category=spec[2],
                        triggered=False,
                        protocol="docker",
                        detail=version_detail,
                        evidence=ver_body[:400].decode("utf-8", "replace"),
                        remediation="Return Docker Engine version JSON on GET /version",
                    )
                )
            else:
                skip_reason = _TLS_SKIP_REASON if spec[0] == "docker.tls_hint_mismatch" else reason
                safe_out.append(skipped_indicator(*spec, skip_reason, protocol="docker"))
        return safe_out

    # --- stock ApiVersion / Version / GitCommit ---
    stock_detail, stock_requires = _stock_version_assessment(version)
    stock_hit = bool(stock_detail)

    # --- unknown API path facade ---
    mystery = f"/_hpa_nonexistent_{secrets.token_hex(3)}"
    path_status, _path_hdrs, path_body, path_err = _http_exchange(host, port, "GET", mystery)
    path_doc = _as_dict(_parse_json(path_body))
    path_skipped = bool(path_err) and path_status == 0 and not path_body
    path_hit = False
    path_detail = "unknown-path handling not evaluated"
    if not path_skipped:
        if _looks_like_api_not_found(path_status, path_doc):
            path_detail = f"compliant unknown-path handling (status={path_status})"
        elif path_status == 200 and (_looks_like_version_or_info(path_doc) or path_doc == version):
            path_hit = True
            path_detail = (
                f"GET {mystery} returned status=200 version/info-shaped JSON "
                "(unknown API routes should not echo Engine version/info documents)"
            )
        else:
            path_detail = f"unknown-path reply status={path_status}"

    # --- method stubs: DELETE / PUT on /_ping ---
    method_notes: list[str] = []
    method_hit = False
    method_skipped = True
    method_err = ""
    for verb in ("DELETE", "PUT"):
        m_status, _m_hdrs, m_body, m_err = _http_exchange(host, port, verb, "/_ping")
        if m_err and m_status == 0 and not m_body:
            method_notes.append(f"{verb}: unanswered ({m_err})")
            method_err = method_err or m_err
            continue
        method_skipped = False
        if m_status == 200 and _is_ping_ok(m_status, m_body):
            method_hit = True
            method_notes.append(f"{verb} /_ping returned 200 OK (method ignored)")
        elif m_status == 200:
            method_hit = True
            method_notes.append(f"{verb} /_ping returned status=200 body={m_body[:40]!r}")
        else:
            method_notes.append(f"{verb} /_ping status={m_status}")
    method_detail = "; ".join(method_notes) if method_notes else "method handling not evaluated"

    # --- /info must be a system-info document, not a version echo ---
    info_status, _info_hdrs, info_body, info_err = _http_exchange(host, port, "GET", "/info")
    info_doc = _as_dict(_parse_json(info_body))
    info_skipped = bool(info_err) and info_status == 0 and not info_body
    info_hit = False
    info_detail = "info endpoint not evaluated"
    if not info_skipped:
        if info_status in {401, 403}:
            info_skipped = True
            info_detail = f"info denied/unavailable (status={info_status})"
        elif info_status == 200 and info_doc is not None and _is_docker_info(info_doc):
            info_detail = (
                f"info ok Name={info_doc.get('Name')!r} "
                f"Driver={info_doc.get('Driver')!r} "
                f"Containers={info_doc.get('Containers')}"
            )
        elif info_status == 200 and (
            info_doc == version or (_is_docker_version(info_doc) and not _is_docker_info(info_doc))
        ):
            info_hit = True
            info_detail = (
                "GET /info returned a version-shaped document "
                "(expected system info fields: ID, Containers, Images, Driver, Name, …)"
            )
        elif info_status == 200:
            info_hit = True
            info_detail = (
                f"GET /info status=200 is missing required system-info fields "
                f"(keys={sorted(info_doc)[:8] if info_doc else []})"
            )
        elif _looks_like_api_not_found(info_status, info_doc):
            info_skipped = True
            info_detail = f"info denied/unavailable (status={info_status})"
        else:
            info_detail = f"GET /info status={info_status}"

    # --- /containers/json discovery shape (must be a JSON array) ---
    c_status, _c_hdrs, c_body, c_err = _http_exchange(host, port, "GET", "/containers/json")
    c_parsed = _parse_json(c_body)
    containers_skipped = bool(c_err) and c_status == 0 and not c_body
    containers_hit = False
    containers_detail = "containers discovery not evaluated"
    if not containers_skipped:
        if c_status in {401, 403}:
            containers_skipped = True
            containers_detail = f"/containers/json denied (status={c_status})"
        elif c_status == 200 and isinstance(c_parsed, list):
            containers_detail = f"/containers/json ok list_len={len(c_parsed)}"
        elif c_status == 200 and (
            _looks_like_version_or_info(_as_dict(c_parsed) if isinstance(c_parsed, dict) else None)
            or c_parsed == version
        ):
            containers_hit = True
            containers_detail = (
                "GET /containers/json returned version/info-shaped JSON "
                "(expected a JSON array of container summaries)"
            )
        elif c_status == 200:
            containers_hit = True
            containers_detail = (
                f"GET /containers/json status=200 is not a JSON array "
                f"(type={type(c_parsed).__name__})"
            )
        elif _looks_like_api_not_found(c_status, _as_dict(c_parsed) if isinstance(c_parsed, dict) else None):
            containers_skipped = True
            containers_detail = f"/containers/json denied/unavailable (status={c_status})"
        else:
            containers_detail = f"GET /containers/json status={c_status}"

    # --- arbitrary_auth ---
    if auth_from_challenge:
        auth_hit = auth_ok == 2
        auth_detail = (
            "anonymous GET /version challenged; two entropy-varied Basic credentials "
            "both returned Engine version JSON"
            if auth_hit
            else ("; ".join(auth_notes) if auth_notes else "Basic challenge not bypassed")
        )
        auth_skipped = False
    elif ver_status in (401, 403) and auth_notes:
        # Challenge path ran but did not unlock (should not reach here for Docker —
        # non-speaker exit — kept for consistent detail if framing policy changes).
        auth_hit = False
        auth_detail = "; ".join(auth_notes)
        auth_skipped = auth_ok == 0 and bool(auth_err) and all(
            "unanswered" in n for n in auth_notes
        )
    else:
        auth_hit = False
        auth_detail = (
            "anonymous GET /version already returned Engine version JSON; "
            "Basic is not a credential gate"
        )
        auth_skipped = False

    # --- state_nonpersist: re-fetch /info after pause and compare to /version ---
    pause_s = jittered_reconnect_pause()
    s_status, _s_hdrs, s_body, s_err = _http_exchange(host, port, "GET", "/info")
    s_doc = _as_dict(_parse_json(s_body))
    state_err = s_err
    state_evidence = s_body or info_body
    if bool(s_err) and s_status == 0 and not s_body:
        state_skipped = True
        state_hit = False
        state_detail = closed_reason(state_err)
    elif s_status in {401, 403} or (
        _looks_like_api_not_found(s_status, s_doc) and s_status != 200
    ):
        state_skipped = True
        state_hit = False
        state_detail = f"/info denied/unavailable for coherence check (status={s_status})"
    else:
        state_skipped = False
        state_hit, state_detail = _state_version_info_mismatch(
            version, info_doc=s_doc, info_status=s_status
        )
    rtt_note = rtt_evidence(pause_s * 1000.0)
    if rtt_note and state_hit:
        state_detail = f"{state_detail}; pause_{rtt_note}"

    return [
        Indicator(
            id="docker.arbitrary_auth",
            title="Docker accepts two entropy-varied Basic credentials on /version",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason=closed_reason(auth_err) if auth_skipped else "",
            error=auth_err if auth_skipped else "",
            protocol="docker",
            detail=auth_detail,
            evidence=f"{low_user},{high_user}" if auth_hit else "",
            remediation="Reject unknown Basic credentials instead of always returning /version",
            fidelity="decisive" if auth_hit else "medium",
        ),
        Indicator(
            id="docker.state_nonpersist",
            title="Docker /version metadata mismatches /info ServerVersion",
            category="state_nonpersist",
            triggered=state_hit,
            skipped=state_skipped,
            skip_reason=state_detail if state_skipped else "",
            error=state_err,
            protocol="docker",
            detail=state_detail,
            evidence=(state_evidence[:400].decode("utf-8", "replace") if state_evidence else ""),
            remediation="Keep Version coherent across GET /version and GET /info ServerVersion",
            fidelity="high" if state_hit else "medium",
        ),
        Indicator(
            id="docker.ping_framing",
            title="Docker /_ping response is not plain-text OK",
            category="static_signature",
            triggered=ping_hit,
            protocol="docker",
            detail=ping_detail,
            evidence=(ping_body[:500].decode("utf-8", "replace") if ping_body else ""),
            remediation="Return HTTP 200 with plain-text body OK on GET /_ping",
            fidelity="high" if ping_hit else "medium",
        ),
        Indicator(
            id="docker.version_framing",
            title="Docker /version response is not a valid Engine version document",
            category="static_signature",
            triggered=False,
            protocol="docker",
            detail=version_detail,
            evidence=ver_body[:500].decode("utf-8", "replace"),
            remediation="Return Docker Engine version JSON on GET /version",
        ),
        Indicator(
            id="docker.path_facade",
            title="Docker answers unknown API paths with a version/info-shaped 200",
            category="static_signature",
            triggered=path_hit,
            skipped=path_skipped,
            skip_reason=path_err if path_skipped else "",
            error=path_err,
            protocol="docker",
            detail=path_detail,
            evidence=(path_body[:400].decode("utf-8", "replace") if path_body else ""),
            remediation="Return 404 JSON errors for unknown HTTP API routes",
            fidelity="high" if path_hit else "medium",
        ),
        Indicator(
            id="docker.method_stub",
            title="Docker ignores HTTP method on /_ping (DELETE/PUT stub)",
            category="static_signature",
            triggered=method_hit,
            skipped=method_skipped,
            skip_reason=method_err if method_skipped else "",
            error=method_err,
            protocol="docker",
            detail=method_detail,
            evidence=method_detail[:400],
            remediation="Do not treat DELETE/PUT /_ping as a successful ping",
            fidelity="high" if method_hit else "medium",
        ),
        Indicator(
            id="docker.stock_version",
            title="Docker version metadata matches a stock honeypot lure",
            category="static_signature",
            triggered=stock_hit,
            protocol="docker",
            detail=stock_detail or "version metadata does not match stock lure tokens",
            evidence=ver_body[:500].decode("utf-8", "replace"),
            remediation="Use unique Version / ApiVersion / GitCommit metadata",
            requires_corroboration=stock_requires,
            fidelity="medium",
        ),
        Indicator(
            id="docker.info_stub",
            title="Docker /info is missing required fields or echoes /version",
            category="static_signature",
            triggered=info_hit,
            skipped=info_skipped,
            skip_reason=info_detail if info_skipped else "",
            error=info_err,
            protocol="docker",
            detail=info_detail,
            evidence=(info_body[:400].decode("utf-8", "replace") if info_body else ""),
            remediation="Implement GET /info with ID, Containers, Images, Driver, Name, ServerVersion",
            fidelity="high" if info_hit else "medium",
        ),
        Indicator(
            id="docker.containers_stub",
            title="Docker /containers/json is not a container list (version/info echo)",
            category="static_signature",
            triggered=containers_hit,
            skipped=containers_skipped,
            skip_reason=containers_detail if containers_skipped else "",
            error=c_err,
            protocol="docker",
            detail=containers_detail,
            evidence=(c_body[:400].decode("utf-8", "replace") if c_body else ""),
            remediation="Return a JSON array of container summaries on GET /containers/json",
            fidelity="high" if containers_hit else "medium",
        ),
        Indicator(
            id="docker.tls_hint_mismatch",
            title="Docker TLS transport hints disagree with plain-HTTP Engine API",
            category="static_signature",
            triggered=False,
            skipped=True,
            skip_reason=_TLS_SKIP_REASON,
            protocol="docker",
            detail=_TLS_SKIP_REASON,
            remediation="TLS Engine API (2376) probing is deferred beyond v1",
        ),
    ]


__all__ = ["probe_docker"]
