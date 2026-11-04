"""Cobalt Strike / Mythic / Sliver HTTP face classification (non-destructive).

Never treat ``CS detected ⇒ honeypot``. Distinguish:
- ``c2_panel_or_decoy`` — ambiguous stock 404/plain or live-looking panel face
- ``c2_decoy_clone`` — static HTML UI clone without a dynamic C2 backend
"""

from __future__ import annotations

import re

# Stock Cobalt Strike default HTTP 404 face (empty/tiny text/plain).
_CS_PLAIN_404 = re.compile(r"^\s*$")

# Static UI markers seen on Mythic / CS web clones (not proof of a live teamserver).
_MYTHIC_UI = (
    "mythic",
    "graphql",
    "apollo-client",
    "web_ui",
)
_CS_UI = (
    "cobalt strike",
    "teamserver",
    "beacon",
    "aggressor",
)
_SLIVER_UI = (
    "sliver",
    "implant",
)


def match_c2_stock_404_plain(status: int, content_type: str, body: bytes | str) -> str | None:
    """CS-like bare 404 + text/plain + empty/tiny body → ambiguous panel_or_decoy."""
    if int(status) != 404:
        return None
    ctype = (content_type or "").lower()
    # Stock CS faces are text/plain (or omit Content-Type on an empty body).
    if ctype and "text/plain" not in ctype:
        return None
    raw = body if isinstance(body, (bytes, bytearray)) else str(body or "").encode("latin-1", "replace")
    if len(raw) > 64:
        return None
    text = raw.decode("latin-1", "replace")
    if not _CS_PLAIN_404.match(text):
        return None
    return "stock C2-like 404 text/plain empty body"


def match_c2_static_ui_clone(body: bytes | str) -> str | None:
    """Static Mythic/CS/Sliver HTML UI markers (without asserting live backend)."""
    raw = body if isinstance(body, (bytes, bytearray)) else str(body or "").encode("utf-8", "replace")
    low = raw[:8192].decode("utf-8", "replace").lower()
    if not low.strip():
        return None
    if any(tok in low for tok in _MYTHIC_UI if tok != "graphql"):
        if "mythic" in low or "apollo-client" in low or "web_ui" in low:
            return "static Mythic-like UI markers"
    if any(tok in low for tok in _CS_UI):
        return "static Cobalt Strike-like UI markers"
    if any(tok in low for tok in _SLIVER_UI):
        return "static Sliver-like UI markers"
    return None


def has_c2_dynamic_backend(
    *,
    graphql_ok: bool = False,
    websocket_upgrade: bool = False,
    api_json_ok: bool = False,
) -> bool:
    """True when a live-looking C2 control-plane endpoint answered."""
    return bool(graphql_ok or websocket_upgrade or api_json_ok)


def classify_c2_http_face(
    *,
    status: int,
    content_type: str,
    body: bytes | str,
    graphql_ok: bool = False,
    websocket_upgrade: bool = False,
    api_json_ok: bool = False,
) -> tuple[str, str, str, bool, str]:
    """Return (indicator_id, detail, fidelity, requires_corroboration, fingerprint_type).

    Empty indicator_id means no C2 tell.
    """
    dynamic = has_c2_dynamic_backend(
        graphql_ok=graphql_ok,
        websocket_upgrade=websocket_upgrade,
        api_json_ok=api_json_ok,
    )
    stock = match_c2_stock_404_plain(status, content_type, body)
    ui = match_c2_static_ui_clone(body)

    if ui and not dynamic:
        return (
            "http.c2_decoy_clone",
            ui,
            "high",
            False,
            "c2_decoy",
        )
    if stock or (ui and dynamic):
        detail = stock or f"{ui}; dynamic backend present (ambiguous live panel)"
        return (
            "http.c2_panel_or_decoy",
            detail,
            "low" if dynamic and not stock else "medium",
            True,
            "",
        )
    return ("", "", "medium", False, "")
