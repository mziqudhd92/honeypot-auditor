"""HTTP wire parsing utilities (header order preserved)."""

from __future__ import annotations


def _normalize_crlf(raw: str) -> str:
    return raw.replace("\r\n", "\n")


def _header_blob(raw: str) -> str:
    return _normalize_crlf(raw).split("\n\n", 1)[0]


def parse_header_names(raw: str) -> list[str]:
    """Return header field names in wire order (original casing)."""
    blob = _header_blob(raw)
    names: list[str] = []
    for line in blob.split("\n")[1:]:
        if ":" not in line:
            continue
        name, _ = line.split(":", 1)
        names.append(name.strip())
    return names


def parse_header_map(raw: str) -> dict[str, str]:
    """Return lowercase header name → value map."""
    blob = _header_blob(raw)
    out: dict[str, str] = {}
    for line in blob.split("\n")[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip().lower()] = v.strip()
    return out
