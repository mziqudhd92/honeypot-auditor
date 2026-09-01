#!/usr/bin/env bash
# Capture TLS ServerHello JA3S/JA4S baselines using fixed ClientHello (audit profile).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-127.0.0.1:443}"
HOST="${TARGET%%:*}"
PORT="${TARGET##*:}"
OUT="$ROOT/src/honeypot_auditor/data/tls_profiles.json"
python3 - <<PY
import json, sys
sys.path.insert(0, "$ROOT/src")
from honeypot_auditor.tls_fingerprint import (
    compute_ja3s, compute_ja4s, read_server_hello, tls_handshake,
)
raw, err = tls_handshake("$HOST", int("$PORT"))
if err:
    print(f"handshake failed: {err}", file=sys.stderr)
    sys.exit(1)
parsed = read_server_hello(raw)
if not parsed:
    print("no ServerHello parsed", file=sys.stderr)
    sys.exit(1)
ja3s = compute_ja3s(parsed) if parsed.version < 0x0304 else ""
ja4s = compute_ja4s(parsed) if parsed.version >= 0x0304 else ""
doc = {
    "_meta": {
        "note": "Lab capture — merge into package data/tls_profiles.json as needed",
        "capture": "scripts/capture-tls-baseline.sh HOST:PORT",
    },
    "lures": {
        "captured_baseline": {
            "ja3s": ja3s or "n/a",
            "ja4s": ja4s or "n/a",
            "description": f"Captured from $TARGET using fixed ClientHello",
        }
    },
    "cdn_edge": {},
}
with open("$OUT", "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(f"Wrote {ja3s or ja4s} to $OUT")
PY
