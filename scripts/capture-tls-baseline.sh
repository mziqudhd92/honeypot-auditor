#!/usr/bin/env bash
# Capture TLS ServerHello JA3S/JA4S baselines using fixed ClientHello (audit profile).
#
# Usage:
#   scripts/capture-tls-baseline.sh [--name NAME] [--cdn] [--update-package] TARGET
#
# TARGET may be HOST:PORT, [IPv6]:PORT, or bare HOST/IPv6 (default port 443).
# Default: merge into .lab-tls-capture/tls_profiles.json (never clobber package placeholders).
# --update-package: merge into packaged data (lures or cdn_tls_profiles.json).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="captured_baseline"
KIND="lure"
UPDATE_PACKAGE=0
TARGET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      NAME="${2:?--name requires a value}"
      shift 2
      ;;
    --cdn)
      KIND="cdn"
      shift
      ;;
    --update-package)
      UPDATE_PACKAGE=1
      shift
      ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    -*)
      echo "unknown option: $1" >&2
      exit 2
      ;;
    *)
      TARGET="$1"
      shift
      ;;
  esac
done

if [[ -z "${TARGET}" ]]; then
  echo "usage: $0 [--name NAME] [--cdn] [--update-package] TARGET" >&2
  exit 2
fi

LAB_DIR="$ROOT/.lab-tls-capture"
mkdir -p "$LAB_DIR"

if [[ "$UPDATE_PACKAGE" -eq 1 ]]; then
  if [[ "$KIND" == "cdn" ]]; then
    OUT="$ROOT/src/honeypot_auditor/data/cdn_tls_profiles.json"
  else
    OUT="$ROOT/src/honeypot_auditor/data/tls_profiles.json"
  fi
else
  OUT="$LAB_DIR/tls_profiles.json"
fi

export HPA_CAPTURE_TARGET="$TARGET"
export HPA_CAPTURE_NAME="$NAME"
export HPA_CAPTURE_KIND="$KIND"
export HPA_CAPTURE_OUT="$OUT"
export HPA_CAPTURE_ROOT="$ROOT"

python3 - <<'PY'
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["HPA_CAPTURE_ROOT"])
sys.path.insert(0, str(root / "src"))

from honeypot_auditor.tls_fingerprint import (  # noqa: E402
    capture_tls_baseline,
    clear_tls_profile_cache,
    merge_tls_profile_entry,
    parse_host_port,
)

target = os.environ["HPA_CAPTURE_TARGET"]
name = os.environ["HPA_CAPTURE_NAME"]
kind = os.environ["HPA_CAPTURE_KIND"]
out = Path(os.environ["HPA_CAPTURE_OUT"])

try:
    host, port = parse_host_port(target, default_port=443)
except ValueError as exc:
    print(f"invalid target: {exc}", file=sys.stderr)
    sys.exit(2)

ja3s, ja4s, err = capture_tls_baseline(host, port)
if err:
    print(f"handshake failed: {err}", file=sys.stderr)
    sys.exit(1)

if out.is_file():
    doc = json.loads(out.read_text(encoding="utf-8"))
else:
    doc = {
        "_meta": {
            "note": "Lab capture — merge into package data as needed",
            "capture": "scripts/capture-tls-baseline.sh [--name NAME] [--cdn] TARGET",
        },
        "lures": {},
        "cdn_edge": {},
    }

merged = merge_tls_profile_entry(
    doc,
    name=name,
    ja3s=ja3s if ja3s and "n/a" not in ja3s.lower() else "",
    ja4s=ja4s,
    description=f"Captured from {host}:{port} using fixed ClientHello",
    kind=kind,
)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
clear_tls_profile_cache()
fp = ja3s or ja4s or "(empty)"
print(f"Merged {kind}/{name} ({fp}) into {out}")
PY
