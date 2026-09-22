#!/usr/bin/env bash
# Demo: pip install + Cowrie SSH audit (clean output for GIF/screencast).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="${TARGET:-127.0.0.1}"
export DEBIAN_FRONTEND=noninteractive

printf '\n\033[1mHONEYPOT AUDITOR v1.0.0 — Cowrie demo\033[0m\n'
echo "Install from source + nmap → audit SSH honeypot"
echo "Target: $TARGET  (Cowrie SSH :28222)"
sleep "${PAUSE_SEC:-2}"

CLOSED=9
PORTS="ssh=28222,telnet=${CLOSED},smtp=${CLOSED},http=${CLOSED},ftp=${CLOSED},smb=${CLOSED},redis=${CLOSED},vnc=${CLOSED},sip=${CLOSED}"

docker run --rm \
  -e TARGET="$TARGET" \
  --network host \
  -v /tmp:/out \
  -v "$ROOT:/hpaudit-src:ro" \
  -v "$ROOT/docs/scripts/demo-run-audit.sh:/demo-run-audit.sh:ro" \
  -v "$ROOT/docs/scripts/demo-print-result.py:/demo-print-result.py:ro" \
  ubuntu:24.04 bash /demo-run-audit.sh "Cowrie (SSH honeypot)" "$PORTS" "cowrie-audit.json"
