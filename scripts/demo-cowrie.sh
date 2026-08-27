#!/usr/bin/env bash
# Demo: pip install + Cowrie SSH audit (clean output for GIF/screencast).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${TARGET:-54.84.251.249}"
export DEBIAN_FRONTEND=noninteractive

printf '\n\033[1mHONEYPOT AUDITOR — Cowrie demo\033[0m\n'
echo "Install from PyPI + nmap → audit SSH honeypot on port 2222"
echo "Target: $TARGET  (Cowrie SSH :2222 on combined lab)"
sleep "${PAUSE_SEC:-2}"

CLOSED=9
PORTS="ssh=2222,telnet=${CLOSED},smtp=${CLOSED},http=${CLOSED},ftp=${CLOSED},smb=${CLOSED},redis=${CLOSED},vnc=${CLOSED},sip=${CLOSED}"

docker run --rm \
  -e TARGET="$TARGET" \
  -v /tmp:/out \
  -v "$ROOT:/hpaudit-src:ro" \
  -v "$ROOT/scripts/demo-run-audit.sh:/demo-run-audit.sh:ro" \
  -v "$ROOT/scripts/demo-print-result.py:/demo-print-result.py:ro" \
  ubuntu:24.04 bash /demo-run-audit.sh "Cowrie (SSH honeypot)" "$PORTS" "cowrie-audit.json"
