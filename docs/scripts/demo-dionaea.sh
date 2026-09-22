#!/usr/bin/env bash
# Demo: pip install + Dionaea audit (clean output for GIF/screencast).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="${TARGET:-127.0.0.1}"
export DEBIAN_FRONTEND=noninteractive

printf '\n\033[1mHONEYPOT AUDITOR v1.0.0 — Dionaea demo\033[0m\n'
echo "Install from source + nmap → audit FTP + HTTP + SMB honeypot"
echo "Target: $TARGET  (Dionaea lab ports 22121 / 28081 / 21445)"
sleep "${PAUSE_SEC:-2}"

CLOSED=9
PORTS="ftp=22121,http=28081,smb=21445,smtp=${CLOSED},vnc=${CLOSED},sip=${CLOSED},ssh=${CLOSED},telnet=${CLOSED},redis=${CLOSED}"

docker run --rm \
  -e TARGET="$TARGET" \
  --network host \
  -v /tmp:/out \
  -v "$ROOT:/hpaudit-src:ro" \
  -v "$ROOT/docs/scripts/demo-run-audit.sh:/demo-run-audit.sh:ro" \
  -v "$ROOT/docs/scripts/demo-print-result.py:/demo-print-result.py:ro" \
  ubuntu:24.04 bash /demo-run-audit.sh "Dionaea (FTP/HTTP/SMB)" "$PORTS" "dionaea-audit.json"
