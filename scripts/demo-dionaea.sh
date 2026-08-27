#!/usr/bin/env bash
# Demo: pip install + Dionaea audit (clean output for GIF/screencast).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${TARGET:-54.234.30.254}"
export DEBIAN_FRONTEND=noninteractive

printf '\n\033[1mHONEYPOT AUDITOR — Dionaea demo\033[0m\n'
echo "Install from PyPI + nmap → audit FTP + HTTP + SMB honeypot"
echo "Target: $TARGET  (Dionaea-only lab — ports 21, 80, 445, 5060 + nmap)"
sleep "${PAUSE_SEC:-2}"

CLOSED=9
PORTS="ftp=21,http=80,smb=445,smtp=25,vnc=5900,sip=5060,ssh=${CLOSED},telnet=${CLOSED},redis=${CLOSED}"

docker run --rm \
  -e TARGET="$TARGET" \
  -v /tmp:/out \
  -v "$ROOT:/hpaudit-src:ro" \
  -v "$ROOT/scripts/demo-run-audit.sh:/demo-run-audit.sh:ro" \
  -v "$ROOT/scripts/demo-print-result.py:/demo-print-result.py:ro" \
  ubuntu:24.04 bash /demo-run-audit.sh "Dionaea (FTP/HTTP/SMB)" "$PORTS" "dionaea-audit.json"
