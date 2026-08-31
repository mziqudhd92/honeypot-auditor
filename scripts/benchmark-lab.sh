#!/usr/bin/env bash
# Run honeypot-auditor benchmark against CHN + stock honeypots.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${HONEYPOT_AUDITOR:-$ROOT/.venv/bin/honeypot-auditor}"
COMPOSE="${COMPOSE:-docker compose -f $ROOT/deploy/docker-compose.benchmark.yml}"

if [[ ! -x "$CLI" ]]; then
  echo "missing $CLI — run: pip install -e '.[full,dev]'" >&2
  exit 1
fi

echo "==> Starting benchmark honeypots (cowrie + dionaea)..."
$COMPOSE up -d
sleep 8

run_case() {
  local name="$1"
  shift
  echo ""
  echo "========== $name =========="
  "$CLI" "$@" --deep || true
}

# CyberHalluciNet research sensor (should NOT be flagged)
run_case "CHN research (expect Likely Real Host)" \
  --target 127.0.0.1 \
  --preset docker-research \
  --output "/tmp/hpaudit-chn.json"

# Cowrie (should be flagged) — uses existing container on 8022/8023 if present
run_case "Cowrie (expect Suspected/Confirmed Honeypot)" \
  --target 127.0.0.1 \
  --preset iana \
  --ports ssh=8022,telnet=8023 \
  --output "/tmp/hpaudit-cowrie.json"

# Dionaea multi-protocol (no SSH — dionaea does not expose SSH by default)
run_case "Dionaea (expect Suspected/Confirmed Honeypot)" \
  --target 127.0.0.1 \
  --preset iana \
  --ports ftp=8021,http=8024,smb=8445,redis=26379,smtp=8025,vnc=8026,sip=8027 \
  --timeout 5 \
  --output "/tmp/hpaudit-dionaea.json"

echo ""
echo "JSON reports: /tmp/hpaudit-{chn,cowrie,dionaea}.json"
