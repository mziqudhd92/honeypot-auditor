#!/usr/bin/env bash
# Shared runner: install honeypot-auditor in Ubuntu, audit, print clean summary.
# Usage: demo-run-audit.sh <label> <ports> <outfile>
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export PYTHONWARNINGS=ignore
export PYTHONUNBUFFERED=1

T="${TARGET:?missing TARGET}"
LABEL="${1:?label}"
PORTS="${2:?ports}"
OUTFILE="${3:?outfile}"

apt-get update -qq
apt-get install -y -qq python3-venv python3-full nmap ca-certificates >/dev/null

python3 -m venv /opt/venv
if [[ -d /hpaudit-src ]]; then
  cp -a /hpaudit-src /tmp/hpaudit-build
  /opt/venv/bin/pip install -q "/tmp/hpaudit-build[full]"
else
  /opt/venv/bin/pip install -q "honeypot-auditor[full]==1.0.0"
fi

echo ""
echo "Installed: $(/opt/venv/bin/honeypot-auditor --version 2>/dev/null | tr -d '\r')"
echo "           nmap $(nmap --version 2>/dev/null | head -1 | sed 's/Nmap version //;s/ (.*//')"
echo ""

# Only scan remapped (non-placeholder) ports so other local labs do not bleed in.
export PORTS
ONLY_PORTS="$(
  python3 - <<'PY'
import os
parts = [p.strip() for p in os.environ["PORTS"].split(",") if p.strip()]
keep = []
for part in parts:
    if "=" not in part:
        continue
    _, port = part.split("=", 1)
    if port.isdigit() and int(port) not in (0, 9):
        keep.append(port)
print(",".join(keep))
PY
)"
if [[ -z "$ONLY_PORTS" ]]; then
  echo "demo-run-audit: no usable ports in: $PORTS" >&2
  exit 1
fi

echo "Running:"
echo "  honeypot-auditor --target $T -p $ONLY_PORTS --ports $PORTS --confirm-authorized --deep"
echo "  (includes Nmap NSE banner / honeypot scripts)"
echo ""
echo "Probing target (this takes ~45-90 seconds)..."
echo ""

# Run quietly — no Rich tables, no scapy warnings on screen.
/opt/venv/bin/honeypot-auditor \
  --target "$T" \
  -p "$ONLY_PORTS" \
  --ports "$PORTS" \
  --confirm-authorized --deep --timeout 10 \
  --output "/out/$OUTFILE" >/tmp/hpaudit-demo.log 2>/tmp/hpaudit-demo.err || true

python3 /demo-print-result.py "/out/$OUTFILE" "$LABEL"
