#!/usr/bin/env bash
# Audit the real-services Docker lab. Expect Likely Real Host / score << Suspected.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="${COMPOSE:-docker compose -f $ROOT/deploy/docker-compose.real-services.yml}"
OUT_DIR="${OUT_DIR:-/tmp/hpaudit-real}"
mkdir -p "$OUT_DIR"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  CLI=(env PYTHONPATH="$ROOT/src" "$ROOT/.venv/bin/python" -m honeypot_auditor)
elif [[ -x "$ROOT/.venv/bin/honeypot-auditor" ]]; then
  CLI=("$ROOT/.venv/bin/honeypot-auditor")
else
  echo "missing CLI — run: uv sync / pip install -e '.[full,dev]'" >&2
  exit 1
fi

echo "==> Starting real-service lab..."
$COMPOSE up -d

echo "==> Waiting for listeners..."
wait_port() {
  local port="$1" name="$2" tries="${3:-60}"
  for ((i=1; i<=tries; i++)); do
    if (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1; then
      echo "  $name :$port ready"
      return 0
    fi
    sleep 2
  done
  echo "  WARN: $name :$port not ready after ${tries}*2s" >&2
}

wait_udp() {
  local name="$1" secs="${2:-8}"
  echo "  $name settling ${secs}s"
  sleep "$secs"
}

wait_port 8081 nginx
wait_port 16379 redis
wait_port 15432 postgres
wait_port 13306 mysql 90
wait_port 21211 memcached
wait_port 19200 elasticsearch 120
wait_port 11883 mosquitto
wait_port 27017 mongo 90
wait_port 2223 openssh 90
wait_port 1445 samba
wait_port 3128 squid
wait_port 12121 vsftpd 60
wait_port 2324 telnet 60
wait_port 1110 dovecot-pop3 60
wait_port 2525 postfix 60
wait_udp coredns 5
wait_udp chrony 5
wait_udp tftpd 5

for ((i=1; i<=60; i++)); do
  if curl -fsS "http://127.0.0.1:19200/" >/dev/null 2>&1; then
    echo "  elasticsearch HTTP ready"
    break
  fi
  sleep 2
done

# Remap protocols onto free lab ports. Preset still lists other protocols;
# closed ones skip and do not raise the score.
PORTS=(
  "ssh=2223"
  "http=8081"
  "redis=16379"
  "postgres=15432"
  "mysql=13306"
  "memcached=21211"
  "elasticsearch=19200"
  "mqtt=11883"
  "dns=15353"
  "ntp=1123"
  "mongodb=27017"
  "smb=1445"
  "httpproxy=3128"
  "ftp=12121"
  "telnet=2324"
  "tftp=1069"
  "pop3=1110"
  "smtp=2525"
  # Keep known-busy docker-research defaults off other local honeypot listeners.
  "imap=39943"
  "vnc=39901"
  "sip=39960"
  "snmp=39961"
  "ipp=39931"
  "git=39918"
  "rdp=39989"
  "mssql=39933"
)
PORT_CSV=$(IFS=,; echo "${PORTS[*]}")

echo ""
echo "==> Running honeypot-auditor against real services (TCP from host)..."
"${CLI[@]}" \
  --target 127.0.0.1 \
  --preset docker-research \
  --ports "$PORT_CSV" \
  --timeout 5 \
  -v \
  --output "$OUT_DIR/report.json"

# TFTP replies from an ephemeral TID; Docker Desktop NAT drops host→published UDP
# TID replies. Probe TFTP from inside the compose network instead.
echo ""
echo "==> TFTP in-network probe (Docker Desktop UDP TID workaround)..."
docker run --rm --network honeypot-auditor-real_default \
  -v "$ROOT":/work -w /work \
  -v "$OUT_DIR":/out \
  python:3.12-slim-bookworm \
  bash -lc 'pip install -q -e ".[full]" && python -m honeypot_auditor --target tftpd --ports tftp=69 --preset docker-research --timeout 5 --output /out/tftp-report.json' \
  || echo "WARN: in-network TFTP probe failed" >&2

# SFTP is OpenSSH subsystem on :2223 (no separate probe engine).
if command -v sshpass >/dev/null 2>&1; then
  echo "==> SFTP smoke (OpenSSH :2223)..."
  sshpass -p hpaudit_lab sftp -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -P 2223 hpaudit@127.0.0.1 <<<'ls' >/dev/null \
    && echo "  sftp ok" || echo "  WARN: sftp smoke failed" >&2
fi

python3 - <<'PY' "$OUT_DIR/report.json" "$OUT_DIR/tftp-report.json"
import json, sys, os
paths = [p for p in sys.argv[1:] if os.path.exists(p)]
all_hits = []
for path in paths:
    with open(path) as f:
        r = json.load(f)
    score = float(r.get("score") or 0)
    scoped = float(r.get("scoped_score") or 0)
    threat = r.get("threat_level") or ""
    hits = [
        i for i in r.get("indicators", [])
        if i.get("triggered") and not i.get("suppressed") and not i.get("skipped")
    ]
    print()
    print(f"========== {os.path.basename(path)} ==========")
    print(f"score={score} scoped={scoped} threat={threat!r} tactical={r.get('tactical_action')!r}")
    print(f"triggered={len(hits)}")
    by_proto = {}
    for i in hits:
        by_proto.setdefault(i.get("protocol") or "?", []).append(
            f"{i['id']} ({i.get('detail','')[:80]})"
        )
    for proto, ids in sorted(by_proto.items()):
        print(f"  {proto}:")
        for line in ids:
            print(f"    - {line}")
    all_hits.extend(hits)
    if threat.startswith("Suspected") or threat.startswith("Confirmed") or max(score, scoped) >= 30:
        sys.exit(1)
if all_hits:
    sys.exit(1)
PY
