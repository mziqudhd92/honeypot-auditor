#!/usr/bin/env bash
# Lab-tour demo: three authorized honeypot hosts, mixed CLI flags (-v / --deep).
# Designed for asciinema → polished cast → GIF (see scripts/record-lab-tour-demo.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HPA="${HPA:-$ROOT/.venv/bin/honeypot-auditor}"
if [[ ! -x "$HPA" ]]; then
  HPA="$(command -v honeypot-auditor || true)"
fi
[[ -n "$HPA" && -x "$HPA" ]] || { echo "honeypot-auditor not found (venv or PATH)" >&2; exit 1; }

COWRIE="${COWRIE_TARGET:-54.237.202.94}"
DD="${DD_TARGET:-54.204.78.207}"
TARPIT="${TARPIT_TARGET:-13.218.137.93}"

PAUSE_TITLE="${PAUSE_TITLE:-2.2}"
PAUSE_RESULT="${PAUSE_RESULT:-7.5}"
PAUSE_SCENE="${PAUSE_SCENE:-1.4}"
TIMEOUT="${DEMO_TIMEOUT:-5}"

export PYTHONUNBUFFERED=1
export PYTHONWARNINGS=ignore
export TERM="${TERM:-xterm-256color}"
export COLUMNS="${COLUMNS:-100}"
export LINES="${LINES:-32}"

clear_soft() {
  printf '\033[2J\033[H'
}

banner() {
  local title="$1"
  local sub="$2"
  clear_soft
  printf '\n'
  printf '  \033[38;5;46m╔══════════════════════════════════════════════════════════════════╗\033[0m\n'
  printf '  \033[38;5;46m║\033[0m  \033[1;97mHONEYPOT-AUDITOR\033[0m  \033[38;5;244m· lab tour · authorized targets only\033[0m      \033[38;5;46m║\033[0m\n'
  printf '  \033[38;5;46m╠══════════════════════════════════════════════════════════════════╣\033[0m\n'
  printf '  \033[38;5;46m║\033[0m  \033[1;93m%s\033[0m\033[38;5;46m║\033[0m\n' "$(printf '%-64s' "$title")"
  printf '  \033[38;5;46m║\033[0m  \033[38;5;250m%s\033[0m\033[38;5;46m║\033[0m\n' "$(printf '%-64s' "$sub")"
  printf '  \033[38;5;46m╚══════════════════════════════════════════════════════════════════╝\033[0m\n'
  printf '\n'
}

type_cmd() {
  local cmd="$1"
  printf '  \033[38;5;244m$\033[0m '
  local i
  for ((i = 0; i < ${#cmd}; i++)); do
    printf '%s' "${cmd:i:1}"
    sleep 0.012
  done
  printf '\n\n'
  sleep 0.35
}

wait_probe() {
  # Sparse status updates so asciinema idle compression can shorten long probes.
  local pid="$1"
  local label="$2"
  local start=$SECONDS
  local frames=('▮▯▯▯' '▮▮▯▯' '▮▮▮▯' '▮▮▮▮' '▯▮▮▮' '▯▯▮▮' '▯▯▯▮' '▯▯▯▯')
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    local elapsed=$((SECONDS - start))
    printf '\r  \033[38;5;51m%s\033[0m  %s  \033[38;5;244m%ss\033[0m   ' \
      "${frames[i % ${#frames[@]}]}" "$label" "$elapsed"
    i=$((i + 1))
    sleep 0.9
  done
  printf '\r  \033[38;5;46m▮▮▮▮\033[0m  %s  \033[1;32mdone\033[0m          \n\n' "$label"
  wait "$pid" || true
}

run_live() {
  # Live Rich UI (short scans / -v demos).
  local -a args=("$@")
  "$HPA" "${args[@]}" || true
}

run_background_then_show() {
  # Long probes: hide live spinner noise, show compact wait + final report.
  local out="$1"
  shift
  local -a args=("$@")
  local label="deep audit in progress"
  "$HPA" "${args[@]}" --output "$out" >/tmp/hpa-lab-tour.log 2>/tmp/hpa-lab-tour.err &
  wait_probe $! "$label"
  python3 "$ROOT/scripts/demo-print-result.py" "$out" "dd-honeypot stack (--deep)"
  # Also show threat/confidence line from JSON for the scoreboard beat.
  python3 - <<PY
import json
r=json.load(open("$out"))
print()
print(f"  Confidence : {r.get('confidence','?')}")
print(f"  Tactical   : {r.get('tactical_action','?')}")
hits=[i for i in r.get('indicators',[]) if i.get('triggered')]
print(f"  Triggers   : {len(hits)}")
for i in hits[:8]:
    print(f"    • {i.get('id')} — {(i.get('detail') or '')[:70]}")
if len(hits)>8:
    print(f"    … +{len(hits)-8} more")
print()
PY
}

scoreboard() {
  local c="$1" d="$2" t="$3"
  printf '\n'
  printf '  \033[1;97m┌──────────────────────── LAB TOUR SCOREBOARD ────────────────────────┐\033[0m\n'
  printf '  \033[1;97m│\033[0m  \033[38;5;208mCowrie\033[0m   %-15s  \033[38;5;244m-p 22 -v\033[0m                 \033[1;97m│\033[0m\n' "$c"
  printf '  \033[1;97m│\033[0m  \033[38;5;39mdd-stack\033[0m %-15s  \033[38;5;244m-p 22,80,3306 --deep\033[0m     \033[1;97m│\033[0m\n' "$d"
  printf '  \033[1;97m│\033[0m  \033[38;5;201mtarpit\033[0m   %-15s  \033[38;5;244m-p 80,443,445,8080 -v\033[0m    \033[1;97m│\033[0m\n' "$t"
  printf '  \033[1;97m└─────────────────────────────────────────────────────────────────────┘\033[0m\n'
  printf '\n  \033[38;5;244mThree faces. Three option sets. Same fingerprinter.\033[0m\n\n'
}

# ─── INTRO ───────────────────────────────────────────────────────────────
banner ">>> THREE HOSTS · THREE OPTION SETS <<<" "Cowrie  ·  dd-honeypot stack  ·  silent-accept tarpit"
sleep "$PAUSE_TITLE"

# ─── SCENE 1: Cowrie, SSH-only, verbose, no deep ─────────────────────────
banner "SCENE 1 / 3  ·  COWRIE" "password-gated SSH · pre-auth KEX facade · -v · no --deep"
sleep "$PAUSE_SCENE"
CMD="honeypot-auditor --target $COWRIE --confirm-authorized -p 22 -v --timeout $TIMEOUT"
type_cmd "$CMD"
run_live --target "$COWRIE" --confirm-authorized -p 22 -v --timeout "$TIMEOUT" \
  --output /tmp/hpa-cowrie-demo.json
COWRIE_SCORE="$(python3 -c "import json;print(f\"{json.load(open('/tmp/hpa-cowrie-demo.json'))['score']:.0f}%\")" 2>/dev/null || echo "?")"
printf '\n  \033[38;5;244m▸ hold on the scoreboard — KEX facade is the Cowrie tell\033[0m\n'
sleep "$PAUSE_RESULT"

# ─── SCENE 2: dd stack, multi-port, deep, no -v ──────────────────────────
banner "SCENE 2 / 3  ·  DD-HONEYPOT STACK" "SSH + Werkzeug HTTP + MySQL · --deep · compact report (no -v)"
sleep "$PAUSE_SCENE"
CMD="honeypot-auditor --target $DD --confirm-authorized -p 22,80,3306 --deep --timeout $TIMEOUT"
type_cmd "$CMD"
run_background_then_show /tmp/hpa-dd-demo.json \
  --target "$DD" --confirm-authorized -p 22,80,3306 --deep --timeout "$TIMEOUT"
DD_SCORE="$(python3 -c "import json;print(f\"{json.load(open('/tmp/hpa-dd-demo.json'))['score']:.0f}%\")" 2>/dev/null || echo "?")"
printf '\n  \033[38;5;244m▸ deep adds stack/FSM tells — pause to read the verdict\033[0m\n'
sleep "$PAUSE_RESULT"

# ─── SCENE 3: tarpit, silent accepts, verbose, no deep ───────────────────
banner "SCENE 3 / 3  ·  SILENT-ACCEPT TARPIT" "HTTP/HTTPS/SMB/proxy faces that accept TCP then go quiet · -v"
sleep "$PAUSE_SCENE"
CMD="honeypot-auditor --target $TARPIT --confirm-authorized -p 80,443,445,8080 -v --timeout $TIMEOUT"
type_cmd "$CMD"
# Live -v but probes are slow: still run live so the user sees HIT lines; polish-cast will compress waits.
run_live --target "$TARPIT" --confirm-authorized -p 80,443,445,8080 -v --timeout "$TIMEOUT" \
  --output /tmp/hpa-tarpit-demo.json
TARPIT_SCORE="$(python3 -c "import json;print(f\"{json.load(open('/tmp/hpa-tarpit-demo.json'))['score']:.0f}%\")" 2>/dev/null || echo "?")"
printf '\n  \033[38;5;244m▸ silent-accept cluster + SMB timeout — review the HITs\033[0m\n'
sleep "$PAUSE_RESULT"

# ─── FINALE ──────────────────────────────────────────────────────────────
banner "TOUR COMPLETE" "same tool · different lenses · authorized lab only"
scoreboard "$COWRIE_SCORE" "$DD_SCORE" "$TARPIT_SCORE"
sleep 5
printf '  \033[1;32m✓\033[0m demo finished\n\n'
sleep 1.5
