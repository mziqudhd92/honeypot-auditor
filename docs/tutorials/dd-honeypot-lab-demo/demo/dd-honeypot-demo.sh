#!/usr/bin/env bash
# dd-honeypot (DataTrap) demo: five authorized honeypot services in local Docker.
# Scene script for asciinema → polished cast → GIF
# (pipeline: demo/record-dd-demo.sh, style follows docs/scripts/demo-lab-tour.sh).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Repo root when the lab lives in honeypot-auditor/docs/tutorials/dd-honeypot-lab-demo;
# falls back to a sibling checkout for standalone use.
if [[ -z "${AUDITOR_ROOT:-}" ]]; then
  AUDITOR_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"
  [[ -n "$AUDITOR_ROOT" ]] || AUDITOR_ROOT="$(cd "$SCRIPT_DIR/../../honeypot-auditor" && pwd)"
fi
HPA="${HPA:-$AUDITOR_ROOT/.venv/bin/honeypot-auditor}"
[[ -x "$HPA" ]] || HPA="$(command -v honeypot-auditor)"
[[ -n "$HPA" && -x "$HPA" ]] || { echo "honeypot-auditor not found (venv or PATH)" >&2; exit 1; }

T="${DD_TARGET:-127.0.0.1}"
PORTS="${DD_PORTS:-22,23,3306,6380,5433}"
PORT_MAP="${DD_PORT_MAP:-ssh=22,telnet=23,mysql=3306,redis=6380,postgres=5433}"
VERSION="$("$HPA" --version 2>/dev/null | awk '{print $NF}' || echo "1.0.0")"

# Human-readable holds (must survive asciinema idle-time-limit + polish).
PAUSE_TITLE="${PAUSE_TITLE:-2.5}"
PAUSE_RESULT="${PAUSE_RESULT:-10}"
PAUSE_SCENE="${PAUSE_SCENE:-1.8}"
PAUSE_FINALE="${PAUSE_FINALE:-8}"

export PYTHONUNBUFFERED=1
export PYTHONWARNINGS=ignore
# Force 256-color even when the caller's TERM is dumb/unset (Rich needs it).
export TERM="xterm-256color"
export COLUMNS="${COLUMNS:-100}"
export LINES="${LINES:-32}"
export HPA_DEMO_VERSION="$VERSION"

clear_soft() { printf '\033[2J\033[H'; }

# Fixed-width box via Python so Unicode borders stay aligned in the GIF.
banner() {
  local title="$1"
  local sub="$2"
  clear_soft
  TITLE="$title" SUB="$sub" python3 - <<'PY'
import os

W = 66


def clip(s: str, width: int) -> str:
    s = s.replace("\t", " ")
    if len(s) <= width:
        return s + (" " * (width - len(s)))
    if width <= 1:
        return s[:width]
    return s[: width - 1] + "…"


title = clip(os.environ.get("TITLE", ""), W - 2)
sub = clip(os.environ.get("SUB", ""), W - 2)
ver = os.environ.get("HPA_DEMO_VERSION", "1.0.0")
brand_l = f"HONEYPOT-AUDITOR  v{ver}"
brand_r = "· dd-honeypot lab · authorized only"
gap = W - 2 - len(brand_l) - len(brand_r)
if gap < 1:
    brand_r = clip(brand_r, max(8, W - 2 - len(brand_l) - 1)).rstrip()
    gap = max(1, W - 2 - len(brand_l) - len(brand_r))
pad_end = W - (2 + len(brand_l) + gap + len(brand_r))
brand = (
    f"  \033[1;97m{brand_l}\033[0m"
    + (" " * gap)
    + f"\033[38;5;244m{brand_r}\033[0m"
    + (" " * max(0, pad_end))
)

top = "╔" + ("═" * W) + "╗"
mid = "╠" + ("═" * W) + "╣"
bot = "╚" + ("═" * W) + "╝"
g, r, y, d = "\033[38;5;46m", "\033[0m", "\033[1;93m", "\033[38;5;250m"
print()
print(f"  {g}{top}{r}")
print(f"  {g}║{r}{brand}{g}║{r}")
print(f"  {g}{mid}{r}")
print(f"  {g}║{r}  {y}{title}{r}{g}║{r}")
print(f"  {g}║{r}  {d}{sub}{r}{g}║{r}")
print(f"  {g}{bot}{r}")
print()
PY
}

reading_pause() {
  local note="$1"
  # Marker line for polish-demo-cast.py — do not compress the following idle.
  printf '\n  \033[38;5;244m▸ reading pause — %s\033[0m\n' "$note"
  sleep "$PAUSE_RESULT"
}

type_cmd() {
  local cmd="$1"
  printf '  \033[38;5;244m$\033[0m '
  local i
  for ((i = 0; i < ${#cmd}; i++)); do
    printf '%s' "${cmd:i:1}"
    sleep 0.018
  done
  printf '\n\n'
  sleep 0.4
}

wait_probe() {
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

# ─── INTRO ───────────────────────────────────────────────────────────────
banner ">>> THALES DD-HONEYPOT (DATATRAP) · 5 SERVICES <<<" "SSH · Telnet · MySQL · Redis · PostgreSQL — all in one Docker box"
sleep "$PAUSE_TITLE"

# ─── SCENE 1: proof of life ──────────────────────────────────────────────
banner "SCENE 1 / 3  ·  THE TARGET IS ALIVE" "local Docker honeypot · ports 22 23 3306 6380 5433 · 127.0.0.1 only"
sleep "$PAUSE_SCENE"
type_cmd "docker ps --filter name=dd-honeypot-lab --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
docker ps --filter name=dd-honeypot-lab --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
sleep 1
printf '  \033[38;5;244m$\033[0m (printf \x27PING\\r\\n\x27; sleep 1) | nc -w 2 127.0.0.1 6380\n\n'
(printf 'PING\r\n'; sleep 1) | nc -w 2 127.0.0.1 6380 || true
printf '\n  \033[38;5;244m$\033[0m nc -w 2 127.0.0.1 22 </dev/null | head -c 22\n\n'
nc -w 2 127.0.0.1 22 </dev/null | head -c 22 || true
printf '\n\n'
reading_pause "SSH banner + Redis PONG — a live multi-service decoy"

# ─── SCENE 2: basic audit, verbose, live ─────────────────────────────────
banner "SCENE 2 / 3  ·  BASIC AUDIT (-v)" "five protocol faces · weighted Honeyscore · no --deep"
sleep "$PAUSE_SCENE"
CMD="honeypot-auditor --target $T -p $PORTS --ports $PORT_MAP --output /tmp/hpa-dd-basic.json -v"
type_cmd "$CMD"
"$HPA" --target "$T" -p "$PORTS" --ports "$PORT_MAP" --output /tmp/hpa-dd-basic.json -v || true
BASIC_SCORE="$(python3 -c "import json;print(f\"{json.load(open('/tmp/hpa-dd-basic.json'))['score']:.0f}%\")" 2>/dev/null || echo "?")"
reading_pause "arbitrary auth + co-tenancy — review the strategy table"

# ─── SCENE 3: deep audit, background + summary ───────────────────────────
banner "SCENE 3 / 3  ·  DEEP AUDIT" "shell semantics · auth curve · FSM fuzz · co-tenancy · --deep"
sleep "$PAUSE_SCENE"
CMD="honeypot-auditor --target $T -p $PORTS --ports $PORT_MAP --deep --output /tmp/hpa-dd-deep.json"
type_cmd "$CMD"
(
  "$HPA" --target "$T" -p "$PORTS" --ports "$PORT_MAP" --deep \
    --output /tmp/hpa-dd-deep.json >/tmp/hpa-dd-deep.log 2>/tmp/hpa-dd-deep.err
) &
wait_probe $! "deep audit in progress"
DEEP_SCORE="$(python3 -c "import json;print(f\"{json.load(open('/tmp/hpa-dd-deep.json'))['score']:.0f}%\")" 2>/dev/null || echo "?")"
python3 - <<PY
import json
r = json.load(open("/tmp/hpa-dd-deep.json"))
print()
print(f"  Verdict    : {r.get('threat_level','?')}")
print(f"  Score      : {float(r.get('score',0)):.0f}%")
print(f"  Confidence : {r.get('confidence','?')}")
print(f"  Tactical   : {r.get('tactical_action','?')}")
hits = [i for i in r.get('indicators', []) if i.get('triggered')]
print(f"  Triggers   : {len(hits)}")
for i in hits[:9]:
    print(f"    • {i.get('id')} — {(i.get('detail') or '')[:64]}")
if len(hits) > 9:
    print(f"    … +{len(hits)-9} more")
print()
PY
reading_pause "deep tells corroborate the basic audit — read the scoreboard"

# ─── FINALE ──────────────────────────────────────────────────────────────
banner "TOUR COMPLETE · v$VERSION" "dd-honeypot detected on every protocol face"
python3 - <<PY
import json

W = 69


def clip(s, n):
    s = str(s)
    return s + " " * (n - len(s)) if len(s) <= n else s[: n - 1] + "…"


r = json.load(open("/tmp/hpa-dd-deep.json"))
counts = []
colors = {"ssh": "39", "telnet": "201", "mysql": "208", "redis": "196", "postgres": "51"}
for p in r.get("protocol_strategies", []):
    proto = p.get("protocol", "?")
    res = [v.get("status") for v in p.values() if isinstance(v, dict) and "status" in v]
    hits = sum(1 for s in res if s == "hit")
    total = sum(1 for s in res if s in ("hit", "clean"))
    if total:
        counts.append((proto, f"{hits}/{total}", colors.get(proto, "250")))

rows = [(n.upper(), c, "strategies fired", col) for n, c, col in counts]
top = "┌" + ("─" * W) + "┐"
bot = "└" + ("─" * W) + "┘"
title = clip(" DD-HONEYPOT SCOREBOARD ", W)
print()
print(f"  \033[1;97m{top}\033[0m")
print(f"  \033[1;97m│{title}│\033[0m")
print(f"  \033[1;97m│{' ' * W}│\033[0m")
for name, hits, _flag, color in rows:
    plain = clip(f"  {name:<11}  {hits:<6}  strategies fired", W)
    colored = plain.replace(name, f"\033[38;5;{color}m{name}\033[0m\033[1;97m", 1)
    print(f"  \033[1;97m│\033[0m\033[1;97m{colored}\033[0m\033[1;97m│\033[0m")
left = clip(f"  {'HONEYSCORE':<11}  {float(r.get('score',0)):.0f}%     →  {r.get('threat_level','?')}", W)
verdict_colored = left.replace(r.get("threat_level", "?"), f"\033[1;93m{r.get('threat_level','?')}\033[0m\033[1;97m", 1)
print(f"  \033[1;97m│\033[0m\033[1;97m{verdict_colored}\033[0m\033[1;97m│\033[0m")
print(f"  \033[1;97m{bot}\033[0m")
print()
print("  \033[38;5;244mSame fingerprinter as the Cowrie / OpenCanary demos — different decoy.\033[0m")
print()
PY
printf '  \033[38;5;244m▸ reading pause — compare the protocol faces\033[0m\n'
sleep "$PAUSE_FINALE"
printf '  \033[1;32m✓\033[0m demo finished — honeypot-auditor %s × dd-honeypot (DataTrap)\n\n' "$VERSION"
sleep 2
