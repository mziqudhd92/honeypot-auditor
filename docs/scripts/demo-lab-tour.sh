#!/usr/bin/env bash
# Lab-tour demo: three authorized honeypot hosts, mixed CLI flags (-v / --deep).
# Designed for asciinema → polished cast → GIF (see docs/scripts/record-lab-tour-demo.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HPA="${HPA:-$ROOT/.venv/bin/honeypot-auditor}"
if [[ ! -x "$HPA" ]]; then
  HPA="$(command -v honeypot-auditor || true)"
fi
[[ -n "$HPA" && -x "$HPA" ]] || { echo "honeypot-auditor not found (venv or PATH)" >&2; exit 1; }

COWRIE="${COWRIE_TARGET:-127.0.0.1}"
DD="${DD_TARGET:-127.0.0.1}"
TARPIT="${TARPIT_TARGET:-127.0.0.1}"
# Port lists for local Docker demo-lab (override for remote authorized hosts).
COWRIE_PORTS="${COWRIE_PORTS:-28222}"
DD_PORTS="${DD_PORTS:-28223,28080,28306}"
TARPIT_PORTS="${TARPIT_PORTS:-29080,29445,28128}"
DD_PORT_MAP="${DD_PORT_MAP:-ssh=28223,http=28080,mysql=28306}"
TARPIT_PORT_MAP="${TARPIT_PORT_MAP:-http=29080,smb=29445,httpproxy=28128}"
VERSION="$("$HPA" --version 2>/dev/null | awk '{print $NF}' || echo "1.0.0")"

# Human-readable holds (must survive asciinema idle-time-limit + polish).
PAUSE_TITLE="${PAUSE_TITLE:-2.5}"
PAUSE_RESULT="${PAUSE_RESULT:-10}"
PAUSE_SCENE="${PAUSE_SCENE:-1.8}"
PAUSE_FINALE="${PAUSE_FINALE:-8}"
TIMEOUT="${DEMO_TIMEOUT:-5}"

export PYTHONUNBUFFERED=1
export PYTHONWARNINGS=ignore
export TERM="${TERM:-xterm-256color}"
export COLUMNS="${COLUMNS:-100}"
export LINES="${LINES:-32}"
export HPA_DEMO_VERSION="$VERSION"

clear_soft() {
  printf '\033[2J\033[H'
}

# Fixed-width box via Python so Unicode borders stay aligned in the GIF.
banner() {
  local title="$1"
  local sub="$2"
  clear_soft
  TITLE="$title" SUB="$sub" python3 - <<'PY'
import os

W = 66  # columns between the vertical borders


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
brand_r = "· lab tour · authorized only"
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
  # Sparse status updates so polish can shorten long probes without killing result holds.
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
  local -a args=("$@")
  "$HPA" "${args[@]}" || true
}

run_background_then_show() {
  local out="$1"
  shift
  local -a args=("$@")
  local label="deep audit in progress"
  "$HPA" "${args[@]}" --output "$out" >/tmp/hpa-lab-tour.log 2>/tmp/hpa-lab-tour.err &
  wait_probe $! "$label"
  python3 "$ROOT/docs/scripts/demo-print-result.py" "$out" "dd-honeypot stack (--deep)"
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
  COW="$c" DD="$d" TP="$t" python3 - <<'PY'
import os
W = 69
def clip(s, n):
    s = str(s)
    return s + " " * (n - len(s)) if len(s) <= n else s[: n - 1] + "…"

rows = [
    ("Cowrie", os.environ["COW"], f"-p {os.environ.get('COWRIE_PORTS','28222')} -v", "208"),
    ("dd-stack", os.environ["DD"], f"-p {os.environ.get('DD_PORTS','28223,28080,28306')} --deep", "39"),
    ("tarpit", os.environ["TP"], f"-p {os.environ.get('TARPIT_PORTS','29080,29445,28128')} -v", "201"),
]
top = "┌" + ("─" * W) + "┐"
bot = "└" + ("─" * W) + "┘"
title = clip(" LAB TOUR SCOREBOARD ", W)
print()
print(f"  \033[1;97m{top}\033[0m")
print(f"  \033[1;97m│{title}│\033[0m")
print(f"  \033[1;97m│{' ' * W}│\033[0m")
for name, score, flags, color in rows:
    left = f"  {name:<8}  {score:<8}  {flags}"
    left = clip(left, W)
    # re-color name inside padded line
    plain = f"  {name:<8}  {score:<8}  {flags}"
    plain = clip(plain, W)
    colored = plain.replace(
        f"{name:<8}",
        f"\033[38;5;{color}m{name:<8}\033[0m\033[1;97m",
        1,
    )
    print(f"  \033[1;97m│\033[0m\033[1;97m{colored}\033[0m\033[1;97m│\033[0m")
print(f"  \033[1;97m{bot}\033[0m")
print()
print("  \033[38;5;244mThree faces. Three option sets. Same fingerprinter.\033[0m")
print()
PY
}

# ─── INTRO ───────────────────────────────────────────────────────────────
banner ">>> THREE FACES · THREE OPTION SETS · v$VERSION <<<" "Cowrie  ·  OpenCanary / dd-stack  ·  silent-accept tarpit"
sleep "$PAUSE_TITLE"

# ─── SCENE 1: Cowrie, SSH-only, verbose, no deep ─────────────────────────
banner "SCENE 1 / 3  ·  COWRIE" "password-gated SSH · pre-auth KEX facade · -v · no --deep"
sleep "$PAUSE_SCENE"
CMD="honeypot-auditor --target $COWRIE --confirm-authorized -p $COWRIE_PORTS -v --timeout $TIMEOUT"
type_cmd "$CMD"
run_live --target "$COWRIE" --confirm-authorized -p "$COWRIE_PORTS" -v --timeout "$TIMEOUT" \
  --output /tmp/hpa-cowrie-demo.json
COWRIE_SCORE="$(python3 -c "import json;print(f\"{json.load(open('/tmp/hpa-cowrie-demo.json'))['score']:.0f}%\")" 2>/dev/null || echo "?")"
reading_pause "KEX facade is the Cowrie tell — review the scoreboard"

# ─── SCENE 2: dd stack, multi-port, deep, no -v ──────────────────────────
banner "SCENE 2 / 3  ·  DD-HONEYPOT / OPENCANARY" "SSH + HTTP + MySQL · --deep · compact report (no -v)"
sleep "$PAUSE_SCENE"
CMD="honeypot-auditor --target $DD --confirm-authorized -p $DD_PORTS --ports $DD_PORT_MAP --deep --timeout $TIMEOUT"
type_cmd "$CMD"
# Map OpenCanary host ports to protocol engines for a clean deep scan.
run_background_then_show /tmp/hpa-dd-demo.json \
  --target "$DD" --confirm-authorized -p "$DD_PORTS" \
  --ports "$DD_PORT_MAP" --deep --timeout "$TIMEOUT"
DD_SCORE="$(python3 -c "import json;print(f\"{json.load(open('/tmp/hpa-dd-demo.json'))['score']:.0f}%\")" 2>/dev/null || echo "?")"
reading_pause "deep stack/FSM tells — read the verdict and triggers"

# ─── SCENE 3: tarpit, silent accepts, verbose, no deep ───────────────────
banner "SCENE 3 / 3  ·  SILENT-ACCEPT TARPIT" "HTTP/HTTPS/SMB/proxy faces that accept TCP then go quiet · -v"
sleep "$PAUSE_SCENE"
CMD="honeypot-auditor --target $TARPIT --confirm-authorized -p $TARPIT_PORTS --ports $TARPIT_PORT_MAP -v --timeout $TIMEOUT"
type_cmd "$CMD"
run_live --target "$TARPIT" --confirm-authorized -p "$TARPIT_PORTS" \
  --ports "$TARPIT_PORT_MAP" -v --timeout "$TIMEOUT" \
  --output /tmp/hpa-tarpit-demo.json
TARPIT_SCORE="$(python3 -c "import json;print(f\"{json.load(open('/tmp/hpa-tarpit-demo.json'))['score']:.0f}%\")" 2>/dev/null || echo "?")"
reading_pause "silent-accept + SMB timeout — review the HIT lines"

# ─── FINALE ──────────────────────────────────────────────────────────────
export COWRIE_PORTS DD_PORTS TARPIT_PORTS
banner "TOUR COMPLETE · v$VERSION" "same tool · different lenses · authorized lab only"
scoreboard "$COWRIE_SCORE" "$DD_SCORE" "$TARPIT_SCORE"
printf '  \033[38;5;244m▸ reading pause — compare the three scores\033[0m\n'
sleep "$PAUSE_FINALE"
printf '  \033[1;32m✓\033[0m demo finished\n\n'
sleep 2
