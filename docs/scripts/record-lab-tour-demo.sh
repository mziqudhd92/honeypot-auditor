#!/usr/bin/env bash
# Record + polish + render the multi-host lab-tour demo GIF.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/demo}"
NAME="${NAME:-lab-tour}"
CAST_RAW="$OUT_DIR/honeypot-auditor-${NAME}-demo.raw.cast"
CAST="$OUT_DIR/honeypot-auditor-${NAME}-demo.cast"
GIF="$OUT_DIR/honeypot-auditor-${NAME}-demo.gif"

COWRIE_TARGET="${COWRIE_TARGET:-127.0.0.1}"
DD_TARGET="${DD_TARGET:-127.0.0.1}"
TARPIT_TARGET="${TARPIT_TARGET:-127.0.0.1}"
COWRIE_PORTS="${COWRIE_PORTS:-28222}"
DD_PORTS="${DD_PORTS:-28223,28080,28306}"
TARPIT_PORTS="${TARPIT_PORTS:-29080,29445,28128}"
DD_PORT_MAP="${DD_PORT_MAP:-ssh=28223,http=28080,mysql=28306}"
TARPIT_PORT_MAP="${TARPIT_PORT_MAP:-http=29080,smb=29445,httpproxy=28128}"

mkdir -p "$OUT_DIR"

command -v asciinema >/dev/null || { echo "install asciinema: brew install asciinema" >&2; exit 1; }
command -v agg >/dev/null || { echo "install agg: brew install agg" >&2; exit 1; }

export COWRIE_TARGET DD_TARGET TARPIT_TARGET COWRIE_PORTS DD_PORTS TARPIT_PORTS DD_PORT_MAP TARPIT_PORT_MAP
export HPA="${HPA:-$ROOT/.venv/bin/honeypot-auditor}"
export COLUMNS=100 LINES=32
# Keep these >= polish --reading-hold so asciinema does not crush pauses first.
export PAUSE_TITLE="${PAUSE_TITLE:-2.5}"
export PAUSE_RESULT="${PAUSE_RESULT:-10}"
export PAUSE_SCENE="${PAUSE_SCENE:-1.8}"
export PAUSE_FINALE="${PAUSE_FINALE:-8}"
export DEMO_TIMEOUT="${DEMO_TIMEOUT:-5}"

HPA_VER="$("$HPA" --version 2>/dev/null | awk '{print $NF}' || echo "1.0.0")"

echo "==> Recording lab-tour demo (honeypot-auditor $HPA_VER)"
echo "    Cowrie  $COWRIE_TARGET:$COWRIE_PORTS"
echo "    dd      $DD_TARGET:$DD_PORTS"
echo "    tarpit  $TARPIT_TARGET:$TARPIT_PORTS"
echo "    raw:    $CAST_RAW"
echo "    result pause=${PAUSE_RESULT}s  (asciinema idle limit must be higher)"

# Idle limit must exceed PAUSE_RESULT / PAUSE_FINALE or reading pauses vanish.
asciinema rec \
  --overwrite \
  --idle-time-limit 12 \
  --cols 100 \
  --rows 32 \
  --title "honeypot-auditor $HPA_VER lab tour (Cowrie · OpenCanary · tarpit)" \
  --command "bash $ROOT/docs/scripts/demo-lab-tour.sh" \
  "$CAST_RAW"

echo "==> Polishing cast (compress probes, keep reading pauses)…"
python3 "$ROOT/docs/scripts/polish-demo-cast.py" \
  --max-idle 0.55 \
  --progress-idle 0.12 \
  --reading-hold 9.0 \
  "$CAST_RAW" "$CAST"

echo "==> Rendering GIF (realtime — no speedup)…"
agg \
  --font-size 15 \
  --line-height 1.25 \
  --theme monokai \
  --speed 1.0 \
  --idle-time-limit 10 \
  --fps-cap 20 \
  "$CAST" "$GIF"

if command -v gifsicle >/dev/null; then
  echo "==> Optimizing GIF…"
  gifsicle -O3 --colors 256 -o "$GIF.tmp" "$GIF" && mv "$GIF.tmp" "$GIF"
fi

rm -f "$CAST_RAW"

echo ""
echo "Artifacts:"
echo "  $CAST"
echo "  $GIF"
ls -lh "$CAST" "$GIF"
