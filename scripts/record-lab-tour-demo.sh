#!/usr/bin/env bash
# Record + polish + render the multi-host lab-tour demo GIF.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/demo}"
NAME="${NAME:-lab-tour}"
CAST_RAW="$OUT_DIR/honeypot-auditor-${NAME}-demo.raw.cast"
CAST="$OUT_DIR/honeypot-auditor-${NAME}-demo.cast"
GIF="$OUT_DIR/honeypot-auditor-${NAME}-demo.gif"

COWRIE_TARGET="${COWRIE_TARGET:-54.237.202.94}"
DD_TARGET="${DD_TARGET:-54.204.78.207}"
TARPIT_TARGET="${TARPIT_TARGET:-13.218.137.93}"

mkdir -p "$OUT_DIR"

command -v asciinema >/dev/null || { echo "install asciinema: brew install asciinema" >&2; exit 1; }
command -v agg >/dev/null || { echo "install agg: brew install agg" >&2; exit 1; }

export COWRIE_TARGET DD_TARGET TARPIT_TARGET
export HPA="${HPA:-$ROOT/.venv/bin/honeypot-auditor}"
export COLUMNS=100 LINES=32
export PAUSE_TITLE="${PAUSE_TITLE:-2.0}"
export PAUSE_RESULT="${PAUSE_RESULT:-6.5}"
export PAUSE_SCENE="${PAUSE_SCENE:-1.2}"
export DEMO_TIMEOUT="${DEMO_TIMEOUT:-5}"

echo "==> Recording lab-tour demo"
echo "    Cowrie  $COWRIE_TARGET"
echo "    dd      $DD_TARGET"
echo "    tarpit  $TARPIT_TARGET"
echo "    raw:    $CAST_RAW"

# Soft idle limit while recording; polish-demo-cast.py does the aggressive cut.
asciinema rec \
  --overwrite \
  --idle-time-limit 2.5 \
  --cols 100 \
  --rows 32 \
  --title "honeypot-auditor lab tour (3 hosts · mixed options)" \
  --command "bash $ROOT/scripts/demo-lab-tour.sh" \
  "$CAST_RAW"

echo "==> Polishing cast (compress waits, hold results)…"
python3 "$ROOT/scripts/polish-demo-cast.py" \
  --max-idle 0.28 \
  --progress-idle 0.08 \
  --result-hold 2.4 \
  "$CAST_RAW" "$CAST"

echo "==> Rendering GIF…"
agg \
  --font-size 15 \
  --line-height 1.25 \
  --theme monokai \
  --speed 1.25 \
  --idle-time-limit 0.28 \
  --fps-cap 18 \
  "$CAST" "$GIF"

if command -v gifsicle >/dev/null; then
  echo "==> Optimizing GIF…"
  gifsicle -O3 --colors 256 -o "$GIF.tmp" "$GIF" && mv "$GIF.tmp" "$GIF"
fi

echo ""
echo "Artifacts:"
echo "  $CAST"
echo "  $GIF"
ls -lh "$CAST" "$GIF"
