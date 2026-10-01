#!/usr/bin/env bash
# Record + polish + render the dd-honeypot (DataTrap) demo cast and GIF.
# Mirrors honeypot-auditor's docs/scripts/record-lab-tour-demo.sh pipeline.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="$(dirname "$HERE")"
# Repo root when the lab lives in honeypot-auditor/docs/tutorials/dd-honeypot-lab-demo;
# falls back to a sibling checkout for standalone use.
if [[ -z "${AUDITOR_ROOT:-}" ]]; then
  AUDITOR_ROOT="$(git -C "$LAB" rev-parse --show-toplevel 2>/dev/null || true)"
  [[ -n "$AUDITOR_ROOT" ]] || AUDITOR_ROOT="$(cd "$LAB/../../honeypot-auditor" && pwd)"
fi
POLISH="$AUDITOR_ROOT/docs/scripts/polish-demo-cast.py"

OUT_DIR="${OUT_DIR:-$LAB}"
NAME="${NAME:-dd-honeypot-demo}"
CAST_RAW="$OUT_DIR/honeypot-auditor-${NAME}.raw.cast"
CAST="$OUT_DIR/honeypot-auditor-${NAME}.cast"
GIF="$OUT_DIR/honeypot-auditor-${NAME}.gif"

command -v asciinema >/dev/null || { echo "install asciinema: brew install asciinema" >&2; exit 1; }
command -v agg >/dev/null || { echo "install agg: brew install agg" >&2; exit 1; }
[[ -f "$POLISH" ]] || { echo "polish script not found: $POLISH" >&2; exit 1; }

# Idle limit must exceed the reading pauses or they vanish.
asciinema rec \
  --overwrite \
  --idle-time-limit 12 \
  --cols 100 \
  --rows 32 \
  --title "honeypot-auditor × dd-honeypot (DataTrap) — 5 services, authorized lab" \
  --command "bash $HERE/dd-honeypot-demo.sh" \
  "$CAST_RAW"

echo "==> Polishing cast (compress probes, keep reading pauses)…"
python3 "$POLISH" \
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
echo ""
echo "Replay:  asciinema play $CAST"
