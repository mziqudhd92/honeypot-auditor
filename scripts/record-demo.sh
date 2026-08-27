#!/usr/bin/env bash
# Record asciinema casts + GIFs: Cowrie @ combined lab, Dionaea @ dedicated lab.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/docs/demo}"

COWRIE_TARGET="${COWRIE_TARGET:-54.84.251.249}"
DIONAEA_TARGET="${DIONAEA_TARGET:-54.234.30.254}"

mkdir -p "$OUT_DIR"

command -v asciinema >/dev/null || { echo "install asciinema: brew install asciinema" >&2; exit 1; }
command -v agg >/dev/null || { echo "install agg: brew install agg" >&2; exit 1; }

record_one() {
  local name="$1"
  local script="$2"
  local target="$3"
  local cast="$OUT_DIR/honeypot-auditor-${name}-demo.cast"
  local gif="$OUT_DIR/honeypot-auditor-${name}-demo.gif"

  echo ""
  echo "==> Recording $name demo (target=$target)"
  echo "    cast: $cast"
  export TARGET="$target" PAUSE_SEC=1
  asciinema rec \
    --overwrite \
    --idle-time-limit 3 \
    --title "honeypot-auditor: $name audit ($target)" \
    --command "bash $script" \
    "$cast"

  echo "==> Rendering GIF for $name ..."
  agg --font-size 16 --line-height 1.3 --theme monokai "$cast" "$gif"
  echo "    gif:  $gif"
}

case "${1:-all}" in
  cowrie)
    record_one cowrie "$ROOT/scripts/demo-cowrie.sh" "$COWRIE_TARGET"
    ;;
  dionaea)
    record_one dionaea "$ROOT/scripts/demo-dionaea.sh" "$DIONAEA_TARGET"
    ;;
  all)
    record_one cowrie "$ROOT/scripts/demo-cowrie.sh" "$COWRIE_TARGET"
    record_one dionaea "$ROOT/scripts/demo-dionaea.sh" "$DIONAEA_TARGET"
    ;;
  *)
    echo "usage: $0 [cowrie|dionaea|all]" >&2
    exit 1
    ;;
esac

echo ""
echo "Artifacts in $OUT_DIR:"
echo "  honeypot-auditor-cowrie-demo.gif   (target $COWRIE_TARGET)"
echo "  honeypot-auditor-dionaea-demo.gif  (target $DIONAEA_TARGET)"
