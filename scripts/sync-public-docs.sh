#!/usr/bin/env bash
# Fail CI when README/Pages CLI flag tables drift from --help output.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -x "$ROOT/.venv/bin/honeypot-auditor" ]; then
  HPA="$ROOT/.venv/bin/honeypot-auditor"
elif command -v honeypot-auditor >/dev/null 2>&1; then
  HPA="honeypot-auditor"
elif [ -x "$ROOT/.venv/bin/python" ]; then
  HPA="$ROOT/.venv/bin/python -m honeypot_auditor.cli"
else
  HPA="python -m honeypot_auditor.cli"
fi
HELP="$($HPA --help)"
missing=0

grep_flag() {
  local haystack="$1"
  local needle="$2"
  printf '%s' "$haystack" | grep -Fq -- "$needle"
}

grep_file() {
  local file="$1"
  local needle="$2"
  grep -Fq -- "$needle" "$file"
}

for flag in --safe-mode --passive-first --osint-only --passive-first-confirm --dual-stack --profile --jitter --jitter-ms --max-concurrent --seed --preset --format --intel-provider --intel-key; do
  if ! grep_flag "$HELP" "$flag"; then
    echo "missing from --help: $flag" >&2
    missing=1
  fi
done
if ! grep_file "$ROOT/README.md" "check-sig"; then
  echo "missing from README.md: check-sig" >&2
  missing=1
fi
if ! grep_file "$ROOT/docs/index.html" "check-sig"; then
  echo "missing from docs/index.html: check-sig" >&2
  missing=1
fi

for doc in README.md docs/index.html; do
  for needle in --safe-mode --passive-first --osint-only --passive-first-confirm --dual-stack --jitter --intel-provider sarif deception-audit; do
    if ! grep_file "$ROOT/$doc" "$needle"; then
      echo "missing from $doc: $needle" >&2
      missing=1
    fi
  done
done
exit "$missing"
