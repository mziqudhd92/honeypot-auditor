# Contributing

Thanks for helping improve Honeypot Auditor.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[full,dev]"
pytest
```

## Pull requests

1. Fork and create a feature branch.
2. Add or update tests for behavior changes.
3. Run `pytest` and `ruff check src tests`.
4. Keep probes **non-destructive** — banner/state checks only.
5. Do not add exploit payloads or third-party honeypot product names in shipped strings (use neutral “low-interaction emulator” language).

## Commit messages

Use conventional prefixes: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.

## Scope

In scope: new protocol tells, clearer scoring, docs, optional intel providers with explicit opt-in.

Out of scope: unauthorized scanning features, auto-exploitation, removing the public-IP authorization gate.
