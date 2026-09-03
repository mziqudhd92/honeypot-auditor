# Contributing

Thanks for helping improve Honeypot Auditor.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[full,dev,security]"
make test          # fast unit tests (no coverage)
make test-cov      # branch coverage + HTML report
make lint          # Ruff checks and format verification
make security      # Semgrep, Bandit, dependencies, and secret history
```

On Windows PowerShell, activate with `.\.venv\Scripts\Activate.ps1` and run the commands
shown in the Makefile directly if `make` is unavailable. CI includes a native Windows job.

## Coverage

Configuration lives in `pyproject.toml` under `[tool.coverage.*]` (single source of truth).

| Command | Purpose |
|---------|---------|
| `make test` | Unit tests only (`pytest --no-cov`) |
| `make test-cov` | Full suite with branch coverage; opens `htmlcov/index.html` |
| `pytest --no-cov` | Same as `make test` |
| `pytest` | Coverage + terminal/XML/HTML reports; fails under **60%** |

CI runs a dedicated **coverage** job on Python 3.12 and uploads `coverage.xml` + `htmlcov/` as a workflow artifact (`coverage-report`). The version matrix runs `pytest --no-cov` for speed.

When changing probe or scoring logic, add or update tests and keep `make test-cov` green before opening a PR.

## Pull requests

1. Fork and create a feature branch.
2. Add or update tests for behavior changes.
3. Run `make test-cov`, `make lint` (Ruff plus mypy), and `make security`.
4. Keep probes **non-destructive** — banner/state checks only.
5. Do not add exploit payloads or third-party honeypot product names in shipped strings (use neutral “low-interaction emulator” language).
6. Prefer **small, focused PRs** (one theme: protocol probe · scoring/schema · CI/docs). Mega-PRs are hard to review.
7. Do **not** mix pure `ruff format` / import churn with behavior changes — land formatting as a separate `chore:` PR so `git blame` stays useful.

Security-tool suppressions must be line-scoped, identify the exact rule, and have an adjacent
reason explaining why the construct is necessary. Never add a repository-wide rule exclusion to
make a pull request pass. Synthetic secret fixtures must use an inline allowlist marker or an exact
historical fingerprint; real credentials must never enter the repository.

Required reviewers are listed in `.github/CODEOWNERS` (analyzer, probes, plugins, reporters, workflows).

## Commit messages

Use conventional prefixes: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.

## Scope

In scope: new protocol tells, clearer scoring, docs, optional intel providers with explicit opt-in.

Out of scope: unauthorized scanning features, auto-exploitation, removing the public-IP authorization gate.
