# Publishing to PyPI

Goal: `pip install honeypot-auditor` from [PyPI](https://pypi.org/project/honeypot-auditor/).

Repository: **https://github.com/mziqudhd92/honeypot-auditor**

## CI / release model

| Event | What runs |
|-------|-----------|
| Push / PR to `main` | Unit tests (3.10–3.14), ruff, dedicated coverage job ≥60%, build |
| Push to `main` | + Cowrie Docker integration audit |
| GitHub Release `vX.Y.Z` | Tests → PyPI publish (Trusted Publishing) |

**Versions are not auto-bumped on push.** Bump `pyproject.toml` + `__init__.py`, update `CHANGELOG.md`, tag `vX.Y.Z`, publish release.

## Trusted Publishing (recommended)

1. [pypi.org](https://pypi.org/) → **Publishing** → **Add a new pending publisher**
   - Project: `honeypot-auditor`
   - Owner: `mziqudhd92`
   - Repository: `honeypot-auditor`
   - Workflow: `publish.yml`
   - Environment: `pypi`
2. GitHub → repo → **Settings** → **Environments** → create **`pypi`**
3. Tag and release:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

   GitHub → **Releases** → publish release for `v0.2.0`

Tag must match `version` in `pyproject.toml` (CI enforces this).

## Manual upload

```bash
pip install build twine
python -m build
twine upload dist/*
```

## After publish

```bash
pip install honeypot-auditor
pip install "honeypot-auditor[full]"
honeypot-auditor --version
```
