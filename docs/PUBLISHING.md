# Publishing to PyPI

Goal: `pip install honeypot-auditor` from [PyPI](https://pypi.org/project/honeypot-auditor/).

Repository: **https://github.com/mziqudhd92/honeypot-auditor**

## CI / release model

| Event | What runs |
|-------|-----------|
| Push / PR to `main` | Unit tests (3.10–3.14), ruff, coverage, build, security, golden |
| Push tag `vX.Y.Z` | **`publish-pypi.yml`** → PyPI (Trusted Publishing) + GHCR |
| GitHub Release `vX.Y.Z` | **`publish.yml`** → tests + version check only (does **not** upload to PyPI) |

**Versions are not auto-bumped on push.** Bump `pyproject.toml` + `__init__.py`, update `CHANGELOG.md`, tag `vX.Y.Z`, push the tag, then optionally create a GitHub Release for notes.

## Trusted Publishing (required for CI uploads)

1. [pypi.org](https://pypi.org/) → project **honeypot-auditor** → **Publishing** → add publisher:
   - Owner: `mziqudhd92`
   - Repository: `honeypot-auditor`
   - Workflow: **`publish-pypi.yml`** (not `publish.yml`)
   - Environment: `pypi`
2. GitHub → repo → **Settings** → **Environments** → ensure **`pypi`** exists
3. Tag and push (this is what publishes):

   ```bash
   git tag -a v0.7.3 -m "v0.7.3"
   git push origin v0.7.3
   ```

   Optionally create a GitHub Release from that tag for release notes — it will **not** re-upload to PyPI.

Tag must match `version` in `pyproject.toml`.

## Manual upload

```bash
pip install build twine
python -m build
twine upload dist/*
```

## After publish

```bash
pip install -U honeypot-auditor
pip install "honeypot-auditor[full]"
honeypot-auditor --version
```
