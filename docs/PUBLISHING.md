# Publishing

Repository: **https://github.com/mziqudhd92/honeypot-auditor**

## Channels

| Channel | How |
|---------|-----|
| **PyPI** | Tag `vX.Y.Z` → `publish-pypi.yml` (Trusted Publishing) |
| **GHCR** | Tag `vX.Y.Z` → `publish-ghcr.yml` |
| **Snap Store** | Tag `vX.Y.Z` → `publish-snap.yml` (strict confinement → `candidate`) |
| **Launchpad PPA** | Tag `vX.Y.Z` → `publish-ppa.yml` (`ppa:ls1911/honeypot-auditor`, Noble) |
| GitHub Release | Notes only — does **not** re-upload to PyPI/Snap/PPA |

**Versions are not auto-bumped on push.** Bump `pyproject.toml` + `__init__.py`, update `CHANGELOG.md` and `debian/changelog`, tag `vX.Y.Z`, push the tag.

Tag must match `version` in `pyproject.toml`.

---

## PyPI

Goal: `pip install honeypot-auditor` from [PyPI](https://pypi.org/project/honeypot-auditor/).

### Trusted Publishing

1. [pypi.org](https://pypi.org/) → project **honeypot-auditor** → **Publishing** → add publisher:
   - Owner: `mziqudhd92`
   - Repository: `honeypot-auditor`
   - Workflow: **`publish-pypi.yml`** (not `publish.yml`)
   - Environment: `pypi`
2. GitHub → repo → **Settings** → **Environments** → ensure **`pypi`** exists
3. Tag and push:

   ```bash
   git tag -a v0.9.5 -m "v0.9.5"
   git push origin v0.9.5
   ```

### Manual upload

```bash
pip install build twine
python -m build
twine upload dist/*
```

### After publish

```bash
pip install -U honeypot-auditor
pip install "honeypot-auditor[full]"
honeypot-auditor --version
```

---

## Snap Store (strict)

Recipe: [`snap/snapcraft.yaml`](../snap/snapcraft.yaml) (`base: core24`, `confinement: strict`).

Install (once published):

```bash
sudo snap install honeypot-auditor --candidate
# later promote to stable in the store, then:
sudo snap install honeypot-auditor
honeypot-auditor --version
```

### One-time Snap Store setup

1. Register the name: https://snapcraft.io/account/register-snap  
   Name: **`honeypot-auditor`**
2. Export login credentials for CI (do this on a trusted machine):

   ```bash
   snapcraft export-login --snaps=honeypot-auditor \
     --channels=edge,beta,candidate,stable \
     --acls=package_access,package_push,package_update,package_release \
     snap-ci.login
   ```

3. GitHub → **Settings** → **Environments** → create **`snap`**
4. Add secret **`SNAPCRAFT_STORE_CREDENTIALS`** = full contents of `snap-ci.login`
5. Delete the local `snap-ci.login` file after storing the secret

Tagged releases publish to **`candidate`**. Promote to `stable` in the Snap Store UI or re-run **Publish Snap** with channel `stable`.

### Local snap build

```bash
sudo snap install snapcraft --classic
snapcraft   # from repo root; uses snap/snapcraft.yaml
sudo snap install ./honeypot-auditor_*.snap --dangerous
```

Strict confinement: outbound probes need the `network` plug (auto-connected). Optional nmap (`-n`) is limited in the snap; use PPA/pip for full nmap integration.

---

## Launchpad PPA (Ubuntu Noble)

Package metadata: [`debian/`](../debian/). Target: **`ppa:ls1911/honeypot-auditor`** on **Noble (24.04)**.

Install:

```bash
sudo add-apt-repository ppa:ls1911/honeypot-auditor
sudo apt update
sudo apt install honeypot-auditor
honeypot-auditor --version
```

### One-time Launchpad setup

1. Create the PPA: https://launchpad.net/~/+activate-ppa  
   Suggested name: **`honeypot-auditor`** → URL `ppa:ls1911/honeypot-auditor`
2. Enable **Noble** for the PPA
3. Create/upload a GPG key whose UID email Launchpad knows (e.g. `security@helloaeterna.com`):

   ```bash
   gpg --full-generate-key   # RSA 4096, email matching Launchpad
   gpg --armor --export-secret-keys KEYID > launchpad-secret.asc
   gpg --armor --export KEYID | # upload public key to Launchpad
   ```

   Launchpad → Account → **OpenPGP keys** → import the public key.

4. GitHub → **Settings** → **Environments** → create **`ppa`**
5. Secrets on that environment:
   - **`LAUNCHPAD_GPG_PRIVATE_KEY`** — full armored private key (`-----BEGIN PGP PRIVATE KEY BLOCK-----` …)
   - **`LAUNCHPAD_GPG_PASSPHRASE`** — passphrase (omit only if the key is unprotected)

### Local source package + upload

```bash
sudo apt install debhelper dh-python devscripts dput \
  python3-setuptools python3-rich python3-paramiko python3-requests python3-pyfiglet
# sync debian/changelog version with pyproject if needed
debuild -S -d
dput ppa:ls1911/honeypot-auditor ../honeypot-auditor_*_source.changes
```

Watch the build: https://launchpad.net/~ls1911/+archive/ubuntu/honeypot-auditor

`rich-argparse` is not in Ubuntu archives; the CLI falls back to stdlib argparse help. Install `[full]` extras via pip if you need Redis/SOCKS/Scapy helpers beyond Suggests.

---

## Release checklist

1. Bump `pyproject.toml` + `src/honeypot_auditor/__init__.py`
2. Update `CHANGELOG.md` and `debian/changelog` (same upstream version; native Debian package)
3. Keep `requirements-snap.txt` aligned with `[full]` extras if deps change
4. `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`
5. Confirm Actions: PyPI, GHCR, Snap (`candidate`), PPA upload
6. Create GitHub Release notes from the tag
7. After Snap bake time / PPA publish, smoke-test:

   ```bash
   snap install honeypot-auditor --candidate
   sudo apt install honeypot-auditor
   ```
