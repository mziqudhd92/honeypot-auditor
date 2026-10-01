# Demo recordings

asciinema casts + animated GIFs for README / docs. Recorded against
**honeypot-auditor 1.0.0** with the local Docker lab in
`docs/demo/lab/docker-compose.yml` (localhost-only ports).

| File | What it shows | Notes |
|------|----------------|-------|
| `honeypot-auditor-lab-tour-v1.0.0.cast` / `.gif` | **3 faces · mixed options · v1.0.0** | Cowrie (`-p` SSH `-v`), OpenCanary / dd-stack (`--deep`), silent-accept tarpit (`-v`) |
| `honeypot-auditor-cowrie-demo.cast` / `.gif` | Pip-install + Cowrie deep | Ubuntu container install path → local Cowrie |
| `honeypot-auditor-dionaea-demo.cast` / `.gif` | Pip-install + Dionaea deep | Ubuntu container install path → local Dionaea |
| `honeypot-auditor-dd-honeypot-demo.cast` / `.gif` → `docs/tutorials/dd-honeypot-lab-demo/` | **Thales dd-honeypot (DataTrap) · 5 services · v1.0.3** | SSH **2222** + Telnet + MySQL + Redis + PostgreSQL (`-p` + full `--ports` map, `-v`, then `--deep`) · Honeyscore 100% · beginner lab (Dockerfile, configs, tutorial) lives with the media |

```bash
open docs/demo/honeypot-auditor-lab-tour-v1.0.0.gif
open docs/demo/honeypot-auditor-cowrie-demo.gif
open docs/demo/honeypot-auditor-dionaea-demo.gif
open docs/tutorials/dd-honeypot-lab-demo/honeypot-auditor-dd-honeypot-demo.gif
```

Still frames from the lab-tour GIF (for articles / Medium):
[`screenshots/`](./screenshots/) — regenerate with `python3 docs/demo/screenshots/extract_from_gif.py`.

## Prerequisites

```bash
# Start local demo targets (Cowrie, OpenCanary, Dionaea, tarpit)
docker compose -f docs/demo/lab/docker-compose.yml up -d

# Tooling
brew install asciinema agg gifsicle   # gifsicle optional
# honeypot-auditor 1.0.0 in .venv
```

## Lab-tour demo (recommended)

Records live audits against the local demo stack, then **polishes** the cast so
long probes do not force wall-clock waits, while **holding** on scoreboards long
enough to read:

```bash
bash docs/scripts/record-lab-tour-demo.sh
```

Optional overrides (defaults are localhost high ports from the compose file):

```bash
COWRIE_TARGET=127.0.0.1 COWRIE_PORTS=28222 \
DD_TARGET=127.0.0.1 DD_PORTS=28223,28080,28306 \
TARPIT_TARGET=127.0.0.1 TARPIT_PORTS=29080,29445,28128 \
PAUSE_RESULT=6.5 DEMO_TIMEOUT=6 \
bash docs/scripts/record-lab-tour-demo.sh
```

Pipeline: `demo-lab-tour.sh` → asciinema `.raw.cast` → `polish-demo-cast.py` →
`.cast` → `agg` → `.gif` (+ optional `gifsicle`).

## Single-host demos (Cowrie / Dionaea)

```bash
docker compose -f docs/demo/lab/docker-compose.yml up -d cowrie dionaea
bash docs/scripts/record-demo.sh all
```

Requires `asciinema`, `agg`, Docker, **nmap** (installed in-container via apt).

## Replay locally

```bash
asciinema play docs/demo/honeypot-auditor-lab-tour-v1.0.0.cast
asciinema play docs/demo/honeypot-auditor-cowrie-demo.cast
asciinema play docs/demo/honeypot-auditor-dionaea-demo.cast
asciinema play docs/tutorials/dd-honeypot-lab-demo/honeypot-auditor-dd-honeypot-demo.cast
```

## dd-honeypot (DataTrap) demo

Target: the beginner lab in `docs/tutorials/dd-honeypot-lab-demo/` (tutorial +
Dockerfile + configs) — the official `ghcr.io/thalesgroup/dd-honeypot` image with
five configured services (SSH **2222**, Telnet 23, MySQL 3306, Redis 6380, PostgreSQL
5433, all bound to 127.0.0.1). Follow [`TUTORIAL.md`](../tutorials/dd-honeypot-lab-demo/TUTORIAL.md)
to build and run the lab, then replay the bundled recording:

```bash
asciinema play docs/tutorials/dd-honeypot-lab-demo/honeypot-auditor-dd-honeypot-demo.cast
open docs/tutorials/dd-honeypot-lab-demo/honeypot-auditor-dd-honeypot-demo.gif
```

Scenes: proof-of-life (banner + PING), basic `-v` audit, `--deep` audit with verdict
summary and per-protocol scoreboard (Honeyscore 100%).

