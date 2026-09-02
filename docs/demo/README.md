# Demo recordings

asciinema casts + animated GIFs for README / docs.

| File | What it shows | Notes |
|------|----------------|-------|
| `honeypot-auditor-lab-tour-demo.cast` / `.gif` | **3 lab hosts · mixed options** | Cowrie (`-p 22 -v`), dd-stack (`--deep`, no `-v`), tarpit (`-p 80,443,445,8080 -v`) |
| `honeypot-auditor-cowrie-demo.cast` / `.gif` | Pip-install + Cowrie deep (legacy EC2 lab) | Docker Ubuntu install path |
| `honeypot-auditor-dionaea-demo.cast` / `.gif` | Pip-install + Dionaea deep (legacy EC2 lab) | Docker Ubuntu install path |

```bash
open docs/demo/honeypot-auditor-lab-tour-demo.gif
open docs/demo/honeypot-auditor-cowrie-demo.gif
open docs/demo/honeypot-auditor-dionaea-demo.gif
```

## Lab-tour demo (recommended)

Records live audits against the three authorized lab IPs, then **polishes** the
cast so long probes (deep / silent-accept) do not force wall-clock waits, while
**holding** on scoreboards long enough to read:

```bash
bash scripts/record-lab-tour-demo.sh
```

Optional overrides:

```bash
COWRIE_TARGET=54.237.202.94 \
DD_TARGET=54.204.78.207 \
TARPIT_TARGET=13.218.137.93 \
PAUSE_RESULT=6.5 \
DEMO_TIMEOUT=5 \
bash scripts/record-lab-tour-demo.sh
```

Pipeline: `demo-lab-tour.sh` → asciinema `.raw.cast` → `polish-demo-cast.py` →
`.cast` → `agg` → `.gif` (+ optional `gifsicle`).

## Legacy single-host demos

```bash
COWRIE_TARGET=54.84.251.249 DIONAEA_TARGET=54.234.30.254 bash scripts/record-demo.sh all
```

Requires `asciinema`, `agg`, Docker, **nmap** (installed in-container via apt).

## Replay locally

```bash
asciinema play docs/demo/honeypot-auditor-lab-tour-demo.cast
asciinema play docs/demo/honeypot-auditor-cowrie-demo.cast
asciinema play docs/demo/honeypot-auditor-dionaea-demo.cast
```
