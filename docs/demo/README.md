# Demo recordings

asciinema casts + animated GIFs showing **pip install** from a clean Ubuntu 24.04
container and **separate deep audits** against the EC2 benchmark lab.

| File | Target | Honeypot | Result |
|------|--------|----------|--------|
| `honeypot-auditor-cowrie-demo.cast` / `.gif` | `54.84.251.249` | Cowrie SSH `:2222` (combined lab) | **58%** Suspected |
| `honeypot-auditor-dionaea-demo.cast` / `.gif` | `54.234.30.254` | Dionaea-only lab | **65%** Confirmed |

```bash
open docs/demo/honeypot-auditor-cowrie-demo.gif
open docs/demo/honeypot-auditor-dionaea-demo.gif
```

## Re-record

```bash
COWRIE_TARGET=54.84.251.249 DIONAEA_TARGET=54.234.30.254 bash scripts/record-demo.sh all
```

## Replay locally

```bash
asciinema play docs/demo/honeypot-auditor-cowrie-demo.cast
asciinema play docs/demo/honeypot-auditor-dionaea-demo.cast
```

## Re-record

Requires `asciinema`, `agg`, Docker, **nmap** (installed in-container via apt), and an authorized target:

```bash
TARGET=54.84.251.249 bash scripts/record-demo.sh cowrie
TARGET=54.84.251.249 bash scripts/record-demo.sh dionaea
TARGET=54.84.251.249 bash scripts/record-demo.sh all
```

Demos install `honeypot-auditor[full]` + **nmap**, run **deep** audits with NSE scripts enabled (no `--skip-nmap`), and print a plain-English result box (no Rich table noise).
