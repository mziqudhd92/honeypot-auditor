# Beginner Tutorial: Detect a Local Honeypot with honeypot-auditor

In this tutorial you will:

1. Install **honeypot-auditor** — a CLI that fingerprints whether a target behaves like a honeypot
2. Install and run **dd-honeypot (DataTrap)** — an open-source honeypot by ThalesGroup — in Docker,
   with **SSH, Telnet, MySQL, Redis and PostgreSQL** enabled
3. Point the auditor at it and watch it detect the honeypot with a **Honeyscore of 100% — "Confirmed Honeypot"**

Everything runs on your own machine (`127.0.0.1`), so this is a fully authorized lab exercise.

```
 .───────────────────────────────────────────────────────────────.
 │  you (honeypot-auditor) ──probes──▶ Docker ▶ dd-honeypot      │
 │                                       22, 23, 3306, 6380, 5433│
 '───────────────────────────────────────────────────────────────'
```

**Time needed:** ~15 minutes · **Difficulty:** beginner

**Rather watch?** A recorded demo lives next to this tutorial:

- [`honeypot-auditor-dd-honeypot-demo.gif`](honeypot-auditor-dd-honeypot-demo.gif) — animated GIF, plays anywhere
- [`honeypot-auditor-dd-honeypot-demo.cast`](honeypot-auditor-dd-honeypot-demo.cast) — asciinema cast, replay in your terminal with `asciinema play honeypot-auditor-dd-honeypot-demo.cast` (record with the tooling in [`demo/`](demo/))

---

## 0. Prerequisites

| Tool | Check it works | Notes |
|------|----------------|-------|
| Docker Desktop | `docker --version` | Any recent version; start Docker Desktop first |
| Python 3.10+ | `python3 --version` | For the auditor |
| git | `git --version` | Optional, only if you want the auditor from source |

> **Safety / ethics:** this tutorial targets `127.0.0.1` (your own machine).
> Never point honeypot-auditor at systems you do not own or have written permission to test.

---

## 1. Install honeypot-auditor

Open a terminal and create an isolated Python environment (keeps your system Python clean):

```bash
mkdir -p ~/lab && cd ~/lab
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
```

Install the tool from PyPI (the `[full]` extra adds everything the deep probes may use):

```bash
pip install "honeypot-auditor[full]"
honeypot-auditor --version
```

You should see:

```
honeypot-auditor 1.0.3
```

> **Alternative (run from source instead of PyPI):**
> ```bash
> git clone https://github.com/mziqudhd92/honeypot-auditor.git
> cd honeypot-auditor
> python3 -m venv .venv && source .venv/bin/activate
> pip install -e ".[full]"
> ```
> With this variant, run the tool as `python3 honeypot-auditor.py ...` instead of `honeypot-auditor ...`.

---

## 2. Create the lab folder (the ready-made Dockerfile)

Create a folder for the lab. This tutorial ships a `Dockerfile` that layers 5 pre-written
honeypot configs on top of the official DataTrap image — so you don't have to write any
config by hand.

Your lab folder should look like this:

```
dd-honeypot-lab/
├── Dockerfile              ← builds the lab image
├── docker-compose.yml      ← optional one-command launcher
├── .dockerignore
└── honeypot/               ← 5 honeypot definitions, one folder each
    ├── ssh/
    │   ├── config.json     ← SSH honeypot on container port 22 (Alpine Linux w/ fake FS)
    │   ├── data.jsonl      ← request→response pairs for known commands
    │   └── fs_alpine.jsonl.gz  ← fake filesystem for ls / cd / cat
    ├── telnet/
    │   ├── config.json     ← Telnet honeypot on container port 23 (D-Link device)
    │   ├── data.jsonl
    │   └── alpine_fs_small.jsonl.gz
    ├── mysql/
    │   ├── config.json     ← MySQL honeypot on container port 3306
    │   └── data.jsonl      ← e.g. "SELECT VERSION()" → 8.0.33
    ├── redis/
    │   ├── config.json     ← Redis honeypot on container port 6379
    │   └── data.jsonl      ← e.g. "PING" → +PONG
    └── postgres/
        ├── config.json     ← PostgreSQL honeypot on container port 5432
        └── data.jsonl      ← e.g. "SELECT version()" → PostgreSQL 15.4
```

> **Building the folder by hand instead?** Each honeypot is one subfolder with a
> `config.json`. The essential schema:
>
> | Field | Meaning |
> |-------|---------|
> | `type` | `ssh`, `telnet`, `mysql`, `redis` or `postgres` |
> | `port` | port to listen on **inside the container** |
> | `data_file` | path to the dataset JSONL (use absolute paths, e.g. `/data/honeypot/ssh/data.jsonl`) |
> | `fs_file` | fake filesystem (SSH/Telnet only) |
> | `model_id` + `system_prompt` | LLM fallback (DataTrap uses AWS Bedrock; see the note below) |
>
> Datasets (`data.jsonl`) are one JSON object per line:
> `{"command": "uname -a", "response": "Linux alpine 5.15.105-lts ..."}`
>
> **Why ship datasets at all?** DataTrap answers dataset hits directly and calls AWS Bedrock
> for everything else. Without AWS credentials the LLM fallback fails, so we pre-seed the
> common commands/queries the auditor sends. That keeps the honeypot realistic without
> needing a cloud account.

If you received these files alongside this tutorial, just `cd` into that folder:

```bash
cd ~/lab/dd-honeypot-lab
```

---

## 3. Build the lab image

```bash
docker build -t dd-honeypot-lab .
```

Expected (last lines):

```
=> [2/2] COPY honeypot/ /data/honeypot/
=> exporting to image
=> => naming to docker.io/library/dd-honeypot-lab
```

**Prefer Docker Compose?** Skip to step 4 and run `docker compose up -d --build` —
that single command builds *and* starts everything.

---

## 4. Start the honeypot container

```bash
docker run -d --name dd-honeypot-lab \
  -p 127.0.0.1:22:22 \
  -p 127.0.0.1:23:23 \
  -p 127.0.0.1:3306:3306 \
  -p 127.0.0.1:6380:6379 \
  -p 127.0.0.1:5433:5432 \
  dd-honeypot-lab
```

**Why these port numbers?** The format is `-p HOST:CONTAINER`.

| Service | Container port | Host port | Why different? |
|---------|---------------|-----------|----------------|
| SSH | 22 | 22 | standard |
| Telnet | 23 | 23 | standard |
| MySQL | 3306 | 3306 | standard |
| Redis | 6379 | **6380** | 6379 is usually taken by a real local Redis |
| PostgreSQL | 5432 | **5433** | 5432 is usually taken by a real local PostgreSQL |

Binding to `127.0.0.1:` keeps every service private to your machine — nothing is exposed
to your network.

> **Port conflict?** If any chosen host port is already in use, pick a free one
> (e.g. `2222`) and change it in **both** places: the `-p` flag here *and* the matching
> `--ports` flag in step 6. Check availability with `nc -z -w 1 127.0.0.1 <port>`.

---

## 5. Verify all 5 services are listening

```bash
docker logs dd-honeypot-lab 2>&1 | grep -E "Found 5 honeypots|running on port|running on 0"
```

Expected:

```
INFO - Found 5 honeypots. Starting...
INFO - Redis Honeypot running on port 6379
INFO - PostgresHoneypot running on 0.0.0.0:5432
INFO - SSH Honeypot running on port 22
INFO - MySQL honeypot running on port 3306
```

(The Telnet honeypot logs "Telnet Honeypot started. Port: 23" — it starts the same way.)

Then do a quick reachability check from your host:

```bash
for p in 22 23 3306 6380 5433; do
  nc -z -w 1 127.0.0.1 $p >/dev/null 2>&1 && echo "port $p: open" || echo "port $p: CLOSED"
done
```

Expected:

```
port 22: open
port 23: open
port 3306: open
port 6380: open
port 5433: open
```

Fun check — grab a fake Redis PONG through the honeypot:

```bash
(printf 'PING\r\n'; sleep 1) | nc -w 3 127.0.0.1 6380
# → +PONG
```

---

## 6. Run honeypot-auditor (basic audit)

Make sure you're still in the venv from step 1, then run:

```bash
honeypot-auditor --target 127.0.0.1 \
  -p 22,23,3306,6380,5433 \
  --ports ssh=22,telnet=23,mysql=3306,redis=6380,postgres=5433 \
  --output audit-dd-basic.json \
  -v
```

**What do these flags mean?**

| Flag | Meaning |
|------|---------|
| `--target 127.0.0.1` | audit your own machine (no authorization flag needed for private IPs) |
| `-p 22,23,3306,6380,5433` | scan **only** these 5 TCP ports — exactly where the honeypot listens |
| `--ports ssh=22,telnet=23,mysql=3306,redis=6380,postgres=5433` | tell the auditor which protocol lives on which port. This matters: non-standard ports (6380/5433) would otherwise be probed as SSH, and overriding **every** protocol prevents double-probing |
| `--output audit-dd-basic.json` | write the machine-readable report |
| `-v` | verbose: show the score formula, per-protocol matrix and every triggered tell |

Expected highlight from the output (after a minute or so):

```
╭────────────────────────────── Honeypot Auditor ──────────────────────────────╮
│ Target        127.0.0.1 (127.0.0.1)                                          │
│ Honeyscore    100.0% (global)                                                │
│ Confidence    high                                                           │
│ Tactical      SKIP_TARGET                                                    │
│ Threat level  Confirmed Honeypot                                             │
╰──────────────────────────────────────────────────────────────────────────────╯
```

> **Tip:** don't pipe the output into `head` or `less` — a broken pipe can kill the run
> before the JSON report is written. Redirect to a file instead:
> `honeypot-auditor ... > console.txt 2>&1`

---

## 7. Run the deep audit (more detection axes)

`--deep` adds six extra detection axes: shell semantics, OS coherence, SSH/HASSH fingerprints,
protocol state-machine fuzzing, co-tenancy and latency analysis.

```bash
honeypot-auditor --target 127.0.0.1 \
  -p 22,23,3306,6380,5433 \
  --ports ssh=22,telnet=23,mysql=3306,redis=6380,postgres=5433 \
  --deep \
  --output audit-dd-deep.json \
  -v
```

Deep mode found **9 additional tells** in this lab — e.g.:

```
deep.auth_curve:            random creds accepted on attempts [1, 2, 3, 4, 5]
deep.shell_semantics:       arith: expected '2993', got 'Command not handled.'
deep.idle_accept:           accepted 10/10 idle connects mean=0.2ms
deep.cotenancy:             5 responsive IT lures: ssh:22, telnet:23, redis:6380, ...
```

---

## 8. Read the results

The verdict bands are:

| Honeyscore | Verdict |
|-----------|---------|
| < 30% (clean) | Likely Real Host |
| < 30% (with anomalies) | Inconclusive |
| 30 – 59% | Suspected Honeypot |
| **≥ 60%** | **Confirmed Honeypot** ← this lab scores **100%** |

Score reached 100% mainly because of **arbitrary auth** — the honeypot accepts *any*
username/password (a classic honeypot giveaway, and a real service would never do that),
plus **multi-protocol corroboration** (tells fired on 5 different protocols on one host).

What fired, per protocol (from the actual run):

| Protocol | Basic result | Example evidence |
|----------|--------------|------------------|
| SSH :22 | 3/3 strategies HIT | two random logins both accepted; sftp subsystem missing; `/tmp` canary file vanishes after re-login |
| Redis :6380 | 3/3 strategies HIT | any AUTH password returns `+OK`; `EX` TTL ignored; INFO stats frozen |
| Telnet :23 | 1/3 HIT | IAC "Are-You-There" probe unanswered |
| MySQL :3306 | 1/2 HIT | protocol state-machine leak: "Expected seq(1) got seq(0)" on a wrong auth sequence |
| PostgreSQL :5433 | 1/2 HIT | rejects SSL, then offers cleartext-password auth only |

**Reading the JSON report** — the two most useful fields:

```bash
python3 - <<'EOF'
import json
r = json.load(open("audit-dd-basic.json"))
print("Score:", r["score"], "→", r["threat_level"])
for t in r["triggered"]:
    print(" HIT:", t["id"])
EOF
```

Every `id` maps to a documented detection strategy in the auditor's
[`docs/STRATEGIES.md`](https://github.com/mziqudhd92/honeypot-auditor/blob/main/docs/STRATEGIES.md).

---

## 9. Stop and clean up

```bash
docker rm -f dd-honeypot-lab     # removes the container (re-run step 4 to start again)
deactivate                        # leave the Python venv when you're done
```

The image (`dd-honeypot-lab`) stays on disk; remove it with `docker rmi dd-honeypot-lab`.

---

## Troubleshooting

| Symptom | Cause & fix |
|---------|-------------|
| `docker: bind: address already in use` | The host port is taken. Pick another (see the note in step 4) and update `--ports` in step 6 to match. |
| `port X: CLOSED` in step 5 | The container needs a few seconds to start — check `docker logs dd-honeypot-lab` for startup errors. |
| SSH probes show `connection reset`, but `docker exec` into the container works | Rare Docker Desktop port-forward wedge. Recreate the container: `docker rm -f dd-honeypot-lab` then re-run step 4. |
| macOS says port 22 is in use before Docker starts | macOS "Remote Login" (SSH) is enabled — turn it off in System Settings, or map the honeypot elsewhere (e.g. `-p 127.0.0.1:2222:22` + `--ports ssh=2222`). |
| Telnet probes skip with "connection refused" | You're probing too fast after start, or a wedged forward (see above). Telnet is also the honeypot's *least* detectable face — a partial result there is normal. |
| Results mention protocols you didn't set up (SMB, Memcached, Elasticsearch…) | You ran without `-p`, so the full default port preset was scanned — other local services (or lab containers) were audited too. Always scope with `-p` for a clean verdict. |
| Windows: `nc` not found | Use `Test-NetConnection 127.0.0.1 -Port 22` in PowerShell instead. |

---

## What you just did (recap)

1. Installed a multi-protocol honeypot detector (`honeypot-auditor`)
2. Deployed a real open-source honeypot (ThalesGroup **dd-honeypot / DataTrap**) with 5 services
3. Scanned only the honeypot's ports and let the auditor correlate tells across protocols
4. Confirmed the detection: **Honeyscore 100% · Confirmed Honeypot · high confidence**

Try next: switch the honeypot configs to non-default ports, add an HTTP honeypot from the
upstream repo's `test/honeypots/` examples, and see whether the auditor still catches it —
that's deception engineering in a nutshell.
