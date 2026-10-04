# Beginner Tutorial: Detect a Local Honeypot with honeypot-auditor

In this tutorial you will:

1. Install **honeypot-auditor** — a CLI that fingerprints whether a target behaves like a honeypot
2. Build and run **dd-honeypot (DataTrap)** — an open-source honeypot by ThalesGroup — from this lab folder,
   with **SSH, Telnet, MySQL, Redis and PostgreSQL** enabled
3. Point the auditor at it and watch it detect the honeypot with a **Honeyscore of 100% — "Confirmed Honeypot"**

Everything runs on your own machine (`127.0.0.1`), so this is a fully authorized lab exercise.

```
 .────────────────────────────────────────────────────────────────────.
 │  you (honeypot-auditor) ──probes──▶ Docker ▶ dd-honeypot           │
 │                                    2222, 23, 3306, 6380, 5433      │
 '────────────────────────────────────────────────────────────────────'
```

**Lab path (the only one):** [`docs/tutorials/dd-honeypot-lab-demo/`](.)  
All commands below assume you start from the **honeypot-auditor repository root**.

**Time needed:** ~15 minutes · **Difficulty:** beginner

**Rather watch?** A recorded demo lives in this same folder:

- [`honeypot-auditor-dd-honeypot-demo.gif`](honeypot-auditor-dd-honeypot-demo.gif) — animated GIF
- [`honeypot-auditor-dd-honeypot-demo.cast`](honeypot-auditor-dd-honeypot-demo.cast) — replay with  
  `asciinema play docs/tutorials/dd-honeypot-lab-demo/honeypot-auditor-dd-honeypot-demo.cast`

---

## 0. Prerequisites

| Tool | Check it works | Notes |
|------|----------------|-------|
| Docker Desktop | `docker --version` | Any recent version; start Docker Desktop first |
| Python 3.10+ | `python3 --version` | For the auditor |
| git | `git --version` | To clone this repository |
| `nc` (netcat) | `nc -h` / `nc -v` | Optional reachability checks (PowerShell alternative below) |

> **Safety / ethics:** this tutorial targets `127.0.0.1` (your own machine).
> Never point honeypot-auditor at systems you do not own or have written permission to test.

Clone the repo if you have not already, then stay at the repo root:

```bash
git clone https://github.com/mziqudhd92/honeypot-auditor.git
cd honeypot-auditor
```

Confirm the lab folder exists:

```bash
ls docs/tutorials/dd-honeypot-lab-demo/Dockerfile \
   docs/tutorials/dd-honeypot-lab-demo/docker-compose.yml \
   docs/tutorials/dd-honeypot-lab-demo/honeypot
```

---

## 1. Install honeypot-auditor

Create an isolated Python environment at the repo root (keeps your system Python clean):

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[full]"
honeypot-auditor --version
```

You should see:

```
honeypot-auditor 1.0.3
```

> **Alternative (PyPI only, without an editable checkout):**
> ```bash
> python3 -m venv .venv && source .venv/bin/activate
> pip install "honeypot-auditor[full]"
> ```
> You still need this repository cloned so you can build the Docker lab in
> `docs/tutorials/dd-honeypot-lab-demo/`.

---

## 2. Understand the lab layout

This folder ships a `Dockerfile` that layers five pre-written honeypot configs on top of
the official DataTrap image — you do not write config by hand.

```
docs/tutorials/dd-honeypot-lab-demo/
├── Dockerfile                 ← builds the lab image
├── docker-compose.yml         ← optional one-command launcher
├── TUTORIAL.md                ← this file
├── honeypot-auditor-dd-honeypot-demo.gif / .cast
└── honeypot/                  ← 5 honeypot definitions, one folder each
    ├── ssh/     config.json · data.jsonl · fs_alpine.jsonl.gz
    ├── telnet/  config.json · data.jsonl · alpine_fs_small.jsonl.gz
    ├── mysql/   config.json · data.jsonl
    ├── redis/   config.json · data.jsonl
    └── postgres/ config.json · data.jsonl
```

> **Config schema (for curiosity):** each honeypot is one subfolder with a `config.json`.
>
> | Field | Meaning |
> |-------|---------|
> | `type` | `ssh`, `telnet`, `mysql`, `redis` or `postgres` |
> | `port` | port to listen on **inside the container** |
> | `data_file` | absolute path to the dataset JSONL (e.g. `/data/honeypot/ssh/data.jsonl`) |
> | `fs_file` | fake filesystem (SSH/Telnet only) |
> | `model_id` + `system_prompt` | LLM fallback (DataTrap uses AWS Bedrock) |
>
> Datasets (`data.jsonl`) are one JSON object per line:
> `{"command": "uname -a", "response": "Linux alpine 5.15.105-lts ..."}`
>
> **Why ship datasets?** DataTrap answers dataset hits directly and calls AWS Bedrock
> for everything else. Without AWS credentials the LLM fallback fails, so we pre-seed
> the common commands the auditor sends. That keeps the honeypot useful offline.

Enter the lab directory for the Docker steps:

```bash
cd docs/tutorials/dd-honeypot-lab-demo
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
that single command builds *and* starts everything (same host ports as below).

---

## 4. Start the honeypot container

SSH is published on **host port 2222** (not 22) so it does not collide with macOS
“Remote Login” / a real local `sshd`.

```bash
docker run -d --name dd-honeypot-lab \
  -p 127.0.0.1:2222:22 \
  -p 127.0.0.1:23:23 \
  -p 127.0.0.1:3306:3306 \
  -p 127.0.0.1:6380:6379 \
  -p 127.0.0.1:5433:5432 \
  dd-honeypot-lab
```

**Why these port numbers?** The format is `-p HOST:CONTAINER`.

| Service | Container port | Host port | Why different? |
|---------|---------------|-----------|----------------|
| SSH | 22 | **2222** | avoids local `sshd` / macOS Remote Login on 22 |
| Telnet | 23 | 23 | standard |
| MySQL | 3306 | 3306 | standard |
| Redis | 6379 | **6380** | 6379 is often taken by a real local Redis |
| PostgreSQL | 5432 | **5433** | 5432 is often taken by a real local PostgreSQL |

Binding to `127.0.0.1:` keeps every service private to your machine — nothing is exposed
to your LAN.

> **Port conflict?** If any chosen host port is already in use, pick a free one
> (e.g. `2323` for Telnet) and change it in **both** places: the `-p` flag here *and*
> the matching `--ports` / `-p` values in steps 6–7.
> Check availability with `nc -z -w 1 127.0.0.1 <port>`.

If a previous lab container still exists: `docker rm -f dd-honeypot-lab` first.

---

## 5. Verify all 5 services are listening

```bash
docker logs dd-honeypot-lab 2>&1 | grep -E "Found 5 honeypots|running on port|running on 0|Telnet|Found honeypot folder"
```

Expected highlights (order may vary):

```
INFO - Found 5 honeypots. Starting...
INFO - Redis Honeypot running on port 6379
INFO - PostgresHoneypot running on 0.0.0.0:5432
INFO - SSH Honeypot running on port 22
INFO - MySQL honeypot running on port 3306
INFO - Found honeypot folder: /data/honeypot/telnet
```

Telnet may not print a separate `running on port 23` line — seeing the Telnet folder
(and five honeypots started) is enough.

Then do a quick reachability check from your host:

```bash
for p in 2222 23 3306 6380 5433; do
  nc -z -w 1 127.0.0.1 $p >/dev/null 2>&1 && echo "port $p: open" || echo "port $p: CLOSED"
done
```

Expected:

```
port 2222: open
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

> **Expected log noise later:** while the auditor runs, DataTrap may print
> `Unable to locate credentials` (AWS Bedrock LLM fallback with no cloud account),
> MySQL `AssertionError` traces, or SSH banner read errors. Dataset-matched replies
> still work — treat those lines as noise, not a failed lab.

---

## 6. Run honeypot-auditor (basic audit)

Stay in the venv from step 1. From the **repo root** (or keep using the absolute
`--output` path below), run:

```bash
cd ../../..   # back to honeypot-auditor repo root if you are still in the lab folder

honeypot-auditor --target 127.0.0.1 \
  -p 2222,23,3306,6380,5433 \
  --ports ssh=2222,telnet=23,mysql=3306,redis=6380,postgres=5433 \
  --output audit-dd-basic.json \
  -v
```

**What do these flags mean?**

| Flag | Meaning |
|------|---------|
| `--target 127.0.0.1` | audit your own machine (no authorization flag needed for private IPs) |
| `-p 2222,23,3306,6380,5433` | scan **only** these 5 TCP ports — exactly where the honeypot listens on the host |
| `--ports ssh=2222,telnet=23,mysql=3306,redis=6380,postgres=5433` | map each protocol to its host port. Non-standard ports (2222 / 6380 / 5433) would otherwise be mis-probed; overriding **every** protocol also prevents double-probing |
| `--output audit-dd-basic.json` | write the machine-readable report |
| `-v` | verbose: score formula, per-protocol matrix, every triggered tell |

Expected highlight (after under a minute on a typical laptop):

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
  -p 2222,23,3306,6380,5433 \
  --ports ssh=2222,telnet=23,mysql=3306,redis=6380,postgres=5433 \
  --deep \
  --output audit-dd-deep.json \
  -v
```

Deep mode typically adds several cross-protocol tells on top of the basic score —
examples from this lab:

```
deep.auth_curve:            random creds accepted on attempts [1, 2, 3, 4, 5]
deep.shell_semantics:       arith: expected '2993', got 'Command not handled.'
deep.idle_accept:           accepted 10/10 idle connects mean≈0.1–0.2ms
deep.cotenancy:             5 responsive IT lures: ssh:2222, telnet:23, redis:6380, ...
```

Exact deep IDs can vary slightly between runs; the Honeyscore should remain **100% /
Confirmed Honeypot**. Telnet is the weakest face — an AYT hit may appear in the basic
run and skip in deep (or the reverse). That is normal.

---

## 8. Read the results

The verdict bands are:

| Honeyscore | Verdict |
|-----------|---------|
| < 30% (clean) | Likely Real Host |
| < 30% (with anomalies) | Inconclusive |
| 30 – 59% | Suspected Honeypot |
| **≥ 60%** | **Confirmed Honeypot** ← this lab scores **100%** |

Score reaches 100% mainly because of **arbitrary auth** — the honeypot accepts *any*
username/password (a classic honeypot giveaway), plus **multi-protocol corroboration**
(tells on five different protocols on one host).

What typically fires, per protocol (representative run):

| Protocol | Basic result | Example evidence |
|----------|--------------|------------------|
| SSH :2222 | 3/3 strategies HIT | two random logins both accepted; sftp subsystem missing; `/tmp` canary vanishes after re-login |
| Redis :6380 | 3/3 strategies HIT | any AUTH password returns `+OK`; `EX` TTL ignored; INFO stats frozen |
| Telnet :23 | often 1/3 HIT | IAC “Are-You-There” unanswered (corroboration-gated; may skip on some runs) |
| MySQL :3306 | 1/2 HIT | protocol state-machine leak: `Expected seq(1) got seq(0)` on a wrong auth sequence |
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

Every `id` maps to a documented detection strategy in
[`docs/strategies/`](../../strategies/).

---

## 9. Stop and clean up

```bash
docker rm -f dd-honeypot-lab     # removes the container (re-run step 4 to start again)
deactivate                        # leave the Python venv when you're done
```

The image (`dd-honeypot-lab`) stays on disk; remove it with `docker rmi dd-honeypot-lab`.

Local reports `audit-dd-basic.json` / `audit-dd-deep.json` in the repo root are yours to
keep or delete.

---

## Troubleshooting

| Symptom | Cause & fix |
|---------|-------------|
| `docker: bind: address already in use` | The host port is taken. Pick another and update `--ports` / `-p` in steps 6–7 to match. |
| `port X: CLOSED` in step 5 | Wait a few seconds; check `docker logs dd-honeypot-lab` for startup errors. |
| SSH probes show `connection reset`, but `docker exec` into the container works | Rare Docker Desktop port-forward wedge. Recreate: `docker rm -f dd-honeypot-lab` then re-run step 4. |
| Telnet probes skip with “connection refused” | Probing too soon after start, or a wedged forward. Telnet is also the least detectable face — a partial result there is normal. |
| Results mention protocols you did not set up (SMB, Memcached, …) | You ran without `-p`, so the full default preset was scanned. Always scope with `-p` for a clean verdict. |
| Lots of `Unable to locate credentials` / MySQL `AssertionError` in `docker logs` | Expected without AWS Bedrock — see the note in step 5. |
| Windows: `nc` not found | Use `Test-NetConnection 127.0.0.1 -Port 2222` in PowerShell instead. |
| Wrong directory | Lab commands must run from `docs/tutorials/dd-honeypot-lab-demo/` (build/compose) or the **repo root** (auditor). There is no separate `~/lab/…` copy of this tutorial. |

---

## What you just did (recap)

1. Installed a multi-protocol honeypot detector (`honeypot-auditor`)
2. Deployed a real open-source honeypot (ThalesGroup **dd-honeypot / DataTrap**) with 5 services from `docs/tutorials/dd-honeypot-lab-demo/`
3. Scanned only the honeypot’s host ports and let the auditor correlate tells across protocols
4. Confirmed the detection: **Honeyscore 100% · Confirmed Honeypot · high confidence**

Try next: remap a service to a non-default host port, or add an HTTP honeypot from the
upstream DataTrap `test/honeypots/` examples, and see whether the auditor still catches it —
that’s deception engineering in a nutshell.
