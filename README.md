```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ░█░█░█░█▀▀░█▀▄░█▀█░█▀█░█▀█░▀█▀░█▀█   ░█▀█░█░█░█▀▀░▀█▀░█▀█░█▀▄░█▀▀░█▀▄░█▀█  ║
║  ░█▀█░░█▀▀░█▀▄░█░█░█▀▀░█▀█░░█░░█░█   ░█░█░█░█░▀▀█░░█░░█░█░█░█░█▀▀░█▀▄░█░█  ║
║  ░▀░▀░░▀░░░▀░▀░▀░▀░▀░░░▀░▀░░▀░░▀▀▀   ░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀░░▀▀▀░▀░▀░▀▀▀  ║
║                                                                              ║
║  [+] RELEASE .......... honeypot-auditor v0.2.0                              ║
║  [+] TYPE .............. Multi-Protocol Decoy Fingerprinter / Lab Util       ║
║  [+] PLATFORM .......... Linux · macOS · Windows (Python 3.10+)              ║
║  [+] DISKS ............. 0 · pure electrons · no floppies harmed               ║
║  [+] PROTECTION ........ NONE · MIT license · spread the sauce               ║
║  [+] SUPPLIER .......... https://github.com/mziqudhd92/honeypot-auditor     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  >>> READ THIS NFO BEFORE YOU DIAL IN <<<                                    ║
║                                                                              ║
║  Authorized targets ONLY. Lab boxes. Decoys you own. Sensors you run.        ║
║  Permission on paper (or in ticket).                                         ║
║                                                                              ║
║  Scanning random /16 because Shodan said "interesting" = you are the bait.   ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## -=[ WHAT IS THIS ]=-

**Honeypot Auditor** — a CLI that asks one rude question:

> *Does this IP behave like a low-interaction honeypot, or like something
> that might actually bill someone for downtime?*

Passive intel ([Shodan Honeyscore](https://honeyscore.shodan.io/)) plus active,
**non-destructive** probes across the usual decoy faces. Outputs a weighted
**Honeyscore (0–100%)**, Rich console table, JSON report.

Not exploits. Not exfil. Banner/state/auth semantics. The kind of stuff that
made Cowrie sweat in `'09 and still catches clones in `'26.

```
  [ BASIC ]  Shodan · Nmap NSE · SSH/Telnet/SMB/FTP/HTTP/Redis/SMTP/VNC/SIP
  [ DEEP  ]  shell semantics · OS coherence · HASSH · TCP stack · FSM fuzz
             · co-tenancy buffet detect · latency · egress bait
             (flag: --deep · more intrusive · same authorization rules)
```

---

## -=[ INSTALLATION ]=-

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  STEP 0 · PyPI (after first publish)                                  │
  └─────────────────────────────────────────────────────────────────────┘
```

```bash
pip install honeypot-auditor
pip install "honeypot-auditor[full]"    # nmap deps, impacket, shodan, scapy
```

Publish checklist: [docs/PUBLISHING.md](docs/PUBLISHING.md)

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  STEP 1 · grab the release (source / dev)                             │
  └─────────────────────────────────────────────────────────────────────┘
```

```bash
git clone https://github.com/mziqudhd92/honeypot-auditor.git
cd honeypot-auditor
python3 -m venv .venv
source .venv/bin/activate          # win32: .venv\Scripts\activate
pip install -e ".[full,dev]"       # full probe stack + scapy + dev tools
```

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  STEP 2 · lite install (core only · no impacket/scapy/shodan extras)  │
  └─────────────────────────────────────────────────────────────────────┘
```

```bash
pip install -e .
```

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  STEP 3 · verify your stack                                         │
  └─────────────────────────────────────────────────────────────────────┘
```

```bash
honeypot-auditor --version
pytest -q
```

---

## -=[ QUICKSTART / COMMANDS ]=-

```bash
# local lab · docker-compose research ports (2222, 8081, 1445, …)
honeypot-auditor --target 127.0.0.1 --preset docker-research --skip-nmap

# go deep · six extra detection axes · still no exploits
honeypot-auditor --target 127.0.0.1 --preset docker-research --skip-nmap --deep

# internet-facing target · need explicit ack + Shodan key if you want intel
honeypot-auditor --target 203.0.113.10 --preset iana \
  --shodan-key "$SHODAN_API_KEY" --confirm-authorized

# benchmark lab · cowrie + dionaea in docker
./scripts/benchmark-lab.sh
```

---

## -=[ SCORING MATRIX ]=-

```
  ╭──────────────────────────┬────────┬────────────────────────────────────╮
  │ CATEGORY                 │ WEIGHT │ TRIGGERS                           │
  ├──────────────────────────┼────────┼────────────────────────────────────┤
  │ Shodan intel             │  25%   │ Honeyscore > 0.6 · honeypot tag    │
  │ Arbitrary auth           │  30%   │ any-password SSH/Telnet · open relay│
  │ State non-persistence    │  25%   │ FTP STOR / Redis key vanishes      │
  │ Static signatures        │  20%   │ Cowrie banners · stock uname/cpu   │
  ╰──────────────────────────┴────────┴────────────────────────────────────╯

  --deep ADDS (lab brain mode):
  ┌──────────────────────────┬────────┬────────────────────────────────────┐
  │ behavior                 │  18%   │ $((arith)) · sleep · channel lies  │
  │ coherence                │  15%   │ uname vs /proc vs os-release drift │
  │ stack_fingerprint        │  12%   │ HASSH vs banner · TCP TTL mismatch │
  │ proto_conformance        │  12%   │ HTTP/ FTP/SMTP FSM edge cases      │
  │ co-tenancy               │   8%   │ honeypot buffet · needs corroboration│
  │ temporal                 │  10%   │ robotic latency · egress silence   │
  └──────────────────────────┴────────┴────────────────────────────────────┘

  VERDICT BANDS:
    [##########----------]  < 30%   LIKELY REAL HOST
    [################----]  30-59%  SUSPECTED HONEYPOT
    [####################]  >= 60%  CONFIRMED HONEYPOT
```

Co-tenancy won't fire alone on multi-decoy platforms (looking at you,
research stacks with 11 open faces). Needs another tell first. By design.

---

## -=[ CLI FLAGS ]=-

```
  --target HOST              victim^W subject under authorized test
  --preset docker-research   lab ports (default)
  --preset iana              well-known ports (22, 80, 445, …)
  --ports ssh=2222,http=8081 per-protocol override
  --shodan-key KEY           or env SHODAN_API_KEY
  --output report.json       JSON artifact path
  --confirm-authorized       REQUIRED for public IPs
  --skip-nmap                skip Nmap NSE phase
  --deep                     advanced six-axis probes
  --timeout SECS             socket timeout (default 3)
```

---

## -=[ PORT PRESETS ]=-

```
  PROTOCOL    iana    docker-research
  ──────────────────────────────────
  SSH          22         2222
  HTTP         80         8081
  FTP          21         2121
  Telnet       23         2323
  SMTP         25         2525
  SMB         445         1445
  SIP        5060         5060
  VNC        5900         5900
  Redis      6379         6379
```

---

## -=[ DEV / QA ]=-

```bash
pip install -e ".[full,dev]"
pytest
ruff check src tests
docker compose -f deploy/docker-compose.benchmark.yml up -d
./scripts/benchmark-lab.sh
```

---

## -=[ NOT THE SAME AS UHBS ]=-

This tool asks: **"Is that IP a honeypot?"** (attacker / CTI view)

[UHBS](https://github.com/uhbs/uhbs-standard) asks: **"How good is your decoy?"**
(builder / lab UHQS grade · Modules A–F · 36 protocols)

Same neighborhood. Different door. Use both if you build deception for a living.
Use this one if you just need a fast external fingerprint.

---

## -=[ GREETS / SHOUTS ]=-

```
  Proper respect to:
    Cowrie · Dionaea · Conpot · the old Kippo crew
    UHBS lab rats · CyberHalluciNet purple-team night shift
    Shodan · Salesforce HASSH · everyone who ever typed USER anonymous
    BBS sysops who ran 9600 baud file areas for "utilz"
    and the three people who still read NFO files in 2026

  NO GREETS TO:
    script kiddies scanning /0
    vendors who call Cowrie "AI-powered threat intelligence"
    anyone who STORs malware on decoys then writes a LinkedIn post about it
```

---

## -=[ RESPONSIBLE USE ]=-

Defensive research. Authorized testing. Lab sandboxes. Your sensors. Your tickets.

Do **not** point this at infrastructure you don't own or haven't been cleared to test.

Vuln reports → [SECURITY.md](SECURITY.md)

---

## -=[ HACKING / COVERAGE ]=-

![tests](https://github.com/mziqudhd92/honeypot-auditor/actions/workflows/test.yml/badge.svg)

```bash
make install    # editable install with [full,dev]
make test       # unit tests (fast, no coverage)
make test-cov   # branch coverage gate 60% + htmlcov/index.html
make lint
```

Coverage config: `pyproject.toml` → `[tool.coverage.*]`. CI uploads `coverage.xml` + HTML as the **`coverage-report`** artifact on every push/PR.

Contributing → [CONTRIBUTING.md](CONTRIBUTING.md)

---

## -=[ LICENSE ]=-

```
  MIT · do what you want · keep the copyright · no warranty
  see LICENSE for the lawyer-safe version (boring but binding)
```

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  h0n3yp0t 4ud1t0r · v0.2.0 · spread headers not malware · EOF               ║
╚══════════════════════════════════════════════════════════════════════════════╝
```
