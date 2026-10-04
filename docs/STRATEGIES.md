# Probe strategies

**30** protocol engines (**25 TCP-capable** + **5 UDP-only**; SIP is UDP-first
with TCP fallback). Each uses up to **3** basic probe strategies:

| Strategy | Role |
|----------|------|
| **arbitrary_auth** | Dual synthetic credentials / communities accepted when they should not be |
| **state_nonpersist** | Session or object state that a real daemon would keep |
| **static_signature** | Framing, facade, stock lure, and conformance tells |

## Where to review (auditors)

**Per-protocol folders:** [`docs/strategies/`](strategies/README.md)

Each protocol has its own directory (`docs/strategies/ssh/`,
`docs/strategies/smtp/`, …) with:

- Strategies + indicators tables
- Non-destructive policy / ports
- **Code map** → probe module, signature matchers, tests, `PROTOCOL_STRATEGIES` key

That tree is the canonical place to audit and review strategies by protocol.

| Resource | Path |
|----------|------|
| Protocol index + review checklist | [`docs/strategies/`](strategies/README.md) |
| TCP transport notes | [`docs/tcp/`](tcp/README.md) |
| UDP transport notes | [`docs/udp/`](udp/README.md) |
| Scoring / fidelity | [`docs/SCORING.md`](SCORING.md) |
| Axis catalog (code) | `PROTOCOL_STRATEGIES` in `src/honeypot_auditor/config/scoring.py` |

README **Strategies** = active axes (up to 3; **80** slots). **Indicators** =
scored tells (**255** total).

## `-p` extras

`-p` maps well-known extras the same way: `443`/`8443` → HTTP (TLS),
`8080`/`3128` → HTTP proxy, `139` → SMB, `993`/`1993` → IMAP (TLS/IMAPS),
`8883`/`18883` → MQTT (TLS/MQTTS), `161`/`1161`/`10161` → SNMP (UDP),
`53`/`15353` → DNS (UDP), `123`/`1123` → NTP (UDP), `69`/`1069` → TFTP (UDP),
`1900`/`11900` → SSDP (UDP), `9200`/`19200` → Elasticsearch,
`2375`/`12375` → Docker, `6443`/`16443` → Kubernetes API, `631`/`1631` → IPP,
`11211`/`21211` → Memcached, `1723`/`11723` → PPTP, `5061` → SIP,
`5000`/`5901` → VNC. Unknown numbers are probed as SSH.

Default preset (`--preset both`) probes IANA well-known ports **and** common
lab/docker aliases. Override with `-p` / `--ports`. Closed faces are skipped,
not scored. Port matrix: [README · Supported protocols / ports](../README.md).

## Deep mode & optional layers

`--deep` adds cross-protocol axes (shell semantics, HASSH/TCP stack, FSM fuzz,
co-tenancy, serial + concurrent-load latency) on top of the basic strategies.
Passive-intel providers and Nmap NSE (`-n`) are optional layers, not protocol
engines.
