# Scoring reference

## Honeyscore

Basic category weights (from `config.WEIGHTS`):

| Category | Weight |
|----------|--------|
| Passive intel (Shodan or selected providers) | 25% |
| Arbitrary auth | 30% |
| State non-persistence | 25% |
| Static signature | 20% |
| Co-tenancy | 15% |

Deep mode adds (`DEEP_WEIGHTS`): behavior 18%, coherence 15%, stack_fingerprint 12%, proto_conformance 12%, temporal 10%.

### Intra-category corroboration

Category weight is awarded on the first triggered tell. Each **additional** triggered
indicator in the **same** category adds **+7.5%** (cap **+15%**). Example: two
`static_signature` hits → 20% + 7.5% = 27.5% before other bonuses.

### Temporal indicators (`--deep`)

| ID | What it measures |
|----|------------------|
| `deep.latency` | Serial banner RTT mean + coefficient of variation (canned handlers) |
| `deep.latency_under_load` | Parallel connections: load CV + stretch vs serial baseline (LI traps stay flat) |
| `deep.idle_accept` | Many idle TCP accepts with no backoff |
| `deep.clock_drift` | HTTP `Date` skew / frozen clock (optional SMB SystemTime) |
| `deep.egress` | Contained egress silence after SSH bait DNS |

`deep.latency_under_load` is corroboration-gated and skipped in `--safe-mode`. It is a probe indicator (not a YAML signature primitive).

### IMAP / POP3 mail skins (basic probe)

IMAP and POP3 share the same three basic strategies for Exchange/qeeqbox-class lures.
IMAP details:

| ID | Category | Notes |
|----|----------|-------|
| `imap.arbitrary_auth` | arbitrary_auth | Decisive when hit; skipped on `* PREAUTH` |
| `imap.preauth_state` | state_nonpersist | `SELECT` OK before LOGIN; skipped on PREAUTH |
| `imap.auth_failed_blanket` | static_signature | High fidelity; requires CAPABILITY lure text |
| `imap.stock_banner` | static_signature | Corroboration-gated Exchange greeting |

Full indicator list, PREAUTH/BYE/IMAPS behavior, and non-destructive policy: [`IMAP.md`](IMAP.md).

### MQTT behavioral tells (basic probe)

MQTT uses the same three basic strategies. Prefer these over banner IOCs:

| ID | Category | Notes |
|----|----------|-------|
| `mqtt.arbitrary_auth` | arbitrary_auth | Decisive when hit; skipped if anonymous CONNECT already ok |
| `mqtt.message_bus` | state_nonpersist | Two-client canary (granted SUBACK + poll) — high fidelity |
| `mqtt.session_resume` | state_nonpersist | Hollow `session_present=1`; skipped on SUBACK deny |
| `mqtt.keepalive_zombie` | state_nonpersist | PINGRESP after 1.5× Keep Alive (lab-oriented) |
| `mqtt.empty_clientid` / `mqtt.protocol_facade` | static_signature | RFC conformance, high fidelity |

Full indicator list and non-destructive policy: [`MQTT.md`](MQTT.md).


### SNMP RFC non-compliance (basic probe)

SNMP uses **arbitrary_auth** + **static_signature** only (no session/state axis).
Prefer RFC facade / MIB-stub tells over banner IOCs alone — see [`SNMP.md`](SNMP.md).

| ID | Category | Notes |
|----|----------|-------|
| `snmp.arbitrary_community` | arbitrary_auth | Decisive when hit; `public` alone never scores |
| `snmp.response_clone` | static_signature | Decisive when hit (canned identical UDP payloads) |
| `snmp.request_id` / `snmp.version_facade` / `snmp.nosuch_success` | static_signature | High fidelity RFC tells |
| `snmp.getnext_stub` / `snmp.type_facade` / `snmp.oid_echo` | static_signature | GetNext / ASN.1 / OID-name facade |
| `snmp.ber_framing` / `snmp.stock_sysdescr` | static_signature | Framing + lure banner (weak sysDescr tokens corroboration-gated) |

Full strategy narrative, probe flow, and non-destructive policy: [`SNMP.md`](SNMP.md).

### TFTP RFC non-compliance (basic probe)

TFTP uses **static_signature** + **state_nonpersist** (RFC 1350 / light RFC 2347
over UDP; no auth axis). Prefer TID / opcode / option / retransmit facade tells
over lure strings alone — see [`udp/TFTP.md`](udp/TFTP.md).

| ID | Category | Notes |
|----|----------|-------|
| `tftp.fixed_source_port` | static_signature | High when reply `peer_port == dst_port` (no distinct server TID) |
| `tftp.tid_reuse` | state_nonpersist | High when independent RRQs reuse the same ephemeral server TID |
| `tftp.opcode_facade` / `tftp.error_stub` / `tftp.mode_facade` / `tftp.wrq_stub` | static_signature | Missing-file / illegal-mode / WRQ DATA facades |
| `tftp.option_blindness` | static_signature | RRQ+`blksize` choke (`ERROR 0` empty) instead of OACK / proper ERROR |
| `tftp.response_clone` | static_signature | Canned identical DATA/ACK (or stubby ERROR) for distinct RRQs |
| `tftp.no_retransmit` | static_signature | OACK/DATA never retransmitted while ACK withheld |
| `tftp.stock_payload` | static_signature | Stock ERROR/DATA lure tokens (corroboration-gated) |
| `tftp.framing` | static_signature | Non-speaker / unparseable TFTP reply |

Full indicator list, ports, safe-mode, and non-destructive policy: [`udp/TFTP.md`](udp/TFTP.md).

### DNS RFC non-compliance (basic probe)

DNS uses **all three** basic strategies (UDP/53). Prefer RFC facade / auth / state
tells over banner IOCs alone — see [`udp/DNS.md`](udp/DNS.md).

| ID | Category | Notes |
|----|----------|-------|
| `dns.arbitrary_auth` | arbitrary_auth | Decisive when hit; two entropy-varied private-label queries both NOERROR |
| `dns.state_nonpersist` | state_nonpersist | Frozen SOA serial · identical answer · AA/TTL contradiction |
| `dns.response_clone` | static_signature | Decisive when hit (bitwise-identical replies across txids) |
| `dns.header_framing` / `dns.txid` / `dns.header_facade` / `dns.question_echo` | static_signature | High fidelity RFC tells |
| `dns.rcode_stub` / `dns.edns_facade` | static_signature | NXDOMAIN / EDNS OPT facade |
| `dns.case_encoding_mismatch` / `dns.stock_payload` | static_signature | Corroboration-gated (0x20 case + stock TXT/SOA lure) |

Full strategy narrative, probe flow, and non-destructive policy: [`udp/DNS.md`](udp/DNS.md).

### NTP RFC 5905 non-compliance (basic probe)

NTP uses **all three** basic strategies (UDP/123). Prefer RFC facade / KoD / state
tells over banner IOCs alone — see [`udp/NTP.md`](udp/NTP.md).

| ID | Category | Notes |
|----|----------|-------|
| `ntp.kod_absent` | arbitrary_auth | High when hit; mode-3 burst served without KoD `RATE`/`DENY` |
| `ntp.state_nonpersist` | state_nonpersist | Transmit/receive/reference timestamps fail monotonicity |
| `ntp.response_clone` | static_signature | Decisive when hit (bitwise-identical replies across distinct xmt) |
| `ntp.framing` / `ntp.mode_facade` / `ntp.org_echo` / `ntp.stratum_facade` | static_signature | High fidelity RFC tells |
| `ntp.zeroed_clock_metrics` / `ntp.epoch_zero` / `ntp.stock_refid` | static_signature | Corroboration-gated (sparse metrics · epoch stamps · lure refid) |

Full strategy narrative, probe flow, and non-destructive policy: [`udp/NTP.md`](udp/NTP.md).

### Memcached ASCII non-compliance (basic probe)

Memcached uses **all three** basic strategies (TCP ASCII). Prefer framing / ERROR /
auth / state tells over banner IOCs alone — see [`MEMCACHED.md`](MEMCACHED.md).

| ID | Category | Notes |
|----|----------|-------|
| `memcached.arbitrary_auth` | arbitrary_auth | Decisive when hit; two entropy-varied probe-key `set` both `STORED` |
| `memcached.state_nonpersist` | state_nonpersist | Probe-key set then reconnect get miss / stats ignore write |
| `memcached.stats_clone` | static_signature | Decisive when hit (bitwise-identical `stats` replies) |
| `memcached.version_framing` / `memcached.stats_framing` / `memcached.unknown_command` | static_signature | High fidelity ASCII tells |
| `memcached.get_miss` / `memcached.flush_stub` / `memcached.noreply_facade` | static_signature | Miss END · bare verbosity · noreply quiet |
| `memcached.stock_version` | static_signature | Stock VERSION lure (generic tokens corroboration-gated) |

Probe-key `set`/`delete` allowed; **never** `flush_all`. Full strategy narrative,
probe flow, and non-destructive policy: [`MEMCACHED.md`](MEMCACHED.md).

### Redis RESP non-compliance (basic probe)

Redis uses all three basic strategies. Prefer RESP facade / state tells over banner
IOCs alone — see [`REDIS.md`](REDIS.md).

| ID | Category | Notes |
|----|----------|-------|
| `redis.arbitrary_auth` | arbitrary_auth | Decisive when hit; two random `AUTH` passwords both `+OK` |
| `redis.persist` / `redis.dbsize` | state_nonpersist | Key vanishes on reconnect; `DBSIZE` ignores successful `SET` |
| `redis.auth_wall` | static_signature | OpenCanary-class: always-invalid `AUTH` + `COMMAND` `NOAUTH` |
| `redis.command_stub` / `redis.info_frozen` / `redis.ping_stub` | static_signature | Catalog / clock / `PING` facades (high fidelity) |
| `redis.quit_zombie` / `redis.arity_facade` / `redis.echo_mismatch` | static_signature | Session + parser fidelity |
| `redis.eval_stub` / `redis.config_stub` / `redis.type_stub` / `redis.incr_stub` | static_signature | Command-shape stubs |

Full indicator list, probe flow, safe-mode, and non-destructive policy: [`REDIS.md`](REDIS.md).

### Elasticsearch API non-compliance (basic probe)

Elasticsearch uses **all three** basic strategies (read-only HTTP JSON API plus dual
synthetic Basic and cluster-identity state checks). Prefer path/method/endpoint
facade and auth/state tells over banner IOCs alone — full strategy narrative and
probe flow: [`ELASTICSEARCH.md`](ELASTICSEARCH.md).

| ID | Category | Notes |
|----|----------|-------|
| `elasticsearch.arbitrary_auth` | arbitrary_auth | Decisive when hit; two entropy-varied Basic both 200 ES root on `GET /` |
| `elasticsearch.state_nonpersist` | state_nonpersist | Root UUID/version mismatches `/_nodes` or `/_cluster/health` |
| `elasticsearch.missing_index_ok` / `path_facade` / `method_stub` | static_signature | High-fidelity API non-compliance |
| `elasticsearch.cluster_health_stub` / `cat_stub` | static_signature | Health/cat endpoints echo root instead of proper shapes |
| `elasticsearch.content_type` / `product_header` | static_signature | Wrong Content-Type; modern version without `X-Elastic-Product` |
| `elasticsearch.stock_cluster` | static_signature | Stock cluster_name / version / tagline / uuid (may be corroboration-gated) |
| `elasticsearch.root_framing` | static_signature | Non-speaker / malformed root document |

Full indicator list, ports, safe-mode, and non-destructive policy: [`ELASTICSEARCH.md`](ELASTICSEARCH.md).

### IPP / CUPS non-compliance (basic probe)

IPP uses **all three** basic strategies (HTTP+IPP with TLS fallback). Prefer
CUPS/IPP facade and auth/state tells over banner IOCs alone — see [`IPP.md`](IPP.md).

| ID | Category | Notes |
|----|----------|-------|
| `ipp.arbitrary_auth` | arbitrary_auth | Decisive when hit; two entropy-varied Basic both unlock `/admin` |
| `ipp.state_nonpersist` | state_nonpersist | Illegal-op still successful-ok · ghost printer drifts across reconnect |
| `ipp.ipp_clone` | static_signature | Decisive when hit (bitwise-identical IPP bodies) |
| `ipp.root_framing` / `ipp_framing` / `ghost_printer` / `request_id` / `illegal_op` | static_signature | High fidelity HTTP/IPP tells |
| `ipp.path_facade` / `method_stub` / `printers_stub` / `admin_open` | static_signature | Path/method/admin façades |
| `ipp.server_header` / `frozen_date` / `stock_body` | static_signature | Lure / clock (often corroboration-gated) |

Full indicator list, ports, safe-mode, and non-destructive policy: [`IPP.md`](IPP.md).

**Corroboration bonus**: +5% per protocol beyond the first (max +35%).

**High-signal bonus**: +15% when any triggered indicator has `fidelity` of `high` or
`decisive` (set on the `Indicator`, not a hardcoded ID list). Examples:
`ssh.kex_facade`, `pop3.auth_failed_blanket`, `imap.auth_failed_blanket`,
`redis.arbitrary_auth`, `snmp.arbitrary_community`.

The calculation is additive and capped:

```text
min(category contributions (+ intra-category) + bonuses, 100)
```

Repeated arbitrary authentication for two independent synthetic users is a decisive override to 100%.
Suppressed, skipped, and non-triggered indicators contribute zero. Passive-intel plugins may only use
categories `shodan` (scores via the existing passive weight) or `info` (**never scores**). They cannot
create higher-weight categories such as `arbitrary_auth`.

## Scoped / Normalized Honeyscore (`-p`)

On **targeted single-port** audits (exactly one TCP port in the scan surface), reports also
include a **scoped** score that normalizes global contributions against the sum of
*in-scope* category weights (basic strategies the probed protocol can exercise, plus any
other category that was actually attempted):

```text
scoped = (category_total + bonuses) / (Σ in_scope_weights × 100) × 100
```

Auth-gated skips (for example SSH state checks after failed login) remain in the
denominator so a single-port audit is not over-normalized.
Example: POP3-only `-p 110` with attempted weights 0.75 and raw contribution 42.5% →
scoped ≈ 56.7%. Console, JSON (`scoped_score`), and SARIF expose both global and scoped.
Threat level uses `max(global, scoped)` when scoped applies.

## Score explanation in reports

Every JSON host report has `schema_version: "1.0"` and a `score_breakdown` object containing:

- each active category's weight, attempted state, triggered state, hit count,
  intra-category bonus, and contribution;
- each applied bonus and its contribution;
- optional `scoped` block for single-port audits;
- totals before and after the 100% cap;
- whether the decisive repeated-auth override applied; and
- the final score.

Each serialized indicator also has a four-state `status` (`clear`, `triggered`, `skipped`, or
`suppressed`), its `skip_reason`, `fidelity`, and structured `provenance`. This prevents an
unavailable probe from being mistaken for a clean result.

### Verbose console (`-v`)

Default output is the score panel (global Honeyscore, scoped when `-p` is a single port,
confidence, tactical action, threat level). With `-v` / `--verbose` the console also prints:

1. **Strategy contributions** — weight, hit count, intra-category bonus, hit/skip mark, contribution
2. **Score formula** — `categories + bonuses = raw → global`, plus listed bonuses and intra lines
3. **Scoped formula** (single-port only) — `(numerator / in-scope denominator) × 100`
4. **Protocol strategies** — per-face HIT / clean / skip / —
5. **Indicators** — status, fidelity, protocol, finding, detail
6. **Why this score** — triggered tells with fidelity tags

**Verdict bands** (effective score = max(global, scoped) when scoped applies):

| Band | Condition |
|------|-----------|
| Confirmed Honeypot | ≥60% |
| Suspected Honeypot | 30–59% |
| Inconclusive (Low-confidence anomalies detected) | &lt;30% **and** ≥1 unsuppressed triggered tell |
| Likely Real Host | &lt;30% **and** zero triggered tells |
| Inconclusive | No attempted probes |

## Confidence

Orthogonal to Honeyscore — measures probe breadth:

| Level | Heuristic |
|-------|-----------|
| Low | &lt;3 protocols, single indicator, or &gt;50% skipped |
| Medium | 3+ protocols, 2+ categories |
| High | 5+ protocol hits, or deep with 3+ deep categories |

High-fidelity tells alone raise low → medium confidence.

## Tactical action (red team)

Priority matrix (Honeyscore × Confidence × proxy):

| Action | When |
|--------|------|
| `INCONCLUSIVE` | Proxy detected, or &gt;50% skipped |
| `SKIP_TARGET` | Score ≥60%, confidence medium/high, no proxy |
| `PROCEED_CAUTION` | Ambiguous, low-confidence high score, or anomalies below Suspected |
| `PIVOT_POSSIBLE` | Score &lt;30%, **no** triggered tells, confidence medium/high |

## Capability degradation

When raw sockets or Scapy are unavailable, SYN-ACK and fixed ClientHello probes degrade gracefully; warnings appear in `capability_warnings`.
