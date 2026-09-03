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

**Corroboration bonus**: +5% per protocol beyond the first (max +35%).

**High-signal bonus**: +15% when any triggered indicator has `fidelity` of `high` or
`decisive` (set on the `Indicator`, not a hardcoded ID list). Examples:
`ssh.kex_facade`, `pop3.auth_failed_blanket`.

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
