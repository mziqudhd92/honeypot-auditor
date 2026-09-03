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

**High-signal bonus**: +15% when a highly specific pre-auth fingerprint fires
(`ssh.kex_facade`, `pop3.auth_failed_blanket`). Multiple indicators in the *same*
category (e.g. POP3 stock banner + auth-failed blanket) still only unlock that
category's weight once — the high-signal bonus is how those fingerprints clear
the Suspected band without inventing a second category.

The calculation is additive and capped:

```text
min(category contributions + bonuses, 100)
```

Repeated arbitrary authentication for two independent synthetic users is a decisive override to 100%.
Suppressed, skipped, and non-triggered indicators contribute zero. Passive-intel plugins may only use
categories `shodan` (scores via the existing passive weight) or `info` (**never scores**). They cannot
create higher-weight categories such as `arbitrary_auth`.

## Score explanation in reports

Every JSON host report has `schema_version: "1.0"` and a `score_breakdown` object containing:

- each active category's weight, attempted state, triggered state, and contribution;
- each applied bonus and its contribution;
- totals before and after the 100% cap;
- whether the decisive repeated-auth override applied; and
- the final score.

Each serialized indicator also has a four-state `status` (`clear`, `triggered`, `skipped`, or
`suppressed`), its `skip_reason`, and structured `provenance`. This prevents an unavailable probe from
being mistaken for a clean result. Verbose console output prints the same formula and contribution data.

**Verdict bands**: &lt;30% Likely Real · 30–59% Suspected · ≥60% Confirmed.

## Confidence

Orthogonal to Honeyscore — measures probe breadth:

| Level | Heuristic |
|-------|-----------|
| Low | &lt;3 protocols, single indicator, or &gt;50% skipped |
| Medium | 3+ protocols, 2+ categories |
| High | 5+ protocol hits, or deep with 3+ deep categories |

## Tactical action (red team)

Priority matrix (Honeyscore × Confidence × proxy):

| Action | When |
|--------|------|
| `INCONCLUSIVE` | Proxy detected, or &gt;50% skipped |
| `SKIP_TARGET` | Score ≥60%, confidence medium/high, no proxy |
| `PROCEED_CAUTION` | Ambiguous or low-confidence high score |
| `PIVOT_POSSIBLE` | Score &lt;30%, confidence medium/high |

## Capability degradation

When raw sockets or Scapy are unavailable, SYN-ACK and fixed ClientHello probes degrade gracefully; warnings appear in `capability_warnings`.
