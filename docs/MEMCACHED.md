# Memcached probe

Honeypot-auditor’s Memcached engine speaks the classic **ASCII text protocol**
over **TCP/11211** (lab alias **21211**). Binary/meta protocol is out of scope
for speakership (a light binary/SASL frame may be used as auth evidence only).

It targets Dionaea / multi-service decoy Memcached stubs with **protocol
non-compliance**: malformed `VERSION`/`stats` framing, unknown-command façades,
fake cache hits on missing keys, bitwise-identical canned `stats`, and stock
version lures. It also checks dual entropy-varied probe-key `set` acceptance and
probe-key persistence across reconnect. It does **not** rely on banner IOC lists
alone.

## Strategies

Memcached activates **all three** basic scoring strategies
(`PROTOCOL_STRATEGIES["memcached"]`):

| Strategy | Why it applies to Memcached |
|----------|-----------------------------|
| **arbitrary_auth** | Two entropy-varied ASCII `set` writes both `STORED` (optional binary/SASL mishandling as corroborating evidence). Indicator: `memcached.arbitrary_auth`. |
| **state_nonpersist** | Probe-key `set` then reconnect `get` miss / `stats` ignore the write. Indicator: `memcached.state_nonpersist`. |
| **static_signature** | Version/stats framing, unknown-command ERROR fidelity, get-miss END, gets/CAS façade, canned stats clones, stock VERSION strings, verbosity/noreply façades. |

Detection philosophy:

1. **Baseline speakership** — `version` must look like Memcached ASCII
   (`VERSION` / `ERROR` / `STAT` / `END` / `OK` / `VALUE` / `CLIENT_ERROR` /
   `SERVER_ERROR`). Otherwise the suite is skipped.
2. **Framing** — `version` → `VERSION <token>`; `stats` → `STAT …` lines
   terminated by `END`.
3. **Command fidelity** — unknown tokens and bare `verbosity` must return
   `ERROR` (never `OK`/`VERSION`). Missing-key `get` must return `END` only.
4. **Canned clock** — two independent `stats` replies that are
   bitwise-identical are a decisive façade.
5. **Dual set façade** — two entropy-varied probe keys both `STORED` scores
   `memcached.arbitrary_auth` (keys are deleted immediately after).
6. **Persistence** — a probe-key `set` that vanishes on reconnect `get`, or
   whose write is ignored by `stats`, scores `memcached.state_nonpersist`.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `version` | `flush_all` / `flush_all noreply` |
| `stats`, `stats settings` | `stats reset`, slab reassign |
| `get` of a random `hpaudit_*` miss key | Large multi-get walks |
| Probe-key `set` / `delete` of short-lived `hpa_*` keys only | Authentication dictionary spraying |
| Bare `verbosity` (ERROR expected) | Writes outside the probe-key namespace |
| `verbosity 0 noreply` (quiet expected) | |

**Probe-key `set` / `delete` are allowed** for auth and state checks. Destructive
`flush_all` behaviour is **never** probed. Bare `verbosity` (wrong arity) remains
the non-destructive stand-in for “accepts anything / flush stub” façades
(`memcached.flush_stub`).

## Ports

| Port | Mode |
|------|------|
| 11211 | Production Memcached (TCP) |
| 21211 | Docker / lab research alias |

## Probe flow

```text
version  ──►  ASCII speakership (+ version_framing / stock_version)
        │
        ├─ safe-mode ──► stop (version_framing only)
        │
        ├─ stats → stats_framing
        ├─ foo → unknown_command (must ERROR)
        ├─ get hpaudit_* → get_miss (must END, not VALUE)
        ├─ stats again → stats_clone (bitwise identity)
        ├─ verbosity (no level) → flush_stub stand-in (must ERROR)
        ├─ verbosity 0 noreply → noreply_facade (must stay quiet)
        ├─ dual entropy-varied set (+ optional binary frame) → arbitrary_auth
        └─ probe-key set → pause → get / stats → state_nonpersist
```

## Indicators

### Arbitrary auth

| ID | Category | Trigger |
|----|----------|---------|
| `memcached.arbitrary_auth` | arbitrary_auth | Two entropy-varied ASCII `set` writes both return `STORED` (binary/SASL mishandling may appear in detail). Fidelity **decisive** when hit. Probe keys are deleted after the check. |

### State non-persistence

| ID | Category | Trigger |
|----|----------|---------|
| `memcached.state_nonpersist` | state_nonpersist | Probe-key `set` then reconnect `get` miss and/or `stats` ignore the write. Fidelity **high** when hit. Skipped if `set` was rejected. |

### Static / ASCII conformance

| ID | Trigger |
|----|---------|
| `memcached.version_framing` | `version` reply is not a well-formed `VERSION <token>` line. |
| `memcached.stats_framing` | `stats` reply lacks `STAT`/`END` shape (or answers with `VERSION`/`OK` only). |
| `memcached.unknown_command` | Garbage command (`foo`) returns `OK`/`VERSION`/… instead of `ERROR`. |
| `memcached.get_miss` | `get` of a fresh missing key returns `VALUE` instead of bare `END`. |
| `memcached.cas_facade` | `gets` of a just-stored probe key returns a `VALUE` line without the mandatory numeric `cas_unique` token (skins implement `get` only). An `END` there is left to `state_nonpersist`. |
| `memcached.stats_clone` | Two independent `stats` replies are **bitwise-identical**. Fidelity **decisive** when hit. |
| `memcached.stock_version` | `VERSION` token matches a stock honeypot lure. Generic/common versions are corroboration-gated; decisive lure tokens score alone. |
| `memcached.flush_stub` | Bare `verbosity` (no level) returns success instead of `ERROR` — non-destructive stand-in for flush-accept stubs. **Never sends `flush_all`.** |
| `memcached.noreply_facade` | `verbosity 0 noreply` still returns a body (`OK`/…) instead of staying quiet. |

## Safe mode

`--safe-mode` / `safe_mode`: only `version` speakership +
`memcached.version_framing` are evaluated. Stats, get, unknown-command, clone,
stock, verbosity, noreply, auth, and state probes are skipped.

## Spec references

- [Memcached ASCII protocol](https://github.com/memcached/memcached/blob/master/doc/protocol.txt)
- Commands: `version`, `stats`, `get`, `set`, `delete`, `verbosity`, quiet/`noreply`
- IANA: 11211/tcp Memcached
