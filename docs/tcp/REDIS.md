# Redis probe

Honeypot-auditor’s Redis engine speaks **RESP** (Redis Serialization Protocol)
over **TCP/6379** (lab uses the same port in the default presets).

It targets OpenCanary / Beehive-class Redis stubs with **protocol non-compliance**
and light state checks: services that accept any `AUTH`, freeze `INFO`, omit core
commands, or fail to persist keys. It does **not** rely on banner IOC lists alone.

## Strategies

Redis activates all three basic scoring strategies
(`PROTOCOL_STRATEGIES["redis"]`):

| Strategy | Why it applies to Redis |
|----------|-------------------------|
| **arbitrary_auth** | `AUTH` is the credential gate. Real Redis rejects unknown passwords (or reports that no password is configured). Decoys often return `+OK` for any string. |
| **state_nonpersist** | In-memory stubs often accept `SET` then lose the key on reconnect, or leave `DBSIZE` unchanged. |
| **static_signature** | Most Redis honeypot tells are RESP facades: `COMMAND`/`EVAL`/`CONFIG` stubs, frozen `INFO`, redis-cli `HELP` text, missing `ECHO`/`SELECT`, OpenCanary AUTH+NOAUTH wall, arity/`TYPE`/`INCR` facades, QUIT zombies. |

Detection philosophy:

1. **Baseline speakership** — `PING` must look like RESP (`+`/`-`/`:`/`$`/`*`). Otherwise the suite is skipped.
2. **Auth dual-probe** — two independent random passwords must *both* return `+OK` before `arbitrary_auth` fires.
3. **Catalog & clock fidelity** — `COMMAND`, `INFO` (twice), `HELP`, `ECHO`/`SELECT`, `EVAL`, `CONFIG GET`, wrong-arity `GET`.
4. **Session / type fidelity** — same-connection `QUIT` then `PING`; after a probe `SET`, check `DBSIZE` / `TYPE` / `INCR` / reconnect `GET`.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `PING`, `AUTH` (two synthetics), `COMMAND`, `INFO`, `HELP` | `FLUSHALL` / `FLUSHDB` |
| `ECHO`, `SELECT 0`, `EVAL return 1`, `CONFIG GET *` | `CONFIG SET`, `SCRIPT LOAD`, `SLAVEOF` / `REPLICAOF` |
| Ephemeral `SET`/`GET`/`TYPE`/`INCR`/`DEL` under `hpaudit_*` | `KEYS *`, `SCAN` of large keyspaces |
| Same-session `QUIT` + follow-up `PING` | Password spraying beyond two synthetics |

## Ports

| Port | Mode |
|------|------|
| 6379 | Production Redis (TCP) |

## Probe flow

```text
PING  ──►  RESP speakership (+ optional PING stub)
        │
        ├─ safe-mode ──► stop (ping_stub only)
        │
        ├─ AUTH pw1 + AUTH pw2 → arbitrary_auth (both +OK)
        ├─ COMMAND / INFO×2 / HELP / ECHO / SELECT / EVAL / CONFIG GET
        ├─ GET (no args) → arity_facade
        ├─ same session: QUIT then PING → quit_zombie
        └─ DBSIZE → SET hpaudit_* → DBSIZE / TYPE / INCR / GET / DEL
```

## Indicators

### Arbitrary auth

| ID | Trigger |
|----|---------|
| `redis.arbitrary_auth` | Two independent random `AUTH` passwords both receive `+OK`. Fidelity **decisive** when hit. |

`AUTH` without any password configured, `WRONGPASS`, and OpenCanary `invalid password` are **not** scored as arbitrary auth.

### State

| ID | Trigger |
|----|---------|
| `redis.persist` | After a successful `SET`, reconnect `GET` misses the value / returns null bulk. Fidelity **high** when hit. |
| `redis.dbsize` | After a successful `SET`, `DBSIZE` stays flat (or returns `+OK`). Non-destructive stand-in for flush stubs. |

### Static / RESP conformance

| ID | Trigger |
|----|---------|
| `redis.ping_stub` | `PING` returns `+OK` (or other non-`+PONG` success) instead of `+PONG`. |
| `redis.command_stub` | `COMMAND` returns `+OK` or unknown instead of a catalog array. |
| `redis.info_frozen` | `INFO` clock is a stale snapshot, or `server_time_usec` / `total_commands_processed` do not move across calls. |
| `redis.help_client` | `HELP` returns redis-cli / `.redisclirc` client text. |
| `redis.core_missing` | `ECHO` and/or `SELECT` are unknown commands. |
| `redis.eval_stub` | `EVAL` returns `+OK` or unknown instead of executing Lua. |
| `redis.config_stub` | `CONFIG GET` returns `+OK` / wrong-arity / unknown instead of parameters. |
| `redis.auth_wall` | `AUTH` always `invalid password` and `COMMAND` is `NOAUTH` (OpenCanary-class). |
| `redis.echo_mismatch` | `ECHO` returns `+OK` / null / wrong payload (when not “unknown”). |
| `redis.incr_stub` | `INCR` on a fresh probe key returns `+OK` instead of an integer. |
| `redis.type_stub` | `TYPE` on a string probe key is not `+string`. |
| `redis.arity_facade` | `GET` with no arguments returns `+OK` (or a value) instead of wrong-arity. |
| `redis.quit_zombie` | After `QUIT +OK`, the same TCP session still answers `PING`. |

## Safe mode

`--safe-mode` / `safe_mode`: only `PING` speakership + `redis.ping_stub` are evaluated.
Auth, catalog, state, and session probes are skipped.

## Spec references

- [Redis protocol (RESP)](https://redis.io/docs/reference/protocol-spec/)
- [Redis commands](https://redis.io/commands/) — `PING`, `AUTH`, `COMMAND`, `INFO`, `ECHO`, `QUIT`
- IANA: 6379/tcp Redis
