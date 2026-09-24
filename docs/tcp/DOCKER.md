# Docker Engine API probe

Honeypot-auditor’s Docker engine speaks the **Docker Engine HTTP API** on
**2375** (lab **12375**). TLS-protected Engine API on **2376** is out of scope
for v1 (`docker.tls_hint_mismatch` is always skipped).

It targets canned “open Docker daemon” stubs with **API / protocol
non-compliance** checks: agents that ignore path and method, echo version/info
JSON everywhere, or advertise stock lure version metadata. It does **not** rely
on product-named honeypot IOC lists alone, and it never creates containers,
pulls images, or writes volumes/networks.

## Strategies

Docker activates **all three** basic scoring strategies
(`PROTOCOL_STRATEGIES["docker"]`):

| Strategy | Why it applies to Docker |
|----------|--------------------------|
| **arbitrary_auth** | Anonymous `GET /version` is **401/403**, then two entropy-varied Basic headers both return Engine version JSON. An already-open anonymous `/version` is not a bypass. Indicator: `docker.arbitrary_auth`. |
| **state_nonpersist** | After reconnect, `/version` `Version` mismatches `/info` `ServerVersion`. Indicator: `docker.state_nonpersist`. |
| **static_signature** | Decoy Engine faces are almost always canned HTTP handlers: wrong `/_ping` body, non-version JSON on `/version`, unknown paths that return version/info-shaped **200**, DELETE/PUT on `/_ping` that still return **200 OK**, thin `/info` stubs that echo `/version`, `/containers/json` that echoes version/info instead of a list, or stock `ApiVersion` / `Version` / `GitCommit` lure metadata. |

Detection philosophy:

1. **Baseline speakership** — `GET /_ping` must return plain-text **OK**;
   `GET /version` must return parseable Docker version JSON with Engine shape
   beyond bare `ApiVersion` + `Version` (at least two additional version-document
   fields). Thin `{"ApiVersion","Version"}` stubs are **not** speakers.
   Connection failure skips the suite; non-version `/version` skips deep probes
   after framing (unless a 401/403 challenge is unlocked by dual Basic).
2. **Path and method fidelity** — real daemons 404 unknown routes and do not
   treat DELETE/PUT on `/_ping` as a successful ping. Stubs that return **200**
   version/info JSON (or ping **OK**) for every verb/path are the core tell.
3. **Endpoint shape checks** — `GET /info` must look like system info (`ID`,
   container/image counts, `Driver`, `Name`, …), not a thin echo of `/version`.
   `GET /containers/json` must be a JSON **array**.
4. **Dual Basic façade** — anonymous `/version` must challenge (401/403) and both
   entropy-varied Basic headers then return Engine version JSON to score
   `docker.arbitrary_auth`. An already-open anonymous version is not a bypass.
5. **Version coherence** — `/version` `Version` that contradicts `/info`
   `ServerVersion` scores `docker.state_nonpersist`.
6. **Lure metadata last** — decisive lure tokens (canned `GitCommit` like
   `deadbeef`, absurd/frozen version strings) score alone. Generic still-common
   `ApiVersion` / `Version` values (including historically common `ApiVersion`
   **1.0**) set `requires_corroboration` unless mixed with a decisive token on
   the same version document — they are never decisive alone.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `GET /_ping` | Container create / start / stop / kill |
| `GET /version` (optional Basic) | Image pull / build / push / load |
| `GET /info` (read-only) | Exec / attach / hijack streams |
| `GET /containers/json` (list only) | Volume / network / swarm writes |
| `GET /_hpa_nonexistent_*` | Registry auth dictionary spray |
| `DELETE` / `PUT` on `/_ping` only | |

## Ports

| Port | Mode |
|------|------|
| 2375 | Production Docker Engine API (plain HTTP) |
| 12375 | Lab Docker Engine API (plain HTTP) |
| 2376 | TLS Engine API — **out of scope** (v1) |

## Probe flow

```text
GET /_ping  ──►  ping framing (body must be OK)
GET /version ──►  version framing (ApiVersion + Version)
        │         (401/403 → dual Basic unlock path)
        ├─ safe-mode ──► stop (ping + version framing only)
        │
        ├─ stock ApiVersion/Version/GitCommit → stock_version
        ├─ GET /_hpa_nonexistent_* → path_facade
        ├─ DELETE /_ping · PUT /_ping → method_stub
        ├─ GET /info → info_stub
        ├─ GET /containers/json → containers_stub
        ├─ anon 401/403 then dual Basic → arbitrary_auth
        ├─ /version vs /info ServerVersion → state_nonpersist
        └─ tls_hint_mismatch → always skipped (2376 out of scope)
```

## Indicators

### Arbitrary auth / Basic façade

| ID | Category | Trigger |
|----|----------|---------|
| `docker.arbitrary_auth` | arbitrary_auth | Anonymous `GET /version` challenged 401/403, then two entropy-varied Basic credentials both return Engine version JSON. Fidelity **decisive** when hit. |

### State non-persistence

| ID | Category | Trigger |
|----|----------|---------|
| `docker.state_nonpersist` | state_nonpersist | `/version` `Version` mismatches `/info` `ServerVersion` after reconnect. Denied/unavailable `/info` is **skipped**. Fidelity **high** when hit. |

### Speakership / framing (static_signature)

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `docker.ping_framing` | Speakership | `GET /_ping` is not HTTP 200 with plain-text body `OK` (optional trailing newline allowed). |
| `docker.version_framing` | Speakership | `GET /version` is not parseable Docker version JSON with Engine shape beyond bare `ApiVersion` + `Version` strings (requires additional version-document fields). |

### Lure metadata

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `docker.stock_version` | Lure banner | `ApiVersion` / `Version` / `GitCommit` match stock lure tokens. **Decisive** alone: canned commits (`deadbeef`, `0000000`, …), absurd/frozen version strings (`0.0.0`, `honeypot`, …). **Corroboration-gated** alone: common still-deployed `ApiVersion` (`1.0`, `1.40`, `1.41`, …) or `Version` (`18.09.0`, `20.10.0`, …) — `ApiVersion` **1.0** is never decisive by itself. |

### Path / method / endpoint facades

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `docker.path_facade` | Route facade | Unknown API path returns **200** with version- or info-shaped JSON. Fidelity **high** when hit. |
| `docker.method_stub` | Method facade | `DELETE` / `PUT` on `/_ping` return **200 OK** (ping ignored the verb). Fidelity **high** when hit. |
| `docker.info_stub` | Endpoint shape | `GET /info` is missing required system-info fields or echoes the `/version` document. Fidelity **high** when hit. |
| `docker.containers_stub` | Discovery shape | `GET /containers/json` returns version/info-shaped JSON (or non-array) instead of a container list. Fidelity **high** when hit. |

### TLS (deferred)

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `docker.tls_hint_mismatch` | Transport hint | **Skipped** in v1 — TLS Engine API on port **2376** is out of scope. |

## Safe mode

`--safe-mode` / `safe_mode`: only ping and version framing are evaluated.
Path, method, info, containers, stock metadata, auth, state, and TLS-hint
probes are skipped.

## Example

```bash
honeypot-auditor --target HOST -p 2375 --confirm-authorized -v
# lab alias
honeypot-auditor --target 127.0.0.1 -p 12375 -v
```

## Spec references

- [Docker Engine API](https://docs.docker.com/engine/api/) — System ping / version / info
- [Engine API `/_ping`](https://docs.docker.com/reference/api/engine/latest/#tag/System/operation/SystemPing)
- [Engine API `/version`](https://docs.docker.com/reference/api/engine/latest/#tag/System/operation/SystemVersion)
- [Engine API `/info`](https://docs.docker.com/reference/api/engine/latest/#tag/System/operation/SystemInfo)
- [Engine API `/containers/json`](https://docs.docker.com/reference/api/engine/latest/#tag/Container/operation/ContainerList)
- IANA-style plain HTTP Engine API port **2375** (lab **12375**); TLS **2376** out of scope

## Scoring

`PROTOCOL_STRATEGIES["docker"]` activates **all three** basic strategies.
High-signal examples when triggered: `path_facade`, `method_stub`, `info_stub`,
`containers_stub`, `state_nonpersist` (`high`); `arbitrary_auth` (`decisive`).
Stock version metadata may require corroboration. See
[`SCORING.md`](SCORING.md).

## False-positive notes

- Real Docker daemons exposed on **2375** without TLS are a security problem,
  but they still speak compliant `/_ping` / `/version` / `/info` shapes — this
  probe scores **protocol facade** failures, not “open Docker” alone.
- Common `ApiVersion` / `Version` strings appear on production engines; alone
  they are corroboration-gated and suppressed unless another ungated Docker
  tell fires on the same host.
- Proxies that 401/403 `/info` while allowing `/version` are treated as
  inconclusive for `info_stub` / `state_nonpersist` (skipped), not as a honeypot hit.
- Open anonymous Engine API is **not** scored as `arbitrary_auth` (no credential gate).
