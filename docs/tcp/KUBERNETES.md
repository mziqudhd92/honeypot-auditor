# Kubernetes API probe

Honeypot-auditor’s Kubernetes engine speaks the **Kubernetes API server** HTTP(S)
surface on **6443** (lab **16443**). It prefers **TLS** on those ports (IMAPS-style
implicit TLS), matching how real apiservers present themselves.

It targets low-interaction kube-API skins with **API / protocol non-compliance**
checks: agents that ignore path and method, echo `/version` everywhere, or
advertise stock lure `gitVersion` / `platform` metadata. It does **not** create
workloads, exec into pods, proxy, or delete anything.

## Strategies

Kubernetes activates **all three** basic scoring strategies
(`PROTOCOL_STRATEGIES["kubernetes"]`):

| Strategy | Why it applies to Kubernetes |
|----------|------------------------------|
| **arbitrary_auth** | Anonymous `GET /version` is **401/403**, then two entropy-varied Bearer tokens both return a version document. An already-open anonymous `/version` is not a bypass. Indicator: `kubernetes.arbitrary_auth`. |
| **state_nonpersist** | `/version` `gitVersion`/`gitCommit` drifts across reconnect, or `/apis` contradicts discovery identity. Indicator: `kubernetes.state_nonpersist`. |
| **static_signature** | Decoy kube-API faces are almost always canned HTTP handlers: `/livez`/`/healthz` that are not `ok`, unparseable `/version`, `/api` that is not `APIVersions`, `/apis` that is not `APIGroupList`, unknown paths that return version-shaped **200**, `DELETE /version` ignored, stock `gitVersion`/`platform` lures, or unauthenticated `/api/v1` that dumps object lists (pods/secrets) instead of discovery. |

Detection philosophy:

1. **Baseline speakership** — `/livez` or `/healthz` should return **200** with body
   `ok`, and/or `GET /version` must parse as a version document (`major`, `minor`,
   `gitVersion`). Anything else is framing (or a suite skip on connection failure),
   unless a 401/403 challenge is unlocked by dual Bearer.
2. **Discovery shape** — `GET /api` must look like `APIVersions` (`kind` + `versions`);
   `GET /apis` must look like `APIGroupList` (`kind` + `groups`).
3. **Path and method fidelity** — unknown routes must not echo `/version` at **200**;
   `DELETE /version` must not return the GET version document.
4. **Unauthenticated discovery** — `GET /api/v1` returning `kind=APIResourceList`
   (or **401**/**403**) is normal. A **200** `PodList` / secrets-shaped object list
   without auth is the tell.
5. **Dual Bearer façade** — anonymous `/version` must challenge (401/403) and both
   entropy-varied Bearer tokens then return a version document to score
   `kubernetes.arbitrary_auth`. An already-open anonymous version is not a bypass.
6. **Identity coherence** — reconnect `/version` drift, or `/apis` returning a
   version document, scores `kubernetes.state_nonpersist`.
7. **Lure metadata last** — decisive lure tokens in `gitVersion` / `platform`
   (honeypot names) score alone. Common frozen demo versions
   (`v1.18.0`, …) set `requires_corroboration` unless mixed with a decisive token.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `GET /livez` · `GET /healthz` | Create / update / delete pods, secrets, or any objects |
| `GET /version` (optional Bearer) | `exec`, `attach`, `portforward`, `proxy` |
| `GET /api` · `GET /apis` | Token review / authn dictionary spray |
| `GET /_hpa_nonexistent_*` | Watch streams or large list dumps of cluster data |
| `DELETE /version` only (method probe) | Deletes of any namespaced/cluster resource |
| `GET /api/v1` (discovery only) | `GET /api/v1/pods`, `/secrets`, or other collection lists |

## Ports

| Port | Mode |
|------|------|
| 6443 | Production Kubernetes API server (TLS preferred) |
| 16443 | Lab Kubernetes API server (TLS preferred) |

## Probe flow

```text
GET /livez (fallback /healthz)  ──►  health framing (body == ok)
GET /version                    ──►  version framing (major/minor/gitVersion)
        │                            (401/403 → dual Bearer unlock path)
        ├─ safe-mode ──► stop (health + version framing only)
        │
        ├─ stock gitVersion/platform → stock_version
        ├─ GET /api → api_framing
        ├─ GET /apis → apis_framing
        ├─ GET /_hpa_nonexistent_* → path_facade
        ├─ DELETE /version → method_stub
        ├─ GET /api/v1 → unauthenticated_ok
        ├─ anon 401/403 then dual Bearer → arbitrary_auth
        └─ reconnect /version + /apis → state_nonpersist
```

## Indicators

### Arbitrary auth / Bearer façade

| ID | Category | Trigger |
|----|----------|---------|
| `kubernetes.arbitrary_auth` | arbitrary_auth | Anonymous `GET /version` challenged 401/403, then two entropy-varied Bearer tokens both return a version document. Fidelity **decisive** when hit. |

### State non-persistence

| ID | Category | Trigger |
|----|----------|---------|
| `kubernetes.state_nonpersist` | state_nonpersist | `/version` `gitVersion`/`gitCommit` drifts across reconnect, or `/apis` contradicts discovery (pure `/apis` shape failures are scored as `apis_framing` instead). Fidelity **high** when hit. |

### Speakership / framing (static_signature)

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `kubernetes.health_framing` | Speakership | `/livez` and `/healthz` do not return **200** with body `ok`. |
| `kubernetes.version_framing` | Speakership | `GET /version` is not parseable as `major` / `minor` / `gitVersion`. |
| `kubernetes.api_framing` | Discovery shape | `GET /api` is not `APIVersions`-shaped (`kind` + `versions`). |
| `kubernetes.apis_framing` | Discovery shape | `GET /apis` is not `APIGroupList`-shaped (`kind` + `groups`). |

### Path / method / auth facades

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `kubernetes.path_facade` | Route facade | Unknown API path returns **200** version-shaped JSON. Fidelity **high** when hit. |
| `kubernetes.method_stub` | Method facade | `DELETE /version` returns a version document at **200** (verb ignored). Fidelity **high** when hit. |
| `kubernetes.unauthenticated_ok` | Auth facade | `GET /api/v1` returns **200** with a secrets/pods-shaped object list (`PodList`, `SecretList`, or `items` of secrets) instead of `APIResourceList` or **401**/**403**. Fidelity **high** when hit. |

### Lure metadata

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `kubernetes.stock_version` | Lure banner | `gitVersion` / `platform` match stock lure tokens. **Decisive** alone: honeypot name substrings (`kube-honeypot`, `honey-kube`, …). **Corroboration-gated** alone: frozen demo versions (`v1.18.0`, `v1.16.0`, …). A decisive token on the same document lifts the gate. |

## Safe mode

`--safe-mode` / `safe_mode`: only health and version framing are evaluated.
API/apis framing, path/method stubs, stock metadata, `/api/v1`, auth, and state
checks are skipped.

## Example

```bash
honeypot-auditor --target HOST -p 6443 --confirm-authorized -v
# lab alias
honeypot-auditor --target 127.0.0.1 -p 16443 -v
```

## Spec references

- [Kubernetes API Concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/)
- [API health endpoints (`/livez`, `/readyz`, `/healthz`)](https://kubernetes.io/docs/reference/using-api/health-checks/)
- [Version info (`/version`)](https://kubernetes.io/docs/reference/config-api/apiserver-config/)
- Discovery: `/api`, `/apis`, `/api/v1` (`APIVersions`, `APIGroupList`, `APIResourceList`)
- IANA-style kube-apiserver port **6443** (lab **16443**)

## Scoring

`PROTOCOL_STRATEGIES["kubernetes"]` activates **all three** basic strategies.
High-signal examples when triggered: `path_facade`, `method_stub`,
`unauthenticated_ok`, `apis_framing`, `state_nonpersist` (`high`);
`arbitrary_auth` (`decisive`). Stock versions may require corroboration.
See [`SCORING.md`](SCORING.md).
