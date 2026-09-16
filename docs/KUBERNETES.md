# Kubernetes API probe

Honeypot-auditor’s Kubernetes engine speaks the **Kubernetes API server** HTTP(S)
surface on **6443** (lab **16443**). It prefers **TLS** on those ports (IMAPS-style
implicit TLS), matching how real apiservers present themselves.

It targets low-interaction kube-API skins with **API / protocol non-compliance**
checks: agents that ignore path and method, echo `/version` everywhere, or
advertise stock lure `gitVersion` / `platform` metadata. It does **not** create
workloads, exec into pods, proxy, or delete anything.

## Strategies

Kubernetes activates **one** of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["kubernetes"]`):

| Strategy | Why it applies to Kubernetes |
|----------|------------------------------|
| **static_signature** | Primary axis. Decoy kube-API faces are almost always canned HTTP handlers: `/livez`/`/healthz` that are not `ok`, unparseable `/version`, `/api` that is not `APIVersions`, unknown paths that return version-shaped **200**, `DELETE /version` ignored, stock `gitVersion`/`platform` lures, or unauthenticated `/api/v1` that dumps object lists (pods/secrets) instead of discovery. |
| **arbitrary_auth** | **Not used** on the basic read-only path. No token/password spraying against the apiserver. |
| **state_nonpersist** | **Not used.** There is no session resume surface on these discovery/health endpoints. |

Detection philosophy:

1. **Baseline speakership** — `/livez` or `/healthz` should return **200** with body
   `ok`, and/or `GET /version` must parse as a version document (`major`, `minor`,
   `gitVersion`). Anything else is framing (or a suite skip on connection failure).
2. **Discovery shape** — `GET /api` must look like `APIVersions` (`kind` + `versions`).
3. **Path and method fidelity** — unknown routes must not echo `/version` at **200**;
   `DELETE /version` must not return the GET version document.
4. **Unauthenticated discovery** — `GET /api/v1` returning `kind=APIResourceList`
   (or **401**/**403**) is normal. A **200** `PodList` / secrets-shaped object list
   without auth is the tell.
5. **Lure metadata last** — decisive lure tokens in `gitVersion` / `platform`
   (honeypot names) score alone. Common frozen demo versions
   (`v1.18.0`, …) set `requires_corroboration` unless mixed with a decisive token.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `GET /livez` · `GET /healthz` | Create / update / delete pods, secrets, or any objects |
| `GET /version` | `exec`, `attach`, `portforward`, `proxy` |
| `GET /api` · `GET /apis` | Token review / authn spraying |
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
        │
        ├─ safe-mode ──► stop (health + version framing only)
        │
        ├─ stock gitVersion/platform → stock_version
        ├─ GET /api → api_framing
        ├─ GET /_hpa_nonexistent_* → path_facade
        ├─ DELETE /version → method_stub
        └─ GET /api/v1 → unauthenticated_ok
```

## Indicators

All indicators are category **`static_signature`**.

### Speakership / framing

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `kubernetes.health_framing` | Speakership | `/livez` and `/healthz` do not return **200** with body `ok`. |
| `kubernetes.version_framing` | Speakership | `GET /version` is not parseable as `major` / `minor` / `gitVersion`. |
| `kubernetes.api_framing` | Discovery shape | `GET /api` is not `APIVersions`-shaped (`kind` + `versions`). |

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
API framing, path/method stubs, stock metadata, and `/api/v1` checks are skipped.

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

`PROTOCOL_STRATEGIES["kubernetes"]` activates **static_signature** only.
High-signal examples when triggered: `path_facade`, `method_stub`,
`unauthenticated_ok` (`high`). Stock versions may require corroboration.
See [`SCORING.md`](SCORING.md).
