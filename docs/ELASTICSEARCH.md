# Elasticsearch probe

Honeypot-auditor’s Elasticsearch engine speaks the **HTTP JSON API** on
**9200** (lab **19200**). Transport protocol port **9300** is out of scope.

It targets ElasticHoney-class and similar HTTP stubs with **API / protocol
non-compliance** checks: agents that ignore path and method, echo the root
cluster document everywhere, or advertise stock lure metadata. It does **not**
rely on banner IOC lists alone, and it never writes indices or searches data.

## Strategies

Elasticsearch activates **one** of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["elasticsearch"]`):

| Strategy | Why it applies to Elasticsearch |
|----------|----------------------------------|
| **static_signature** | Primary axis. Decoy “ES” faces are almost always canned HTTP handlers: wrong root shape, stock `cluster_name` / `cluster_uuid` / version, **200** on missing indices, unknown paths that return the root JSON, DELETE/PUT/HEAD that ignore the verb, `/_cluster/health` and `/_cat/health` that echo root instead of health/cat shapes, non-JSON `Content-Type`, or missing `X-Elastic-Product` on modern versions. |
| **arbitrary_auth** | **Not used** on the basic read-only path. No password spraying against `_security` / basic-auth realms (would be noisy and out of the non-destructive policy). |
| **state_nonpersist** | **Not used.** There is no session resume, mailbox, or message bus to contradict — only request/response HTTP API fidelity. |

Detection philosophy:

1. **Baseline speakership** — `GET /` must return a parseable Elasticsearch root
   document (`version.number` plus `tagline` and/or cluster/node name). Anything
   else is framing (or a suite skip on connection failure).
2. **Path and method fidelity** — real clusters 404 unknown indices, reject
   unknown API routes, and do not serve the root document for DELETE/PUT/HEAD on
   `/`. Stubs that return **200** root JSON for every verb/path are the core tell.
3. **Endpoint shape checks** — `/_cluster/health` must look like health
   (`status` ∈ green/yellow/red, node counts); `/_cat/health?format=json` must be
   a JSON **array** (or plain cat text), not the root object.
4. **Transport headers** — JSON bodies should advertise a JSON `Content-Type`;
   versions ≥ 7.14 should send `X-Elastic-Product: Elasticsearch`.
5. **Lure metadata last** — stock `cluster_name` / node name / uuid / frozen
   EOL version strings corroborate. Generic names (`elasticsearch`,
   `docker-cluster`, …) and still-deployed release numbers (`7.17.0`, `8.0.0`, …)
   need another hit (`requires_corroboration`).

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `GET /` root cluster document | Index create / bulk index / delete-by-query |
| `GET /<random-index>` | Snapshot / ILM / security user changes |
| `GET /_hpa_nonexistent_*` | `_search` / scroll that could hit real data |
| `GET /_cluster/health` | Cluster settings / reroute writes |
| `GET /_cat/health?format=json` | Cat APIs that dump index contents |
| `DELETE` / `PUT` / `HEAD` on `/` only | Writes to named indices or templates |

## Ports

| Port | Mode |
|------|------|
| 9200 | Production Elasticsearch HTTP API |
| 19200 | Lab Elasticsearch HTTP API |
| 9300 | Transport protocol — **out of scope** |

## Probe flow

```text
GET /  ──►  root JSON framing (version + tagline/cluster)
        │
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ Content-Type JSON? → content_type
        ├─ stock cluster/name/tagline/version/uuid → stock_cluster
        ├─ GET /hpa-audit-<token> → missing_index_ok
        ├─ GET /_hpa_nonexistent_* → path_facade
        ├─ DELETE / · PUT / · HEAD / → method_stub
        ├─ GET /_cluster/health → cluster_health_stub
        ├─ GET /_cat/health?format=json → cat_stub
        └─ X-Elastic-Product vs version ≥ 7.14 → product_header
```

## Indicators

All indicators are category **`static_signature`**.

### Speakership / framing

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `elasticsearch.root_framing` | Speakership | `GET /` is not a parseable Elasticsearch root document (`version.number` + tagline/cluster). |

### Lure metadata

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `elasticsearch.stock_cluster` | Lure banner | `cluster_name` / node `name` / `tagline` / `version.number` / `cluster_uuid` match stock lure tokens (`elastichoney`, `deadbeef`, frozen EOL versions, …). Generic names (`elasticsearch`, `docker-cluster`, …) and common still-deployed versions (`7.17.0`, `8.0.0`, …) are **corroboration-gated**. |

### Path / method / endpoint facades

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `elasticsearch.missing_index_ok` | Index stub | `GET /hpa-audit-<token>` returns **200** with a JSON body (should be `index_not_found_exception` / 404). Fidelity **high** when hit. |
| `elasticsearch.path_facade` | Route facade | Unknown API path returns **200** root-shaped JSON. Fidelity **high** when hit. |
| `elasticsearch.method_stub` | Method facade | `DELETE` / `PUT` on `/` return a root document at 200, or `HEAD /` returns a root-shaped body. Fidelity **high** when hit. |
| `elasticsearch.cluster_health_stub` | Endpoint shape | `GET /_cluster/health` returns the root document (or non-health JSON) instead of `status` + node counts. Denied/unavailable responses are **skipped**. Fidelity **high** when hit. |
| `elasticsearch.cat_stub` | Endpoint shape | `GET /_cat/health?format=json` returns the root object instead of a JSON array (plain cat text without JSON is acceptable). Fidelity **high** when hit. |

### Transport headers

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `elasticsearch.content_type` | Header facade | JSON root body served with a non-JSON `Content-Type` (e.g. `text/html`). |
| `elasticsearch.product_header` | Header facade | Claimed version ≥ 7.14 without `X-Elastic-Product: Elasticsearch`. Older versions that omit the header are **skipped** (inconclusive). |

## Safe mode

`--safe-mode` / `safe_mode`: only root framing on `GET /` is evaluated.
Missing-index, path, method, health, cat, Content-Type, product-header, and stock
metadata probes are skipped.

## Example

```bash
honeypot-auditor --target HOST -p 9200 --confirm-authorized -v
# lab alias
honeypot-auditor --target 127.0.0.1 -p 19200 -v
```

## Spec references

- [Cluster info (root)](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-info.html)
- [Cluster health](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-health.html)
- [cat health](https://www.elastic.co/guide/en/elasticsearch/reference/current/cat-health.html)
- Index APIs / error responses (`index_not_found_exception`)
- `X-Elastic-Product` header (Elasticsearch 7.14+)
- IANA-style HTTP API port **9200** (lab **19200**)

## Scoring

`PROTOCOL_STRATEGIES["elasticsearch"]` activates **static_signature** only.
High-signal examples when triggered: `missing_index_ok`, `path_facade`,
`method_stub`, `cluster_health_stub`, `cat_stub` (`high`). Stock cluster names
may require corroboration. See [`SCORING.md`](SCORING.md).
