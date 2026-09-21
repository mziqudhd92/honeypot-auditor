# Elasticsearch probe

Honeypot-auditor’s Elasticsearch engine speaks the **HTTP JSON API** on
**9200** (lab **19200**). Transport protocol port **9300** is out of scope.

It targets ElasticHoney-class and similar HTTP stubs with **API / protocol
non-compliance** checks: agents that ignore path and method, echo the root
cluster document everywhere, or advertise stock lure metadata. It does **not**
rely on banner IOC lists alone, and it never writes indices or searches data.

## Strategies

Elasticsearch activates **all three** basic scoring strategies
(`PROTOCOL_STRATEGIES["elasticsearch"]`):

| Strategy | Why it applies to Elasticsearch |
|----------|----------------------------------|
| **arbitrary_auth** | Anonymous `GET /` is **401/403**, then two entropy-varied Basic headers both return the ES root. An already-open root (anonymous 200) is not a bypass. Indicator: `elasticsearch.arbitrary_auth`. |
| **static_signature** | Decoy “ES” faces are almost always canned HTTP handlers: wrong root shape, stock `cluster_name` / `cluster_uuid` / version, **200** on missing indices, unknown paths that return the root JSON, DELETE/PUT/HEAD that ignore the verb, `/_cluster/health` and `/_cat/health` that echo root instead of health/cat shapes, non-JSON `Content-Type`, JSON-only replies to `Accept: application/yaml` (gated — real ES negotiates YAML natively), or missing `X-Elastic-Product` on modern versions. |
| **state_nonpersist** | After reconnect, `GET /` cluster UUID/version mismatches `/_nodes` or `/_cluster/health`. Indicator: `elasticsearch.state_nonpersist`. |

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
   versions ≥ 7.14 should send `X-Elastic-Product: Elasticsearch`. A `GET /`
   with `Accept: application/yaml` must be answered in YAML (content
   negotiation facade, corroboration-gated for JSON-normalizing proxies).
5. **Dual Basic façade** — anonymous `GET /` must challenge (401/403) and both
   entropy-varied Basic headers then return the ES root to score
   `elasticsearch.arbitrary_auth`. An already-open anonymous root is not a bypass.
6. **Cluster identity drift** — root metadata that contradicts `/_nodes` or
   `/_cluster/health` after reconnect scores `elasticsearch.state_nonpersist`.
7. **Lure metadata last** — decisive lure tokens (honeypot names, frozen EOL
   versions, canned UUIDs like `deadbeef`) score alone. Generic names
   (`elasticsearch`, `docker-cluster`, …), still-deployed release numbers
   (`7.17.0`, `8.0.0`, …), and short/truncated UUIDs set
   `requires_corroboration` unless mixed with a decisive token on the same
   root document (then another category hit is not required).

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `GET /` root cluster document | Index create / bulk index / delete-by-query |
| `GET /` with two entropy-varied Basic headers | Password dictionary spray / `_security` user changes |
| `GET /<random-index>` | Snapshot / ILM / security user changes |
| `GET /_hpa_nonexistent_*` | `_search` / scroll that could hit real data |
| `GET /_cluster/health`, `GET /_nodes` | Cluster settings / reroute writes |
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
        ├─ Accept: application/yaml → content_negotiation (gated)
        ├─ stock cluster/name/tagline/version/uuid → stock_cluster
        ├─ GET /hpa-audit-<token> → missing_index_ok
        ├─ GET /_hpa_nonexistent_* → path_facade
        ├─ DELETE / · PUT / · HEAD / → method_stub
        ├─ GET /_cluster/health → cluster_health_stub
        ├─ GET /_cat/health?format=json → cat_stub
        ├─ X-Elastic-Product vs version ≥ 7.14 → product_header
        ├─ anon 401/403 then dual Basic on GET / → arbitrary_auth
        └─ /_nodes + /_cluster/health vs root → state_nonpersist
```

## Indicators

### Arbitrary auth / Basic façade

| ID | Category | Trigger |
|----|----------|---------|
| `elasticsearch.arbitrary_auth` | arbitrary_auth | Anonymous `GET /` challenged 401/403, then two entropy-varied Basic credentials both return the root. Fidelity **decisive** when hit. |

### State non-persistence

| ID | Category | Trigger |
|----|----------|---------|
| `elasticsearch.state_nonpersist` | state_nonpersist | After reconnect, root cluster UUID/version mismatches `/_nodes` or `/_cluster/health`. Fidelity **high** when hit. Denied/unavailable node/health endpoints are **skipped**. |

### Speakership / framing (static_signature)

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `elasticsearch.root_framing` | Speakership | `GET /` is not a parseable Elasticsearch root document (`version.number` + tagline/cluster). |

### Lure metadata

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `elasticsearch.stock_cluster` | Lure banner | `cluster_name` / node `name` / `tagline` / `version.number` / `cluster_uuid` match stock lure tokens. **Decisive** alone: honeypot names, frozen EOL versions, canned UUIDs (`deadbeef`, …). **Corroboration-gated** alone: generic names (`elasticsearch`, `docker-cluster`, …), common still-deployed versions (`7.17.0`, `8.0.0`, …), short/truncated UUIDs. A decisive token on the same root lifts the gate. |

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
| `elasticsearch.content_negotiation` | Header facade | `Accept: application/yaml` still answered with JSON — real ES negotiates YAML natively (corroboration-gated for JSON-normalizing proxies; 406 is a skip). |
| `elasticsearch.product_header` | Header facade | Claimed version ≥ 7.14 without `X-Elastic-Product: Elasticsearch`. Older versions that omit the header are **skipped** (inconclusive). |

## Safe mode

`--safe-mode` / `safe_mode`: only root framing on `GET /` is evaluated.
Missing-index, path, method, health, cat, Content-Type, yaml negotiation,
product-header, stock metadata, dual-Basic auth, and state probes are skipped.

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

`PROTOCOL_STRATEGIES["elasticsearch"]` activates **all three** basic strategies.
High-signal examples when triggered: `elasticsearch.arbitrary_auth` (`decisive`);
`elasticsearch.state_nonpersist`, `missing_index_ok`, `path_facade`, `method_stub`,
`cluster_health_stub`, `cat_stub` (`high`). Stock cluster names may require
corroboration. See [`SCORING.md`](SCORING.md).
