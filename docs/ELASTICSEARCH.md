# Elasticsearch probe

Honeypot-auditor’s Elasticsearch engine speaks the **HTTP JSON API** on
**9200** (lab **19200**). Transport protocol port **9300** is out of scope.

It scores **API / protocol non-compliance** common in ElasticHoney-class stubs:
stock cluster metadata, success responses for missing indices, unknown-path
facades that echo the root document, method stubs, and product-header mismatches.

## Strategies

| Strategy | Why it applies |
|----------|----------------|
| **static_signature** | Primary axis — root framing, lure metadata, 404/facade stubs, method ignore, product header. |
| **arbitrary_auth** | **Not used** on the basic read-only path (no credential spraying). |
| **state_nonpersist** | **Not used** (no session/index lifecycle to contradict). |

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `GET /` root cluster document | Index create / bulk index / delete-by-query |
| `GET /<random-index>` | Snapshot / ILM / security user changes |
| `GET /_hpa_nonexistent_*` | `_search` that could hit real data |
| `DELETE /` probe (expects rejection) | Cluster settings writes |

## Indicators

| ID | Trigger |
|----|---------|
| `elasticsearch.root_framing` | `GET /` is not a parseable Elasticsearch root document (`version` + cluster/tagline). |
| `elasticsearch.stock_cluster` | `cluster_name` / node `name` / `tagline` / `version.number` match stock lure tokens. Generic names like `elasticsearch` are corroboration-gated. |
| `elasticsearch.missing_index_ok` | `GET /hpa-audit-<token>` returns **200** with a JSON body (should be `index_not_found_exception` / 404). |
| `elasticsearch.path_facade` | Unknown API path returns **200** root-shaped JSON. |
| `elasticsearch.method_stub` | `DELETE /` returns the same (or any) root document at 200. |
| `elasticsearch.product_header` | Claimed version ≥ 7.14 without `X-Elastic-Product: Elasticsearch`. |

## Safe mode

`--safe-mode`: only root framing on `GET /` is evaluated.

## Spec references

- Elasticsearch HTTP APIs — [Root](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-info.html), index APIs, error responses
- `X-Elastic-Product` header (7.14+)

## Scoring

`PROTOCOL_STRATEGIES["elasticsearch"]` activates **static_signature** only
(no arbitrary-auth / state-nonpersist on the basic read-only path).
