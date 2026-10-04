# Postgres probe

TCP/5432. Fingerprints SSLRequest→`N` then cleartext-only auth and frozen
`auth.c:326` FATAL blobs typical of shallow Postgres decoys.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | *(inactive)* |
| **state_nonpersist** | Cleartext-only auth · frozen `auth.c:326` fail blob |
| **static_signature** | SSLRequest → N then AuthenticationCleartextPassword only |

## Indicators

| ID | Trigger |
|----|---------|
| `postgres.cleartext` | SSL refused then cleartext-password-only path |
| `postgres.auth_blob` | Frozen / canned FATAL auth failure text |

## Non-destructive policy

Startup / SSLRequest / auth probe only. Never runs SQL.

## Ports

| Port | Mode |
|------|------|
| 5432 | Production / lab Postgres |


## Code map (for auditors)

| Piece | Path |
|-------|------|
| Probe engine | [`src/honeypot_auditor/probes/postgres.py`](../../../src/honeypot_auditor/probes/postgres.py) |
| Signature matchers | [`src/honeypot_auditor/config/signatures/postgres.py`](../../../src/honeypot_auditor/config/signatures/postgres.py) |
| Tests | [`tests/test_postgres.py`](../../../tests/test_postgres.py) |
| Strategy axes | `PROTOCOL_STRATEGIES["postgres"]` in [`config/scoring.py`](../../../src/honeypot_auditor/config/scoring.py) |
| Transport | TCP |

Review order: axes catalog → probe indicators → signature matchers → tests.
