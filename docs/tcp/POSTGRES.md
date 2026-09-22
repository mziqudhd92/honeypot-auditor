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
