# MSSQL probe

TCP/1433. Fingerprints canned TDS prelogin (`ENCRYPT_NOT_SUP`), LOGIN7 18456
failures, and TLS close-after-NOT_SUP stubs.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | *(inactive)* |
| **state_nonpersist** | Canned LOGIN7 18456 · TLS close after ENCRYPT_NOT_SUP |
| **static_signature** | Canned TDS prelogin · PRELOGIN encrypt NOT SUP |

## Indicators

| ID | Trigger |
|----|---------|
| `mssql.signature` / `mssql.prelogin` | Canned prelogin / ENCRYPT_NOT_SUP |
| `mssql.login7` | Fixed LOGIN7 18456 failure |
| `mssql.tls_drop` | TLS closed immediately after NOT_SUP |

## Non-destructive policy

Prelogin / LOGIN7 probes only. Never runs T-SQL against real databases.

## Ports

| Port | Mode |
|------|------|
| 1433 | Production / lab MSSQL |
