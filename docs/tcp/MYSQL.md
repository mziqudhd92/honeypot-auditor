# MySQL probe

TCP/3306. Fingerprints EOL 5.5.x Ubuntu greetings, stock handshake capability
blocks, drop-after-1045, and SSL-request silent drops (OpenCanary class).

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | *(inactive)* |
| **state_nonpersist** | Drop after 1045 · Expected-seq FSM · SSL-request silent drop |
| **static_signature** | EOL 5.5.x ubuntu greeting · stock handshake caps |

## Indicators

| ID | Trigger |
|----|---------|
| `mysql.signature` | EOL / stock server version greeting |
| `mysql.handshake` | Stock capability block + `mysql_native_password` |
| `mysql.persist` | 1045 then connection closed (no retry window) |
| `mysql.seq_order` | Emulator packet-sequence FSM failure |
| `mysql.ssl_drop` | SSLRequest silently dropped |

## Non-destructive policy

Greeting / handshake / dual synthetic auth only. Never runs SQL against real DBs.

## Ports

| Port | Mode |
|------|------|
| 3306 | Production / lab MySQL |
