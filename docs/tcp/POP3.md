# POP3 probe

TCP/110 (lab **1110**). Pairs with IMAP for Exchange / OpenCanary mail skins:
dual USER/PASS, pre-auth STAT/NOOP, greeting framing, and auth-failed blankets.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | Two random USER/PASS pairs |
| **state_nonpersist** | STAT/NOOP before authentication |
| **static_signature** | +OK greeting · unknown-command · auth-failed -ERR blanket · stock lure |

## Indicators

| ID | Trigger |
|----|---------|
| `pop3.arbitrary_auth` | Two random credential pairs both succeed |
| `pop3.preauth_state` | STAT/NOOP allowed before AUTH |
| `pop3.greeting` | Abnormal +OK greeting framing |
| `pop3.unknown_command` | Unknown command not rejected cleanly |
| `pop3.auth_failed_blanket` | STAT/CAPA/HPAU all -ERR after failed auth |
| `pop3.stock_banner` | Stock Exchange / lure banner |

## Non-destructive policy

Never reads or deletes mailbox messages.

## Ports

| Port | Mode |
|------|------|
| 110 | Production POP3 |
| 1110 | Lab |
