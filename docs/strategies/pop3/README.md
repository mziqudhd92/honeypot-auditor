# POP3 probe

TCP/110 (lab **1110**). Pairs with IMAP for Exchange / OpenCanary mail skins:
dual USER/PASS, pre-auth STAT/NOOP and LIST/UIDL, greeting framing, auth-failed
blankets, and RFC 1939 case conformance.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | Two random USER/PASS pairs |
| **state_nonpersist** | STAT/NOOP before authentication · LIST/UIDL before authentication |
| **static_signature** | +OK greeting · unknown-command · auth-failed -ERR blanket · stock lure · lowercase-verb rejection |

## Indicators

| ID | Trigger |
|----|---------|
| `pop3.arbitrary_auth` | Two random credential pairs both succeed |
| `pop3.preauth_state` | STAT/NOOP allowed before AUTH |
| `pop3.preauth_uidl` | LIST/UIDL allowed before AUTH (maildrop listing pre-auth) |
| `pop3.command_case` | Lowercase `capa` → -ERR while uppercase `CAPA` → +OK (RFC 1939 verbs are case-insensitive) |
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


## Code map (for auditors)

| Piece | Path |
|-------|------|
| Probe engine | [`src/honeypot_auditor/probes/pop3.py`](../../../src/honeypot_auditor/probes/pop3.py) |
| Signature matchers | _(inline in probe / shared corpora)_ |
| Tests | [`tests/test_pop3.py`](../../../tests/test_pop3.py) |
| Strategy axes | `PROTOCOL_STRATEGIES["pop3"]` in [`config/scoring.py`](../../../src/honeypot_auditor/config/scoring.py) |
| Transport | TCP |

Review order: axes catalog → probe indicators → signature matchers → tests.
