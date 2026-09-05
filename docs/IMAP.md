# IMAP probe

Honeypot-auditor’s IMAP engine speaks **IMAP4rev1** ([RFC 3501](https://www.rfc-editor.org/rfc/rfc3501.html))
over cleartext **143** / lab **1143**, and implicit TLS (**IMAPS**) on **993**.

It pairs with the POP3 engine for Exchange / mail skins (qeeqbox, OpenCanary-class):
state-boundary checks, identical credential-lure failure text, and stock Exchange
greetings — not mailbox content inspection.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| Greeting / CAPABILITY / LIST / SELECT probes | FETCH, STORE, EXPUNGE, APPEND |
| Tagged unknown verb (`XZPQ`) | Reading or deleting messages |
| Two synthetic `LOGIN` pairs | Password spraying beyond two pairs |
| `LOGOUT` after successful LOGIN | Changing mailbox state |

## Ports and TLS

| Port | Transport |
|------|-----------|
| 143, 1143 | Cleartext IMAP |
| 993 | Implicit TLS via `create_tls_connection` (IMAPS) |

STARTTLS upgrade on 143 is not required for the basic probe.

## Greetings (RFC 3501 §7.1)

| Greeting | Probe behavior |
|----------|----------------|
| `* OK …` | Not Authenticated — full suite (unless safe-mode) |
| `* PREAUTH …` | Already Authenticated — **skip** `imap.arbitrary_auth` and `imap.preauth_state` (SELECT OK is expected). Still samples CAPABILITY / LIST / unknown for blankets and stock banner. |
| `* BYE …` | Rejected connection — valid framing; remaining suite **skipped** (not a greeting tell) |
| Anything else | `imap.greeting` triggered; deeper checks skipped |

## Indicators

### Arbitrary auth

| ID | Trigger |
|----|---------|
| `imap.arbitrary_auth` | Two independent random `LOGIN` pairs both return tagged `OK`. Evidence lists usernames only (no passwords). After accept, the probe sends `LOGOUT`. Fidelity **decisive** when hit. |

Skipped on `* PREAUTH` / `* BYE` / safe-mode / malformed greeting.

### State non-persistence

| ID | Trigger |
|----|---------|
| `imap.preauth_state` | `SELECT INBOX` returns tagged `OK` **before** LOGIN (Not Authenticated bypass). `LIST` OK alone is recorded but **not** scored (fewer FPs). |

Skipped on PREAUTH (already Authenticated per §3.2).

### Static / conformance

| ID | Trigger |
|----|---------|
| `imap.greeting` | Greeting is not `* OK`, `* PREAUTH`, or `* BYE`. |
| `imap.unknown_command` | Unrecognized `XZPQ` returns tagged `OK` (should be `BAD`). |
| `imap.auth_failed_blanket` | Identical **credential-lure** `NO`/`BAD` bodies (e.g. “Authentication failed”) across pre-auth commands **including CAPABILITY**. Legitimate “authenticate first” state text alone does **not** score. Fidelity **high**. |
| `imap.stock_banner` | Greeting matches a stock Exchange lure (e.g. “The Microsoft Exchange IMAP4 service is ready”). Corroboration-gated; fidelity **medium**. |

## Safe mode

`--safe-mode` / `safe_mode`: greeting framing + stock banner only; LOGIN, SELECT/LIST,
unknown-command, and blanket checks are skipped.

## Spec references

- [RFC 3501](https://www.rfc-editor.org/rfc/rfc3501.html) — states, CAPABILITY, LOGIN,
  LIST/SELECT, greetings (`OK` / `PREAUTH` / `BYE`), LOGOUT
- IANA: 143/tcp IMAP, 993/tcp IMAPS

## Scoring

All three basic strategies are active (`PROTOCOL_STRATEGIES["imap"]`).
High-signal examples: `imap.auth_failed_blanket` (`high`), `imap.arbitrary_auth`
(`decisive` when hit). See [`SCORING.md`](SCORING.md).

## Related

- POP3 twin for the same mail-stack skins (ports 110 / 1110)
- `proxy_transport.create_tls_connection` / `wrap_tls` for IMAPS
