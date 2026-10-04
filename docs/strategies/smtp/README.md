# SMTP probe

TCP/25 (lab **2525**). Fingerprints mail lures: any-password AUTH, open relay,
lost envelope state, RSET-ignored envelope state, monotone extension replies,
and STARTTLS capability lies.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | AUTH any-password · open relay |
| **state_nonpersist** | MAIL then RCPT 503 (lost envelope) · envelope survives RSET |
| **static_signature** | Loopback identity · VRFY/EXPN/STARTTLS/ETRN monotone · STARTTLS capability lie |

## Indicators

| ID | Trigger |
|----|---------|
| `smtp.arbitrary_auth` | AUTH accepts random passwords |
| `smtp.open_relay` | Relay accepted without auth |
| `smtp.envelope` | Envelope state lost between MAIL and RCPT |
| `smtp.rset_envelope` | RCPT still 2xx after explicit RSET (canned transaction state) |
| `smtp.identity` | Loopback / stock EHLO identity |
| `smtp.extensions` | VRFY/EXPN/STARTTLS/ETRN canned monotone |
| `smtp.starttls_lie` | STARTTLS advertised + 220 but TLS handshake fails |

## Non-destructive policy

Never delivers real mail. Synthetic AUTH / MAIL / RCPT only; RSET / QUIT cleanup.
Extension fingerprinting may issue STARTTLS; if the server answers 220, the
probe reopens the TCP session before envelope/RSET work so cleartext MAIL/RCPT
are not sent on a TLS-armed socket. The capability-lie STARTTLS probe also
runs in an isolated session (EHLO then STARTTLS; verification disabled —
fingerprinting only).

## Ports

| Port | Mode |
|------|------|
| 25 | Production SMTP |
| 2525 | Lab |


## Code map (for auditors)

| Piece | Path |
|-------|------|
| Probe engine | [`src/honeypot_auditor/probes/smtp.py`](../../../src/honeypot_auditor/probes/smtp.py) |
| Signature matchers | [`src/honeypot_auditor/config/signatures/smtp.py`](../../../src/honeypot_auditor/config/signatures/smtp.py) |
| Tests | [`tests/test_smtp.py`](../../../tests/test_smtp.py) |
| Strategy axes | `PROTOCOL_STRATEGIES["smtp"]` in [`config/scoring.py`](../../../src/honeypot_auditor/config/scoring.py) |
| Transport | TCP |

Review order: axes catalog → probe indicators → signature matchers → tests.
