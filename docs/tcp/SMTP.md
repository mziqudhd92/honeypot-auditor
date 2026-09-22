# SMTP probe

TCP/25 (lab **2525**). Fingerprints mail lures: any-password AUTH, open relay,
lost envelope state, and monotone extension replies.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | AUTH any-password · open relay |
| **state_nonpersist** | MAIL then RCPT 503 (lost envelope) |
| **static_signature** | Loopback identity · VRFY/EXPN/STARTTLS/ETRN monotone |

## Indicators

| ID | Trigger |
|----|---------|
| `smtp.arbitrary_auth` | AUTH accepts random passwords |
| `smtp.open_relay` | Relay accepted without auth |
| `smtp.envelope` | Envelope state lost between MAIL and RCPT |
| `smtp.identity` | Loopback / stock EHLO identity |
| `smtp.extensions` | VRFY/EXPN/STARTTLS/ETRN canned monotone |

## Non-destructive policy

Never delivers real mail. Synthetic AUTH / MAIL / RCPT only; RSET / QUIT cleanup.

## Ports

| Port | Mode |
|------|------|
| 25 | Production SMTP |
| 2525 | Lab |
