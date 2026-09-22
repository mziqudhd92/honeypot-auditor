# SIP probe guide

SIP/2.0 (UDP first, TCP fallback) transaction-coherence fingerprinting for the
`honeypot-auditor` basic probe. The engine speaks read-only `OPTIONS` and
synthetic `REGISTER`s to score decoy PBX skins that accept anything and echo
canned replies.

Ports **5060** (UDP, then TCP). See `PROTOCOL_STRATEGIES["sip"]`.

## Strategies

| Strategy | Why it applies to SIP |
|----------|-----------------------|
| **arbitrary_auth** | Two entropy-varied `REGISTER`s with fake Digest `response` values both return **200**. Nonce reuse alone is not scored. Indicator: `sip.arbitrary_auth`. |
| **state_nonpersist** | CSeq/Call-ID dialog binding is not tracked: identical canned 200 bodies across a CSeq advance, a binding that appears as canned OK after a prior 401/403, or a binding that vanishes after reconnect. Indicator: `sip.state_nonpersist`. |
| **static_signature** | Default User-Agent templates, response Via lacking `received=`/`rport=` additions or the branch echo, and response CSeq that does not echo the request transaction. Indicators: `sip.user_agent`, `sip.via_coherence`, `sip.cseq_echo`. |

## Detection philosophy

1. **Baseline speakership** — an `OPTIONS` request must return a `SIP/2.0`
   status line. Anything else is a suite skip (not a SIP speaker).
2. **Transaction echo coherence** — the request Via sent-by is `0.0.0.0:5060`
   with `;rport`, so a conformant server **must** copy the Via, echo our
   branch, and add `received=<source-ip>` / `rport=<source-port>`
   (RFC 3261 §8.2.6.2, RFC 3581 §4). Skins echo the header verbatim. Gated —
   sloppy-but-real embedded endpoints exist.
3. **Per-transaction CSeq echo** — the two OPTIONS exchanges carry distinct
   CSeq numbers (7 and 9) and randomized per-request branch tokens; every
   response must echo its own request's number *and* method. A canned single
   response for everything fails on the second transaction. Gated.
4. **Digest façade** — two `REGISTER`s with fake Digest credentials (entropy
   varied) both returning 200 is decisive. An identical nonce+realm across
   rapid challenges is normal registrar behavior and is not scored.
5. **Dialog binding** — a re-REGISTER with the same Call-ID and an advanced
   CSeq must retain binding state; canned identical 200s or a binding that
   flips/vanishes score `sip.state_nonpersist`.
6. **Banner last** — the default-template User-Agent tell corroborates.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `OPTIONS` requests | `INVITE` / call setup or media negotiation |
| Synthetic `REGISTER` with fake Digest credentials | Registration of real users or credential spraying |
| Re-REGISTER with advanced CSeq on our own Call-ID | `CANCEL` / `BYE` against unknown dialogs |
| Distinct CSeq/branch per transaction | Amplification (bodies stay `Content-Length: 0`) |

## Ports

| Port | Mode |
|------|------|
| 5060 | SIP over UDP (TCP fallback when UDP is silent) |

## Probe flow

```text
OPTIONS (CSeq 7, random branch)  ──►  SIP/2.0 status line
        │
        ├─ safe-mode ──► stop (user_agent only)
        │
        ├─ Via missing received=/rport=/branch → sip.via_coherence (gated)
        ├─ OPTIONS (CSeq 9) response CSeq echo → sip.cseq_echo (gated)
        ├─ UA/Server default template          → sip.user_agent
        ├─ dual fake-Digest REGISTER both 200  → sip.arbitrary_auth
        │   (nonce reuse across challenges is not scored)
        └─ re-REGISTER same Call-ID, CSeq 1→2  → sip.state_nonpersist
```

## Indicators

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `sip.user_agent` | static_signature | medium | no | `User-Agent`/`Server` header matches a default-template lure list. |
| `sip.via_coherence` | static_signature | high | **yes** (gated) | Response Via lacks `received=<ip>`/`rport=<port>` additions or the request branch echo (sent-by is 0.0.0.0, so both are mandatory). |
| `sip.cseq_echo` | static_signature | high | **yes** (gated) | Response CSeq number/method does not match its own request's transaction (requests use 7 then 9), or CSeq header missing. |
| `sip.arbitrary_auth` | arbitrary_auth | **decisive** when hit | no | Two entropy-varied fake-Digest `REGISTER`s both 200. Nonce reuse is recorded and not scored. |
| `sip.state_nonpersist` | state_nonpersist | high when hit | no | Canned identical 200s across a CSeq advance; binding appears as canned OK after prior challenge; or binding vanishes after reconnect. |

## Safe mode

`--safe-mode` / `safe_mode`: only the User-Agent tell on the baseline OPTIONS
response is evaluated. Via, CSeq, auth, and state probes are skipped.

## Spec references

- [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261.html) — SIP (§8.2.6.2 response construction, Via/CSeq echo)
- [RFC 3581](https://www.rfc-editor.org/rfc/rfc3581.html) — `rport` / `received` symmetric response routing
- IANA: 5060/udp+tcp SIP
