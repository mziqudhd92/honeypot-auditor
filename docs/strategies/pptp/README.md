# PPTP control-channel probe

Honeypot-auditor’s PPTP engine speaks the **RFC 2637** control channel on
**TCP/1723** (lab **11723**). It never opens GRE (IP protocol 47), never runs
PPP/CHAP/MS-CHAPv2, and never completes a tunnel.

It targets canned “open PPTP concentrator” stubs with **five detection checks**
across the three basic scoring strategies: speakers that ignore control-message
semantics, accept any Outgoing-Call without call-id fidelity, fail to echo
Echo Identifiers, or advertise stock hostname/vendor lure strings.

## Strategies

PPTP activates **all three** basic strategies
(`PROTOCOL_STRATEGIES["pptp"]`) via five indicators:

| # | Check | Strategy | What a real service does |
|---|-------|----------|---------------------------|
| 1 | `pptp.framing` | static_signature | SCCRP with magic cookie `0x1A2B3C4D` and control type 2 |
| 2 | `pptp.version_facade` | static_signature | Protocol Version **0x0100**; stock hostname/vendor tokens are corroboration-gated alone |
| 3 | `pptp.echo_id` | state_nonpersist | Echo-Reply **Identifier** equals the Echo-Request |
| 4 | `pptp.call_facade` | arbitrary_auth | OCRP Result=1 **without** echoing the request's Call ID in Peer's Call ID, or with a hollow zero server Call ID. Acceptance alone is honest — PPTP establishes calls pre-auth; PPP authenticates after |
| 5 | `pptp.control_stub` | static_signature | Unknown control types are not answered with a successful SCCRP |

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| Start-Control-Connection-Request / Reply parse | GRE data channel |
| Echo-Request / Reply | PPP LCP / IPCP |
| Outgoing-Call-Request (control only) | CHAP / MS-CHAPv2 / PAP |
| One unused control-type probe | Call clear / Set-Link-Info spam |

## Ports

| Port | Mode |
|------|------|
| 1723 | Production PPTP control (TCP) |
| 11723 | Lab PPTP control (TCP) |

## Probe flow

```text
SCCRQ ──► SCCRP framing + version_facade (+ stock hostname/vendor)
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ Echo-Request (random Identifier)
        │       wrong / missing Echo-Reply ID → pptp.echo_id
        │
        ├─ Outgoing-Call-Request (phone A)
        ├─ unknown control type
        │       successful SCCRP → pptp.control_stub
        │
        └─ reconnect + Outgoing-Call-Request (phone B)
                both accepted without call-id fidelity → pptp.call_facade
```

## Indicators

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `pptp.framing` | static_signature | high | no | Reply is not a PPTP SCCRP (magic / control type). |
| `pptp.version_facade` | static_signature | high / medium | stock-only **yes** | Version ≠ `0x0100`, or stock honeypot hostname/vendor token. |
| `pptp.echo_id` | state_nonpersist | high | no | Echo-Reply Identifier ≠ request (or non-echo reply). |
| `pptp.call_facade` | arbitrary_auth | high | no | Dual OCRQ accepted with fabricated semantics: Peer's Call ID ≠ request, or server Call ID = 0. Honest pre-auth acceptance (echo + non-zero Call ID) stays clean. |
| `pptp.control_stub` | static_signature | high | no | Unused control type answered with successful SCCRP. |

## Safe mode

`--safe-mode`: only SCCRP framing on the baseline Start-Control-Connection
exchange is evaluated.

## Spec references

- [RFC 2637 — Point-to-Point Tunneling Protocol (PPTP)](https://www.rfc-editor.org/rfc/rfc2637.html)
- IANA: 1723/tcp PPTP

## Scoring

`PROTOCOL_STRATEGIES["pptp"]` activates **all three** basic strategies
(**3** slots in the README table; **five** indicator checks). See
[`SCORING.md`](../../SCORING.md).

## FP notes

- **Filtered / closed 1723** — suite skip, not a honeypot hit.
- **Pre-auth call establishment is RFC-honest** — a real concentrator answers
  Outgoing-Call-Requests with Result=1 *before* PPP authentication (auth runs
  inside the GRE tunnel, which this probe never opens). Honest acceptance —
  Peer's Call ID echoing the request plus a non-zero, per-call server Call ID —
  is **clean**; only fabricated OCRP semantics score `pptp.call_facade`.
- **Call denial (Result ≠ 1)** — clean for `pptp.call_facade`.
- **Echo unanswered** — treated as clean (timeout), not a hit; only a wrong
  Identifier or non-echo PPTP body scores `pptp.echo_id`.
- **GRE-only listeners** — out of scope; this engine is TCP control only.


## Code map (for auditors)

| Piece | Path |
|-------|------|
| Probe engine | [`src/honeypot_auditor/probes/pptp.py`](../../../src/honeypot_auditor/probes/pptp.py) |
| Signature matchers | _(inline in probe / shared corpora)_ |
| Tests | [`tests/test_pptp.py`](../../../tests/test_pptp.py) |
| Strategy axes | `PROTOCOL_STRATEGIES["pptp"]` in [`config/scoring.py`](../../../src/honeypot_auditor/config/scoring.py) |
| Transport | TCP |

Review order: axes catalog → probe indicators → signature matchers → tests.
