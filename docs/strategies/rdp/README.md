# RDP probe

TCP/3389. Fingerprints canned NLA cookies and negotiation-failure stubs used by
shallow RDP honeypots.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | *(inactive)* |
| **state_nonpersist** | Second packet is canned negotiation failure |
| **static_signature** | Canned NLA cookie `0x1234` |

## Indicators

| ID | Trigger |
|----|---------|
| `rdp.signature` | Canned NLA / cookie facade |
| `rdp.persist` | Follow-up packet is a fixed negotiation failure |

## Non-destructive policy

Connection negotiation probes only. Never authenticates to a real desktop.

## Ports

| Port | Mode |
|------|------|
| 3389 | Production / lab RDP |


## Code map (for auditors)

| Piece | Path |
|-------|------|
| Probe engine | [`src/honeypot_auditor/probes/rdp.py`](../../../src/honeypot_auditor/probes/rdp.py) |
| Signature matchers | [`src/honeypot_auditor/config/signatures/rdp_vnc.py`](../../../src/honeypot_auditor/config/signatures/rdp_vnc.py) |
| Tests | [`tests/test_rdp.py`](../../../tests/test_rdp.py) |
| Strategy axes | `PROTOCOL_STRATEGIES["rdp"]` in [`config/scoring.py`](../../../src/honeypot_auditor/config/scoring.py) |
| Transport | TCP |

Review order: axes catalog → probe indicators → signature matchers → tests.
