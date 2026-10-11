# VNC probe

TCP/5900 (lab **5000** / **5901**). Fingerprints RFB 3.8 VNC-auth-only lures
and canned authentication failures with no desktop.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | *(inactive)* |
| **state_nonpersist** | RFB auth always canned failure (no desktop) |
| **static_signature** | RFB 3.8 VNC-auth only · canned Authentication failure · type-0 still challenges |

## Indicators

| ID | Trigger |
|----|---------|
| `vnc.handshake` | Abnormal RFB version / security-type set |
| `vnc.security` | VNC-auth-only / type-0 still challenges |
| `vnc.persist` | Auth always canned failure; no desktop session |

## Non-destructive policy

Handshake and auth-type probes only — never attempts real desktop control.

## Ports

| Port | Mode |
|------|------|
| 5900 | Production VNC |
| 5000 / 5901 | Lab / alternate |


## Code map (for auditors)

| Piece | Path |
|-------|------|
| Probe engine | [`src/honeypot_auditor/probes/vnc.py`](../../../src/honeypot_auditor/probes/vnc.py) |
| Signature matchers | [`src/honeypot_auditor/config/signatures/rdp_vnc.py`](../../../src/honeypot_auditor/config/signatures/rdp_vnc.py) |
| Tests | [`tests/test_vnc.py`](../../../tests/test_vnc.py) |
| Strategy axes | `PROTOCOL_STRATEGIES["vnc"]` in [`config/scoring.py`](../../../src/honeypot_auditor/config/scoring.py) |
| Transport | TCP |

Review order: axes catalog → probe indicators → signature matchers → tests.
