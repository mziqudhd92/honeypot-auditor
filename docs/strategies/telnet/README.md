# Telnet probe

TCP/23 (lab **2323**). Fingerprints telnet honeypots: any-password login,
canned rejects, IAC negotiation spray, unanswered AYT, identical command
deserts, and lure identity.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | Two random users both accepted |
| **state_nonpersist** | Canned reject · `/tmp` canary · identical command desert |
| **static_signature** | UAV / IAC spray · AYT stub · unknown-option WILL · lure whoami · fake tty |

## Indicators

| ID | Trigger |
|----|---------|
| `telnet.arbitrary_auth` | Two independent random credentials both succeed |
| `telnet.auth_lure` | Canned auth reject / lure login dialogue |
| `telnet.session_persist` | Session / canary state breaks across reconnect |
| `telnet.cmd_desert` | Distinct post-login commands return the same canned line |
| `telnet.banner` | Stock telnet lure banner |
| `telnet.iac_negotiate` | Abnormal IAC / WILL spray |
| `telnet.ayt_stub` | IAC AYT unanswered after speakership (corroboration-gated) |
| `telnet.whoami` / `telnet.uname` | Lure session identity |

## Ports

| Port | Mode |
|------|------|
| 23 | Production Telnet |
| 2323 | Lab |


## Code map (for auditors)

| Piece | Path |
|-------|------|
| Probe engine | [`src/honeypot_auditor/probes/telnet.py`](../../../src/honeypot_auditor/probes/telnet.py) |
| Signature matchers | [`src/honeypot_auditor/config/signatures/telnet.py`](../../../src/honeypot_auditor/config/signatures/telnet.py) |
| Tests | [`tests/test_telnet.py`](../../../tests/test_telnet.py) |
| Strategy axes | `PROTOCOL_STRATEGIES["telnet"]` in [`config/scoring.py`](../../../src/honeypot_auditor/config/scoring.py) |
| Transport | TCP |

Review order: axes catalog → probe indicators → signature matchers → tests.
