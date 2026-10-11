# HTTP proxy probe

TCP/3128 (also mapped on **8080** in docker-research). Fingerprints Squid/ISA-class
proxy lures: dual Proxy-Authorization Basic, reconnect canned 407, Via localhost,
and silent-accept tarpits.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | Two entropy-varied Proxy-Authorization Basic pairs both allow CONNECT/GET |
| **state_nonpersist** | Prior proxy success becomes identical canned 407 on reconnect |
| **static_signature** | 407 Via localhost · frozen squid 3.3.8 · ISA deny phrase |

## Indicators

| ID | Trigger |
|----|---------|
| `httpproxy.arbitrary_auth` | Two synthetic Proxy-Authorization pairs both succeed |
| `httpproxy.state_nonpersist` | Success collapses to identical 407 on reconnect |
| `httpproxy.signature` | Stock Squid / ISA / Via localhost lure |
| `httpproxy.silent_accept` | TCP accept with no HTTP proxy bytes |

## Non-destructive policy

CONNECT/GET probes to synthetic targets only. Never tunnels real attacker traffic.

## Ports

| Port | Mode |
|------|------|
| 3128 | Production HTTP proxy |
| 8080 | Lab / alternate (docker-research) |


## Code map (for auditors)

| Piece | Path |
|-------|------|
| Probe engine | [`src/honeypot_auditor/probes/httpproxy.py`](../../../src/honeypot_auditor/probes/httpproxy.py) |
| Signature matchers | _(inline in probe / shared corpora)_ |
| Tests | [`tests/test_httpproxy.py`](../../../tests/test_httpproxy.py) |
| Strategy axes | `PROTOCOL_STRATEGIES["httpproxy"]` in [`config/scoring.py`](../../../src/honeypot_auditor/config/scoring.py) |
| Transport | TCP |

Review order: axes catalog → probe indicators → signature matchers → tests.
