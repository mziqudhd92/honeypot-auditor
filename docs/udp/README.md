# UDP probe package

Transport and netutil notes for UDP engines. **Per-protocol strategy guides
live under [`docs/strategies/`](../strategies/)** — one folder per protocol.

TCP guides index: [`docs/tcp/`](../tcp/README.md). **SIP** is UDP-first with
TCP fallback → [`strategies/sip`](../strategies/sip/).

## Layout

```text
src/honeypot_auditor/probes/udp/
  __init__.py      # re-exports discovery
  _engine.py       # UDPEngine + discover_udp_engines()
  dns.py           # DNS RFC non-compliance engine
  ntp.py           # NTP RFC 5905 non-compliance engine
  ssdp.py          # SSDP/UPnP discovery engine
  tftp.py          # RFC 1350 + light RFC 2347

docs/strategies/
  dns/ ntp/ ssdp/ tftp/ snmp/   # strategy guides + code maps
docs/udp/
  README.md                     # this transport index (+ move stubs)
```

## Strategy guides

| Protocol | Guide | Axes |
|----------|-------|------|
| DNS | [strategies/dns](../strategies/dns/) | all three |
| NTP | [strategies/ntp](../strategies/ntp/) | all three |
| TFTP | [strategies/tftp](../strategies/tftp/) | state + static |
| SSDP | [strategies/ssdp](../strategies/ssdp/) | static only |
| SNMP | [strategies/snmp](../strategies/snmp/) | auth + static |

## Discovery rules

- `discover_udp_engines()` walks `probes.udp` submodules.
- Modules whose names start with `_` are **skipped** (helpers such as `_engine`).
- Each protocol module exports `UDP_ENGINE = UDPEngine(name=..., probe=...)`
  (or a callable `probe_<name>`).
- Top-level `PROBE_BY_PROTOCOL` merges discovered engines at import time.
- **Ports and `PROTOCOL_STRATEGIES` stay in `config`** — discovery never feeds
  config (avoids circular imports).

## netutil API

| Call | Role |
|------|------|
| `udp_exchange(host, port, payload, *, connected=False)` | Preferred: returns `UdpExchange` (`data`, `peer_host`, `peer_port`, `rtt_ms`, `error`). |
| `udp_exchange_with_retransmit_watch(...)` | Same as exchange, then idle-listen on the local socket (TFTP OACK one-shot detection). |
| `udp_exchange_to(host, peer_port, payload)` | Follow-up to a learned peer port (TFTP TID). Unconnected. |
| `udp_transact(host, port, payload)` | Back-compat `(data, error)` wrapper for SNMP/SIP. |

### `connected=` vs default

- **Default (`connected=False`)**: `sendto` / `recvfrom`. Peer source port is
  visible — required to learn TFTP TID and to detect `tftp.fixed_source_port`
  when `peer_port == dst_port`.
- **`connected=True`**: `connect` then `send` / `recv`. On many OSes this maps
  ICMP port-unreachable to a refused-style error. Use only when that mapping
  matters more than peer-port learning; do not use it for the first TFTP RRQ.

### `UdpExchange`

```python
@dataclass(frozen=True)
class UdpExchange:
    data: bytes
    peer_host: str
    peer_port: int
    rtt_ms: float
    error: str  # "" on success
```

`rtt_ms` is **evidence only** in v1 — not a standalone scored indicator.

## Packet budget

≤ **8 UDP exchanges** per protocol per host. No amplification:

- No NTP monlist / mode-7
- No DNS AXFR / IXFR / ANY floods
- No TFTP DATA upload / bulk WRQ body
- No SSDP multicast joins / `NOTIFY` floods (unicast `M-SEARCH` only)

SSDP scores **static_signature** only, including corroboration-gated
`ssdp.man_facade` and `ssdp.host_blind`. See [strategies/ssdp](../strategies/ssdp/).

## ICMP refused vs timeout

| Symptom | Typical cause | Probe behavior |
|---------|---------------|----------------|
| Error string contains refused / `ECONNREFUSED` | ICMP port-unreachable (often needs connected mode) | Suite skip via `closed_reason` — not a honeypot hit |
| Timeout / empty reply | Filtered UDP or silent drop | Suite skip — not a framing tell |

Unconnected exchanges often **timeout** on closed ports; connected mode is the
optional path when refuse detection is needed.

## Anti-patterns

- Do not score synthetic latency alone.
- Do not rename indicators to `udp.*` — keep `dns.*` / `ntp.*` / `ssdp.*` / `tftp.*`.
- Do not put product honeypot brand IOCs in probes.
- Do not add SOCKS/UDP proxy transport here.
- Do not auto-source ports/strategies from probe modules into config.
- Do not move `snmp.py` / `sip.py` probe modules in protocol PRs (docs already under `strategies/`).
