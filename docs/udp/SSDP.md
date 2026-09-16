# SSDP / UPnP discovery probe

Honeypot-auditor’s SSDP engine speaks **UPnP Device Architecture** discovery
over **UDP/1900** (lab **11900**): unicast `M-SEARCH` only.

It targets IoT / UPnP honeypot stubs that answer discovery with canned
HTTP/1.1 bodies, ignore search targets, advertise loopback `LOCATION` URLs, or
treat any UDP datagram as a successful search. It does **not** multicast-flood,
spam `NOTIFY`, or fetch device description documents over HTTP in v1.

## Strategies

SSDP activates one of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["ssdp"]`):

| Strategy | Why it applies to SSDP |
|----------|------------------------|
| **arbitrary_auth** | **Empty.** SSDP discovery has no credential exchange. |
| **static_signature** | Framing, header facade, ST echo, response clone, stock `SERVER`, loopback `LOCATION`, method stub. |
| **state_nonpersist** | **Not used.** Discovery is request/response with no session mailbox. |

Detection philosophy:

1. **Baseline speakership** — unicast `M-SEARCH` with `ST: upnp:rootdevice`, small `MX`.
2. **Header honesty** — a `200 OK` must carry `SERVER` / `ST` / `USN` / `LOCATION`.
3. **ST fidelity** — response `ST` must echo the requested search target.
4. **Clone check** — a second distinct `M-SEARCH` must not return a bitwise-identical body.
5. **Lure / loopback** — stock `SERVER` tokens (gated) and `LOCATION` pointing at localhost.
6. **Method stub** — garbage non-`M-SEARCH` must not earn a `200 OK` SSDP reply.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| Unicast `M-SEARCH` to `host:1900` with `ST: ssdp:all` or `upnp:rootdevice` (and one synthetic URN) | Amplification floods / multicast abuse beyond a single packet |
| Small `MX` (1) | `NOTIFY` spam |
| Parse SSDP response headers only | Bulk HTTP GETs of `LOCATION` (optional same-host GET deferred; v1 stays UDP-only) |

Packet budget: ≤ **4** UDP exchanges per host.

## Ports

| Port | Mode |
|------|------|
| 1900 | Production SSDP / UPnP discovery (UDP) |
| 11900 | Lab SSDP (UDP) |

## Probe flow

```text
M-SEARCH ST: upnp:rootdevice  ──►  framing + header_facade + st_echo
        │                         + stock_server + location_loopback
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ M-SEARCH ST: urn:…:Hpaudit-<nonce>:1
        │       identical body → ssdp.response_clone
        │       wrong ST → ssdp.st_echo
        │
        └─ garbage non-M-SEARCH datagram
                200 OK SSDP-shaped → ssdp.method_stub
```

All exchanges use unconnected `udp_exchange` (peer port is evidence only).

## Indicators

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `ssdp.framing` | static_signature | high | no | UDP reply is not an HTTP/1.x SSDP-shaped response. |
| `ssdp.header_facade` | static_signature | high | no | Claims `200 OK` but missing `SERVER` / `ST` / `USN` / `LOCATION`. |
| `ssdp.st_echo` | static_signature | **high** | no | Response `ST` mismatches / ignores the search target. |
| `ssdp.response_clone` | static_signature | high | no | Bitwise-identical payloads for two distinct `M-SEARCH` requests. |
| `ssdp.stock_server` | static_signature | medium | **yes** | `SERVER` matches stock honeypot lure tokens. |
| `ssdp.location_loopback` | static_signature | **high** | no | `LOCATION` host is `127.0.0.1` / `::1` / `localhost`. |
| `ssdp.method_stub` | static_signature | high | no | Non-`M-SEARCH` garbage still answered with `200 OK` SSDP. |

## Safe mode

`--safe-mode` / `safe_mode`: only SSDP framing on the baseline `M-SEARCH` reply
is evaluated. Header, ST, clone, stock, location, and method probes are skipped.

## Spec references

- [UPnP Device Architecture 1.1](https://openconnectivity.org/developer/specifications/upnp-resources/upnp/) — Discovery (`M-SEARCH` / response headers)
- IANA: 1900/udp SSDP

## Scoring

`PROTOCOL_STRATEGIES["ssdp"]` activates **static_signature** only.
High-signal examples: `ssdp.st_echo`, `ssdp.location_loopback`. See
[`SCORING.md`](../SCORING.md) (rollup blurbs land after protocol merges).

## FP notes

- **Filtered UDP** — timeout / ICMP refuse → suite skip, not a honeypot hit.
- **Quiet devices** — no reply to an unknown synthetic URN is **clean** (real
  stacks often stay silent); only a reply with wrong `ST` or a cloned body scores.
- **NAT / CGNAT LOCATION** — private RFC1918 hosts in `LOCATION` are **not**
  scored; only loopback / localhost hostnames fire `location_loopback`.
