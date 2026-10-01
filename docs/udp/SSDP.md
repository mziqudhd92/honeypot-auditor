# SSDP / UPnP discovery probe

Honeypot-auditor’s SSDP engine speaks **UPnP Device Architecture** discovery
over **UDP/1900** (lab **11900**): unicast `M-SEARCH` only.

It targets IoT / UPnP honeypot stubs that answer discovery with canned
HTTP/1.1 bodies, ignore search targets, advertise loopback or non-absolute
`LOCATION` URLs, omit required `EXT` / `CACHE-CONTROL` headers, break USN↔ST
coherence, or treat any UDP datagram as a successful search. It does **not**
multicast-flood, spam `NOTIFY`, or fetch device description documents over
HTTP in v1.

## Strategies

SSDP activates one of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["ssdp"]`):

| Strategy | Why it applies to SSDP |
|----------|------------------------|
| **arbitrary_auth** | **Empty.** SSDP discovery has no credential exchange. |
| **static_signature** | Framing, header facade, ST echo, response clone, stock `SERVER`, loopback `LOCATION`, method stub, empty `EXT` (corroboration-gated), `CACHE-CONTROL max-age`, USN↔ST coherence, absolute `LOCATION` URI, MAN facade, HOST blindness (corroboration-gated). |
| **state_nonpersist** | **Not used.** Discovery is request/response with no session mailbox. |

Detection philosophy:

1. **Baseline speakership** — unicast `M-SEARCH` with `ST: upnp:rootdevice`, small `MX`.
2. **Header honesty** — a `200 OK` must carry `SERVER` / `ST` / `USN` / `LOCATION`.
3. **ST fidelity** — response `ST` must echo the requested search target.
4. **Clone check** — a second distinct `M-SEARCH` must not return a bitwise-identical body.
5. **Lure / loopback** — stock `SERVER` tokens (gated) and `LOCATION` pointing at localhost.
6. **Method stub** — garbage non-`M-SEARCH` must not earn a `200 OK` SSDP reply.
7. **EXT** — UPnP requires an empty `EXT:` header on M-SEARCH replies (corroboration-gated: enough real devices omit it that a lone missing-EXT never scores alone).
8. **CACHE-CONTROL** — must advertise `max-age=<seconds>`.
9. **USN↔ST coherence** — `USN` must embed the response `ST` (typically `uuid:…::ST`).
10. **LOCATION URI** — must be an absolute `http`/`https` URI with a host (not a relative path).

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| Unicast `M-SEARCH` to `host:1900` with `ST: upnp:rootdevice` (and one synthetic URN) | Amplification floods / multicast abuse beyond a single packet |
| Small `MX` (1) | `NOTIFY` spam |
| Parse SSDP response headers only | Bulk HTTP GETs of `LOCATION` (optional same-host GET deferred; v1 stays UDP-only) |

Packet budget: ≤ **6** UDP exchanges per host (baseline + secondary ST + method
stub + MAN facade + HOST blindness).

## Ports

| Port | Mode |
|------|------|
| 1900 | Production SSDP / UPnP discovery (UDP) |
| 11900 | Lab SSDP (UDP) |

## Probe flow

```text
M-SEARCH ST: upnp:rootdevice  ──►  framing + header_facade + st_echo
        │                         + stock_server + location_loopback
        │                         + ext_header + cache_control
        │                         + usn_st_coherence + location_uri
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ M-SEARCH ST: urn:…:Hpaudit-<nonce>:1
        │       identical body → ssdp.response_clone
        │       wrong ST → ssdp.st_echo
        │
        └─ garbage non-M-SEARCH datagram
                200 OK SSDP-shaped → ssdp.method_stub

        ├─ M-SEARCH without MAN
                200 OK → ssdp.man_facade

        └─ M-SEARCH with nonsense HOST
                200 OK → ssdp.host_blind (corroboration-gated)
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
| `ssdp.ext_header` | static_signature | high | **yes** | `200 OK` missing required empty `EXT:` (UPnP DA). |
| `ssdp.cache_control` | static_signature | high | no | `CACHE-CONTROL` missing or lacks `max-age=<seconds>`. |
| `ssdp.usn_st_coherence` | static_signature | **high** | no | `USN` does not embed the response `ST`. |
| `ssdp.location_uri` | static_signature | high | no | `LOCATION` is not an absolute `http`/`https` URI with a host. |
| `ssdp.man_facade` | static_signature | medium | **yes** | `M-SEARCH` without required `MAN: "ssdp:discover"` still answered `200 OK`. |
| `ssdp.host_blind` | static_signature | medium | **yes** | `M-SEARCH` with a nonsense `HOST` still answered `200 OK`. |

## Safe mode

`--safe-mode` / `safe_mode`: only SSDP framing on the baseline `M-SEARCH` reply
is evaluated. Header, ST, clone, stock, location, method, and RFC header probes
are skipped.

## Spec references

- [UPnP Device Architecture 1.1](https://openconnectivity.org/developer/specifications/upnp-resources/upnp/) — Discovery (`M-SEARCH` / response headers)
- IANA: 1900/udp SSDP

## Scoring

`PROTOCOL_STRATEGIES["ssdp"]` activates **static_signature** only (still **1**
strategy slot in the README table). High-signal examples: `ssdp.st_echo`,
`ssdp.location_loopback`, `ssdp.usn_st_coherence`. See
[`SCORING.md`](../SCORING.md).

## FP notes

- **Filtered UDP** — timeout / ICMP refuse → suite skip, not a honeypot hit.
- **Quiet devices** — no reply to an unknown synthetic URN is **clean** (real
  stacks often stay silent); only a reply with wrong `ST` or a cloned body scores.
- **NAT / CGNAT LOCATION** — private RFC1918 hosts in `LOCATION` are **not**
  scored as loopback; only loopback / localhost hostnames fire `location_loopback`.
  Relative paths and non-http schemes fire `location_uri` instead.
- **EXT present with empty value** — `EXT:` / `EXT: ` is **clean** (required shape).
- **Real devices omitting `EXT`** — the spec requires it, but enough real stacks
  ship without it that `ssdp.ext_header` is corroboration-gated: it scores only
  alongside another triggered tell on the same face.
