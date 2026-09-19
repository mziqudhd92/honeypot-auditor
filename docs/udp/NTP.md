# NTP probe

Honeypot-auditor’s NTP engine speaks **NTPv4 client/server modes**
([RFC 5905](https://www.rfc-editor.org/rfc/rfc5905.html)) over **UDP/123**
(lab **1123**).

It targets shallow NTP stubs with **RFC non-compliance** checks: wrong mode,
ignored originate timestamps, impossible stratum, canned identical datagrams,
and zeroed/epoch clock fields. It does **not** rely on product honeypot brand
IOCs alone, and it **never** sends `monlist` / mode-7 control queries.

## Strategies

NTP activates one of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["ntp"]`):

| Strategy | Why it applies to NTP |
|----------|------------------------|
| **arbitrary_auth** | **Empty.** NTP has no client credential on the basic path. |
| **static_signature** | Framing, mode/VN facade, originate echo, stratum facade, response clone, zeroed metrics, epoch-zero timestamps, stock refid lures. |
| **state_nonpersist** | **Not used.** Mode-3/4 is request/response over UDP with no session to resume. |

Detection philosophy:

1. **Baseline speakership** — 48-byte VN=4 mode-3 client packet → parseable ≥48-byte reply.
2. **Request fidelity** — server mode 4, originate echoes client transmit (RFC 5905 §7.3), stratum 1–15 (or stratum 0 with kiss code only).
3. **Canned datagram** — two distinct client transmit timestamps yield bitwise-identical UDP payloads.
4. **Weak clock tells last** — all-zero delay/dispersion/ref, epoch-zero stamps, and lure refids are **corroboration-gated**.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| Single 48-byte client mode-3 (VN=4) | `monlist` / `get_restrict` / mode-7 control |
| Second mode-3 with distinct transmit timestamp | Amplification floods |
| One invalid VN=0 mode-3 facade probe | NTS / mode-6 / private opcode sprays |

Packet budget: ≤ **8** UDP exchanges per host (this engine uses ≤3).

## Ports

| Port | Mode |
|------|------|
| 123 | Production NTP (UDP) |
| 1123 | Lab NTP (UDP) |

## Probe flow

```text
mode-3 VN=4 client (random xmt)  ──►  ≥48-byte NTP framing
        │
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ response mode ≠ 4            → ntp.mode_facade
        ├─ VN=0 client still served     → ntp.mode_facade
        ├─ org ≠ client xmt             → ntp.org_echo
        ├─ stratum 0 w/o kiss / ≥16     → ntp.stratum_facade
        ├─ second distinct xmt          → ntp.response_clone
        ├─ delay+disp+ref all zero      → ntp.zeroed_clock_metrics (gated)
        ├─ ref/rec/xmt at epoch         → ntp.epoch_zero (gated)
        └─ stock lure refid             → ntp.stock_refid (gated)
```

## Indicators

### Static / RFC conformance

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `ntp.framing` | static_signature | high when hit | no | UDP reply is shorter than 48 bytes or otherwise not a parseable NTP header. |
| `ntp.mode_facade` | static_signature | high when hit | no | Reply mode ≠ 4, and/or an invalid VN=0 client request still receives a mode-4 server reply. |
| `ntp.org_echo` | static_signature | high when hit | no | Reply originate timestamp ≠ client transmit timestamp (RFC 5905 §7.3). |
| `ntp.stratum_facade` | static_signature | high when hit | no | Stratum 0 without a kiss-o'-death ASCII refid, or stratum ≥ 16 as a serving reply. |
| `ntp.response_clone` | static_signature | **decisive** when hit | no | Two mode-3 requests with distinct transmit timestamps receive **bitwise-identical** UDP payloads. |
| `ntp.zeroed_clock_metrics` | static_signature | medium | **yes** | `root_delay`, `root_dispersion`, and `reference_timestamp` are all zero (real unsynced hosts can look sparse). |
| `ntp.epoch_zero` | static_signature | medium | **yes** | Reference, receive, or transmit timestamp seconds field is NTP epoch (0) or Unix epoch in NTP form (`2208988800`). |
| `ntp.stock_refid` | static_signature | medium | **yes** | Reference ID matches a generic lure token (`FAKE`, `HONE`, `TEST`, `DECO`, `STUB`, `MOCK`, `NULL`). |

Kiss-o'-death stratum 0 with RFC kiss codes (`INIT`, `STEP`, `RATE`, …) is **compliant** and does not fire `ntp.stratum_facade`.

## Safe mode

`--safe-mode` / `safe_mode`: only framing on the baseline reply is evaluated.
Mode, originate, stratum, clone, zeroed-metrics, epoch-zero, and stock-refid
probes are skipped with a safe-mode reason.

## Spec references

- [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905.html) — NTPv4 (modes, originate echo, stratum, kiss codes)
- IANA: 123/udp NTP

## Scoring

`PROTOCOL_STRATEGIES["ntp"]` activates **static_signature** only
(`arbitrary_auth` and `state_nonpersist` empty). High-signal examples:
`ntp.response_clone` (`decisive` when hit); mode, originate, and stratum tells
typically `high` when triggered. Gated clock/refid tells need another ungated
hit before they inflate Honeyscore. See [`SCORING.md`](../SCORING.md).

## False-positive notes

- **Unsynced real NTP** can briefly show sparse delay/dispersion — hence
  `ntp.zeroed_clock_metrics` and `ntp.epoch_zero` are corroboration-gated.
- **Kiss-o'-death** stratum 0 replies are legitimate; do not treat every
  stratum 0 as a facade.
- **Filtered UDP** (no ICMP) looks like timeout → full suite skip, not framing.
- **ICMP refused** (connected path) → suite skip via `closed_reason`, not a hit.
