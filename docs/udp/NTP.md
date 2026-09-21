# NTP probe

Honeypot-auditor’s NTP engine speaks **NTPv4 client/server modes**
([RFC 5905](https://www.rfc-editor.org/rfc/rfc5905.html)) over **UDP/123**
(lab **1123**).

It targets shallow NTP stubs with **RFC non-compliance** checks: wrong mode,
ignored originate timestamps, impossible stratum, canned identical datagrams,
and zeroed/epoch clock fields. It also checks for missing kiss-o'-death under a
short mode-3 burst and non-monotonic timestamps across exchanges. It does **not**
rely on product honeypot brand IOCs alone, and it **never** sends `monlist` /
mode-7 control queries.

## Strategies

NTP activates **all three** basic scoring strategies
(`PROTOCOL_STRATEGIES["ntp"]`):

| Strategy | Why it applies to NTP |
|----------|------------------------|
| **arbitrary_auth** | Mode-3 burst still served with uniform mode-4 replies and **no** KoD `RATE`/`DENY` (RFC 5905 §7.4). Indicator: `ntp.kod_absent`. |
| **static_signature** | Framing, mode/VN facade, originate echo, stratum facade, response clone, zeroed metrics, epoch-zero timestamps, implausible precision/poll metadata, stock refid lures. |
| **state_nonpersist** | Transmit / receive timestamps are frozen or go backwards. A stable reference timestamp is normal between polls. Indicator: `ntp.state_nonpersist`. |

Detection philosophy:

1. **Baseline speakership** — 48-byte VN=4 mode-3 client packet → parseable ≥48-byte reply.
2. **Request fidelity** — server mode 4, originate echoes client transmit (RFC 5905 §7.3), stratum 1–15 (or stratum 0 with kiss code only).
3. **Canned datagram** — two distinct client transmit timestamps yield bitwise-identical UDP payloads.
4. **KoD under burst** — a short mode-3 burst should elicit stratum-0 KoD `RATE`/`DENY` (or non-uniform clock advance); uniform mode-4 serving with no KoD scores `ntp.kod_absent`.
5. **Timestamp monotonicity** — transmit/receive/reference must advance across exchanges; frozen or regressing stamps score `ntp.state_nonpersist`.
6. **Weak clock tells last** — all-zero delay/dispersion/ref, epoch-zero stamps, and lure refids are **corroboration-gated**.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| Single 48-byte client mode-3 (VN=4) | `monlist` / `get_restrict` / mode-7 control |
| Second mode-3 with distinct transmit timestamp | Amplification floods |
| One invalid VN=0 mode-3 facade probe | NTS / mode-6 / private opcode sprays |
| Short mode-3 burst (2 extras) for KoD / monotonicity | Sustained rate abuse beyond the budget |
| One late mode-3 sample after jitter | |

Packet budget: ≤ **8** UDP exchanges per host. This engine may use more exchanges
than the original framing/clone path (baseline, VN facade, clone, KoD burst,
monotonicity sample) — still within the shared UDP budget.

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
        ├─ precision/poll out of range  → ntp.clock_metadata (gated)
        ├─ second distinct xmt          → ntp.response_clone
        ├─ mode-3 burst (2 extras)      → ntp.kod_absent
        ├─ timestamps across exchanges  → ntp.state_nonpersist
        ├─ delay+disp+ref all zero      → ntp.zeroed_clock_metrics (gated)
        ├─ ref/rec/xmt at epoch         → ntp.epoch_zero (gated)
        └─ stock lure refid             → ntp.stock_refid (gated)
```

## Indicators

### Arbitrary auth / KoD absent

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `ntp.kod_absent` | arbitrary_auth | high when hit | no | Mode-3 burst is served with uniform mode-4 replies and no KoD `RATE`/`DENY`. |

### State non-persistence

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `ntp.state_nonpersist` | state_nonpersist | high when hit | no | Transmit / receive timestamps are frozen or go backwards. Reference timestamp stability is not scored. |

### Static / RFC conformance

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `ntp.framing` | static_signature | high when hit | no | UDP reply is shorter than 48 bytes or otherwise not a parseable NTP header. |
| `ntp.mode_facade` | static_signature | high when hit | no | Reply mode ≠ 4, and/or an invalid VN=0 client request still receives a mode-4 server reply. |
| `ntp.org_echo` | static_signature | high when hit | no | Reply originate timestamp ≠ client transmit timestamp (RFC 5905 §7.3). |
| `ntp.stratum_facade` | static_signature | high when hit | no | Stratum 0 without a kiss-o'-death ASCII refid, or stratum ≥ 16 as a serving reply. |
| `ntp.clock_metadata` | static_signature | medium | **yes** | Precision exponent outside −30..1 or poll exponent outside 0..17 — raw canned bytes (e.g. precision `0x20` ≈ 2³² s, poll `0xFF`) no real clock produces. |
| `ntp.response_clone` | static_signature | **decisive** when hit | no | Two mode-3 requests with distinct transmit timestamps receive **bitwise-identical** UDP payloads. |
| `ntp.zeroed_clock_metrics` | static_signature | medium | **yes** | `root_delay`, `root_dispersion`, and `reference_timestamp` are all zero (real unsynced hosts can look sparse). |
| `ntp.epoch_zero` | static_signature | medium | **yes** | Reference, receive, or transmit timestamp seconds field is NTP epoch (0) or Unix epoch in NTP form (`2208988800`). |
| `ntp.stock_refid` | static_signature | medium | **yes** | Reference ID matches a generic lure token (`FAKE`, `HONE`, `TEST`, `DECO`, `STUB`, `MOCK`, `NULL`). |

Kiss-o'-death stratum 0 with RFC kiss codes (`INIT`, `STEP`, `RATE`, …) is **compliant** and does not fire `ntp.stratum_facade`. Observing KoD `RATE`/`DENY` under burst clears `ntp.kod_absent`.

## Safe mode

`--safe-mode` / `safe_mode`: only framing on the baseline reply is evaluated.
Mode, originate, stratum, clock-metadata, clone, KoD burst, monotonicity,
zeroed-metrics, epoch-zero, and stock-refid probes are skipped with a safe-mode
reason.

## Spec references

- [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905.html) — NTPv4 (modes, originate echo, stratum, kiss codes)
- IANA: 123/udp NTP

## Scoring

`PROTOCOL_STRATEGIES["ntp"]` activates **all three** basic strategies.
High-signal examples: `ntp.response_clone` (`decisive` when hit);
`ntp.kod_absent`, `ntp.state_nonpersist`, mode, originate, and stratum tells
typically `high` when triggered. Gated clock/refid tells need another ungated
hit before they inflate Honeyscore. See [`SCORING.md`](../SCORING.md).

## False-positive notes

- **Unsynced real NTP** can briefly show sparse delay/dispersion — hence
  `ntp.zeroed_clock_metrics` and `ntp.epoch_zero` are corroboration-gated.
- **Odd embedded clocks** can report coarse precision — hence the
  precision/poll range check (`ntp.clock_metadata`) is also corroboration-gated.
- **Kiss-o'-death** stratum 0 replies are legitimate; do not treat every
  stratum 0 as a facade. Missing KoD under a short burst is the
  `ntp.kod_absent` tell.
- **Filtered UDP** (no ICMP) looks like timeout → full suite skip, not framing.
- **ICMP refused** (connected path) → suite skip via `closed_reason`, not a hit.
