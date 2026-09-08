# SNMP probe

Honeypot-auditor’s SNMP engine speaks **community-based SNMPv1 / SNMPv2c**
([RFC 1157](https://www.rfc-editor.org/rfc/rfc1157.html),
[RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html)) over **UDP/161**
(lab **1161**, alternate lab **10161**).

It targets OpenCanary / Conpot-class SNMP stubs with **RFC non-compliance**
checks: agents that answer without parsing the request, accept any community,
or return canned MIB bytes. It does **not** rely on banner IOC lists alone.

## Strategies

SNMP activates two of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["snmp"]`):

| Strategy | Why it applies to SNMP |
|----------|------------------------|
| **arbitrary_auth** | Community strings are the v1/v2c “credential”. Real agents drop or refuse unknown communities; decoys often answer every string with a successful GetResponse. |
| **static_signature** | Most SNMP honeypot tells are protocol-facade / MIB-stub failures: wrong PDU framing, ignored `request-id` / version / OID, GetNext that does not walk, wrong ASN.1 types, stock `sysDescr` lures. |
| **state_nonpersist** | **Not used.** Community Get/GetNext probes are request/response over UDP with no session to resume or mailbox/bus state to contradict. |

Detection philosophy:

1. **Baseline speakership** — `Get(sysDescr.0)` with community `public` (v2c, then v1 fallback). No parseable GetResponse → framing tell or suite skip.
2. **Auth dual-probe** — two independent random communities must *both* succeed before `arbitrary_auth` fires (`public` alone never scores).
3. **Request fidelity** — distinct `request-id`s, invalid version, missing OID, GetNext advance, OID name echo, and ASN.1 types must match the RFCs; canned identical UDP payloads are decisive.
4. **Lure text last** — stock `sysDescr` tokens corroborate; weak Linux strings need another hit.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| GetRequest for `sysDescr.0` / `sysObjectID.0` / `sysUpTime.0` | SetRequest / write communities |
| Single GetNextRequest for `sysDescr.0` | Walk / BulkWalk / GetBulk of large trees |
| GetRequest for a nonexistent enterprise OID | SNMPv3 USM discovery or brute force |
| Random community probes (two) | Password / community spraying beyond two synthetics |

## Ports

| Port | Mode |
|------|------|
| 161 | Production SNMP (UDP) |
| 1161 | Lab SNMP (UDP) |
| 10161 | Alternate lab SNMP (UDP) |

## Probe flow

```text
Get(sysDescr.0) community=public  ──►  BER/GetResponse framing
        │
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ request-id echo check on baseline
        ├─ two random communities → arbitrary_auth
        ├─ version=99 Get → version_facade
        ├─ Get(garbage enterprise OID) → nosuch_success
        ├─ GetNext(sysDescr.0) → getnext_stub
        ├─ Get(sysObjectID.0) + Get(sysUpTime.0) → type_facade + oid_echo
        ├─ second Get(sysDescr.0) distinct request-id → response_clone
        └─ sysDescr lure tokens → stock_sysdescr (often corroboration-gated)
```

## Indicators

### Arbitrary auth

| ID | Trigger |
|----|---------|
| `snmp.arbitrary_community` | Two independent random community strings both receive a successful GetResponse for `sysDescr.0`. Fidelity **decisive** when hit. |

Well-known `public` success alone is **not** scored (common on real gear).
Silent drop / timeout on bad communities is treated as compliant reject.

### Static / RFC conformance

| ID | Strategy role | Trigger |
|----|---------------|---------|
| `snmp.ber_framing` | Speakership | UDP reply is not a parseable SNMP BER message, or PDU is not GetResponse (`0xA2`). |
| `snmp.request_id` | Request fidelity | GetResponse `request-id` ≠ request (RFC 1157 §4.1 requires echo). |
| `snmp.version_facade` | Protocol facade | Message `version=99` still yields a successful GetResponse (unsupported versions should be dropped). |
| `snmp.nosuch_success` | MIB stub | Nonexistent OID returns `error-status=0` with a populated value (v1 → `noSuchName`; v2c → exception tags). |
| `snmp.getnext_stub` | MIB stub | `GetNext(sysDescr.0)` returns success without advancing (same/earlier OID) instead of the next leaf or `endOfMibView` (RFC 1157 §4.1.3 / RFC 3416 §4.2.2). |
| `snmp.type_facade` | ASN.1 facade | `sysObjectID.0` is not OBJECT IDENTIFIER (`0x06`) and/or `sysUpTime.0` is not TimeTicks (`0x43`) (RFC 1213). |
| `snmp.oid_echo` | Canned PDU | Successful GetResponse varbind **name** ≠ requested OID (stubs often reuse `sysDescr.0`). |
| `snmp.response_clone` | Canned datagram | Two `Get(sysDescr.0)` requests with distinct `request-id`s receive **bitwise-identical** UDP payloads. Fidelity **decisive** when hit. |
| `snmp.stock_sysdescr` | Lure banner | `sysDescr` matches stock lure tokens (`opencanary`, `conpot`, `fake snmp`, …). Generic Linux tokens (`linux #1 smp`, `debian gnu/linux`, `unknown`, `device description`) are **corroboration-gated**. |

## Safe mode

`--safe-mode` / `safe_mode`: only BER/PDU framing on the baseline GetResponse is
evaluated. Community, version, noSuch, GetNext, type, OID-echo, clone, and stock
`sysDescr` probes are skipped.

## Spec references

- [RFC 1157](https://www.rfc-editor.org/rfc/rfc1157.html) — SNMPv1 (Get / GetNext, `request-id`, `noSuchName`)
- [RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html) — SNMPv2c PDU (exception tags, GetNext)
- [RFC 1213](https://www.rfc-editor.org/rfc/rfc1213.html) — MIB-II (`sysDescr`, `sysObjectID`, `sysUpTime`)
- IANA: 161/udp SNMP

## Scoring

`PROTOCOL_STRATEGIES["snmp"]` activates **arbitrary_auth** + **static_signature**
only. High-signal examples: `snmp.arbitrary_community` / `snmp.response_clone`
(`decisive` when hit); request-id, version, noSuch, GetNext, type, and OID-echo
tells typically `high` when triggered. See [`SCORING.md`](SCORING.md).
