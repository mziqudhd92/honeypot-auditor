# SNMP probe

Honeypot-auditor’s SNMP engine speaks **community-based SNMPv1 / SNMPv2c**
(RFC 1157, RFC 3416) over **UDP/161** (lab **1161**, alternate lab **10161**).

It focuses on **RFC non-compliance** tells common in OpenCanary / Conpot-class
SNMP stubs: any-community acceptance, broken request-id echo, invalid version
handling, and success responses for nonexistent OIDs.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| GetRequest for `sysDescr.0` | SetRequest / write communities |
| GetRequest for a nonexistent enterprise OID | Walk / BulkWalk of large trees |
| Random community probes (two) | SNMPv3 USM brute force |

## Indicators

### Arbitrary auth

| ID | Trigger |
|----|---------|
| `snmp.arbitrary_community` | Two independent random community strings both receive a successful GetResponse for `sysDescr.0`. **Decisive** when hit. |

Well-known `public` success alone is **not** scored (common on real gear).

### Static / RFC conformance

| ID | Trigger |
|----|---------|
| `snmp.request_id` | GetResponse `request-id` ≠ request (RFC 1157 §4.1 requires echo). |
| `snmp.version_facade` | Message `version=99` still yields a successful GetResponse (unsupported versions should be dropped). |
| `snmp.nosuch_success` | Nonexistent OID returns `error-status=0` with a populated value (v1 should use `noSuchName`; v2c should use exception tags). |
| `snmp.ber_framing` | UDP reply is not a parseable SNMP BER message, or PDU is not GetResponse (`0xA2`). |
| `snmp.stock_sysdescr` | `sysDescr` matches stock lure tokens (`opencanary`, `conpot`, `fake snmp`, …). Generic Linux tokens are corroboration-gated. |

## Safe mode

`--safe-mode`: only BER/PDU framing on the baseline GetResponse is evaluated;
community / version / noSuch probes are skipped.

## Spec references

- [RFC 1157](https://www.rfc-editor.org/rfc/rfc1157.html) — SNMPv1
- [RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html) — SNMPv2c PDU
- IANA: 161/udp SNMP

## Scoring

`PROTOCOL_STRATEGIES["snmp"]` activates **arbitrary_auth** + **static_signature**
(no state-nonpersist axis for community SNMP Get-only probes).
