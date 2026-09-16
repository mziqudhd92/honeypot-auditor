# DNS probe

Honeypot-auditor’s DNS engine speaks **classic DNS over UDP**
([RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html)) with a light
[RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html) EDNS0 OPT check on
**UDP/53** (lab **15353**).

It targets shallow DNS stubs that answer without parsing the request: wrong
transaction IDs, ignored question sections, illegal OPCODE facades, NXDOMAIN
names answered as NOERROR, canned identical datagrams, broken 0x20 case echo,
and EDNS FORMERR on a *valid* OPT. It does **not** rely on product IOC lists
alone.

## Strategies

DNS activates one of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["dns"]`):

| Strategy | Why it applies to DNS |
|----------|------------------------|
| **arbitrary_auth** | **Not used.** Classic DNS has no credential on the basic QUERY path; recursion flags are not auth. |
| **static_signature** | Almost all DNS honeypot tells are protocol-facade failures: header framing, txid, OPCODE/QR, question echo, RCODE stubs, response clones, 0x20 case, EDNS mishandling, stock lure TXT/SOA. |
| **state_nonpersist** | **Not used.** UDP QUERY/RESPONSE has no session to resume. |

Detection philosophy:

1. **Baseline speakership** — A QUERY for a synthetic mixed-case `hpaudit-<nonce>.invalid` name. No parseable QR=1 header → framing tell or suite skip.
2. **Request fidelity** — response ID, question section (including 0x20 casing), and RCODE for `.invalid` must match the RFCs; canned identical UDP payloads are decisive.
3. **Facade probes** — reserved/illegal OPCODE should be dropped (or FORMERR), not answered as a normal QUERY (UDP timeout on drop is a clean non-hit); a *valid* EDNS OPT must not produce FORMERR/garbage (timeout → skip; OPT *absence* alone is not a hit).
4. **Lure text last** — stock TXT/SOA tokens corroborate; weak strings need another hit.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| Single A QUERY for `hpaudit-<nonce>.invalid` (mixed-case 0x20) | AXFR / IXFR / zone transfer |
| Second QUERY with a distinct transaction ID | ANY / amplification / large EDNS size games |
| One reserved/illegal OPCODE probe | Recursive open-resolver scanning beyond the target |
| One QUERY carrying a valid EDNS0 OPT RR | Forced truncation (`TC`) without a lab zone |
| Inspect TXT/SOA rdata already returned | DoH / DoT |

Packet budget: ≤ **8** UDP exchanges per host.

## Ports

| Port | Mode |
|------|------|
| 53 | Production DNS (UDP) |
| 15353 | Lab DNS (UDP) |

## Probe flow

```text
A QUERY hPaUdIt-<n>.iNvAlId  ──►  header framing (QR=1 speaker)
        │
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ txid echo on baseline
        ├─ question section / QDCOUNT echo (+ 0x20 casing)
        ├─ RCODE for .invalid (expect NXDOMAIN)
        ├─ illegal OPCODE probe → header_facade
        ├─ second distinct-ID QUERY → response_clone
        ├─ QUERY + valid OPT → edns_facade
        └─ TXT/SOA lure tokens → stock_payload (often corroboration-gated)
```

## Indicators

### Static / RFC conformance

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `dns.header_framing` | static_signature | high | no | UDP reply is not a parseable DNS header, or QR≠1 on a QUERY response. |
| `dns.txid` | static_signature | high | no | Response transaction ID ≠ request (RFC 1035 §4.1.1). |
| `dns.header_facade` | static_signature | high | no | Illegal/reserved OPCODE is answered as a normal QUERY response (should drop or FORMERR). Silent drop/timeout is **not** a hit. |
| `dns.question_echo` | static_signature | high | no | Response QDCOUNT=0 or question QNAME/QTYPE/QCLASS does not match the request. |
| `dns.rcode_stub` | static_signature | high | no | Synthetic `.invalid` name returns NOERROR with answer RRs (RFC 2606 expects NXDOMAIN). |
| `dns.response_clone` | static_signature | decisive | no | Two QUERYs with distinct IDs receive **bitwise-identical** UDP payloads. |
| `dns.case_encoding_mismatch` | static_signature | high | **yes** (gated) | Question QNAME casing was rewritten (typically fully lowercased). Alone is weak — some real forwarders lowercase; needs another ungated DNS tell to stand alone in scoring. |
| `dns.edns_facade` | static_signature | high | no | A **valid** OPT RR yields FORMERR or an unparseable reply. Timeout → skip. Mere OPT absence in a normal reply is **not** a hit. |
| `dns.stock_payload` | static_signature | medium | **yes** (gated) | Answer/authority TXT or SOA rdata matches stock lure tokens (`honeypot`, `dionaea`, `opencanary`, `conpot`, `dns honeypot`, …). |

## Safe mode

`--safe-mode` / `safe_mode`: only header framing on the baseline QUERY response is
evaluated. Txid, facade, question, RCODE, clone, 0x20, EDNS, and stock probes are
skipped.

## Spec references

- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html) — DNS header, QD/AN, ID/QR/OPCODE/RCODE
- [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html) — EDNS0 OPT pseudo-RR
- [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606.html) — reserved `.invalid`
- IANA: 53/udp DNS

## Scoring

`PROTOCOL_STRATEGIES["dns"]` activates **static_signature** only.
High-signal examples: `dns.response_clone` (`decisive`); txid / header facade /
question echo / RCODE stub / EDNS typically `high` when triggered. Gated tells
(`case_encoding_mismatch`, `stock_payload`) need corroboration. See
[`SCORING.md`](../SCORING.md).

## FP notes

- **0x20 forwarders** — some recursive resolvers lowercase QNAMEs; `dns.case_encoding_mismatch` is corroboration-gated when it fires alone.
- **Filtered UDP** — timeout / empty reply → suite skip (not a framing hit). ICMP refused (connected mode) likewise skips.
- **EDNS-optional servers** — ignoring OPT without FORMERR is fine; only mishandling a valid OPT scores.
- **Real NXDOMAIN vs NOERROR/NODATA** — probe uses `.invalid`; NOERROR *with answers* is the stub tell, not empty NOERROR/NODATA alone.
