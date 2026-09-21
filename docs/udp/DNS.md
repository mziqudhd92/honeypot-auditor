# DNS probe

Honeypot-auditor’s DNS engine speaks **classic DNS over UDP**
([RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html)) with a light
[RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html) EDNS0 OPT check on
**UDP/53** (lab **15353**).

It targets shallow DNS stubs that answer without parsing the request: wrong
transaction IDs, ignored question sections, illegal OPCODE facades, NXDOMAIN
names answered as NOERROR, canned identical datagrams, broken 0x20 case echo,
and EDNS FORMERR on a *valid* OPT. It also checks open-resolver-style acceptance
of entropy-varied private-label queries and frozen/contradictory answer state
across re-query. It does **not** rely on product IOC lists alone.

## Strategies

DNS activates **all three** basic scoring strategies
(`PROTOCOL_STRATEGIES["dns"]`):

| Strategy | Why it applies to DNS |
|----------|------------------------|
| **arbitrary_auth** | Two entropy-varied private-label / bogus-TLD queries both return **NOERROR** with answers/SOA (open-resolver / static SOA façade). Indicator: `dns.arbitrary_auth`. |
| **static_signature** | Protocol-facade failures: header framing, txid, OPCODE/QR, question echo, RCODE stubs, response clones, 0x20 case, EDNS mishandling, message-length incoherence, stock lure TXT/SOA. |
| **state_nonpersist** | Re-query shows a bitwise-identical **positive** answer, a frozen SOA serial in the answer section, or an AA/TTL contradiction. Authority SOA on NXDOMAIN is not a freeze. Indicator: `dns.state_nonpersist`. |

Detection philosophy:

1. **Baseline speakership** — A QUERY for a synthetic mixed-case `hpaudit-<nonce>.invalid` name. No parseable QR=1 header → framing tell or suite skip.
2. **Request fidelity** — response ID, question section (including 0x20 casing), and RCODE for `.invalid` must match the RFCs; canned identical UDP payloads are decisive.
3. **Facade probes** — reserved/illegal OPCODE should be dropped, FORMERR, or NOTIMP — not answered with **NOERROR** as a normal QUERY (UDP timeout on drop is a clean non-hit; NXDOMAIN/REFUSED for the QNAME are also clean). A *valid* EDNS OPT must not produce FORMERR/garbage (timeout → skip; OPT *absence* alone is not a hit).
4. **Byte-exact encoding** — a parseable response must consume exactly its declared sections: trailing pad bytes or miscounted ANCOUNT/ARCOUNT lengths score `dns.length_incoherence` (BIND/Unbound never pad unless an EDNS0 `PAD` option was requested).
5. **Open-resolver façade** — two entropy-varied private-label queries must not both land NOERROR with answers/SOA (`dns.arbitrary_auth`).
6. **Answer state** — after a short pause, re-query the baseline name; a bitwise-identical positive answer, a frozen SOA serial in the answer section, or an AA/TTL contradiction score `dns.state_nonpersist`. Authority SOA on NXDOMAIN/NODATA is normal negative caching.
7. **Lure text last** — stock TXT/SOA tokens corroborate; weak strings need another hit.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| Single A QUERY for `hpaudit-<nonce>.invalid` (mixed-case 0x20) | AXFR / IXFR / zone transfer |
| Second QUERY with a distinct transaction ID | ANY / amplification / large EDNS size games |
| Two entropy-varied private-label / bogus-TLD QUERYs | Recursive open-resolver scanning beyond the target |
| One reserved/illegal OPCODE probe | Forced truncation (`TC`) without a lab zone |
| One QUERY carrying a valid EDNS0 OPT RR | DoH / DoT |
| One re-query of the baseline name (state check) | Dynamic updates / NOTIFY |
| Inspect TXT/SOA rdata already returned | |

Packet budget: ≤ **8** UDP exchanges per host (baseline, facade, clone, EDNS,
dual auth queries, and one state re-query fit the budget).

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
        ├─ two private-label QUERYs → arbitrary_auth
        ├─ re-query baseline QNAME → state_nonpersist
        └─ TXT/SOA lure tokens → stock_payload (often corroboration-gated)
```

## Indicators

### Arbitrary auth / open-resolver façade

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `dns.arbitrary_auth` | arbitrary_auth | **decisive** when hit | no | Two entropy-varied private-label / bogus-TLD queries both return NOERROR with answers/SOA. |

### State non-persistence

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `dns.state_nonpersist` | state_nonpersist | high when hit | no | Re-query shows a bitwise-identical positive answer, a frozen answer-section SOA serial, or an AA/TTL contradiction. |

### Static / RFC conformance

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `dns.header_framing` | static_signature | high | no | UDP reply is not a parseable DNS header, or QR≠1 on a QUERY response. |
| `dns.txid` | static_signature | high | no | Response transaction ID ≠ request (RFC 1035 §4.1.1). |
| `dns.header_facade` | static_signature | high | no | Illegal/reserved OPCODE is answered with **NOERROR** (as a normal QUERY). Drop, FORMERR, NOTIMP, NXDOMAIN, and REFUSED are **not** hits. |
| `dns.question_echo` | static_signature | high | no | Response QDCOUNT=0 or question QNAME/QTYPE/QCLASS does not match the request. |
| `dns.rcode_stub` | static_signature | high | no | Synthetic `.invalid` name returns NOERROR with answer RRs (RFC 2606 expects NXDOMAIN). |
| `dns.response_clone` | static_signature | decisive | no | Two QUERYs with distinct IDs receive **bitwise-identical** UDP payloads. |
| `dns.case_encoding_mismatch` | static_signature | high | **yes** (gated) | Question QNAME casing was rewritten (typically fully lowercased). Alone is weak — some real forwarders lowercase; needs another ungated DNS tell to stand alone in scoring. |
| `dns.edns_facade` | static_signature | high | no | A **valid** OPT RR yields FORMERR or an unparseable reply. Timeout → skip. Mere OPT absence in a normal reply is **not** a hit. |
| `dns.length_incoherence` | static_signature | high | no | Parseable response leaves trailing bytes after its declared sections — conformant encoders (BIND/Unbound) emit byte-exact messages and never pad unless EDNS0 `PAD` was requested. |
| `dns.stock_payload` | static_signature | medium | **yes** (gated) | Answer/authority TXT or SOA rdata matches stock lure tokens (`honeypot`, `dionaea`, `opencanary`, `conpot`, `dns honeypot`, …). |

## Safe mode

`--safe-mode` / `safe_mode`: only header framing on the baseline QUERY response is
evaluated. Txid, facade, question, RCODE, clone, 0x20, EDNS, length, auth, state,
and stock probes are skipped.

## Spec references

- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html) — DNS header, QD/AN, ID/QR/OPCODE/RCODE
- [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html) — EDNS0 OPT pseudo-RR
- [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606.html) — reserved `.invalid`
- IANA: 53/udp DNS

## Scoring

`PROTOCOL_STRATEGIES["dns"]` activates **all three** basic strategies.
High-signal examples: `dns.arbitrary_auth` and `dns.response_clone` (`decisive`);
`dns.state_nonpersist`, txid / header facade / question echo / RCODE stub / EDNS
typically `high` when triggered. Gated tells (`case_encoding_mismatch`,
`stock_payload`) need corroboration. See [`SCORING.md`](../SCORING.md).

## FP notes

- **0x20 forwarders** — some recursive resolvers lowercase QNAMEs; `dns.case_encoding_mismatch` is corroboration-gated when it fires alone.
- **Filtered UDP** — timeout / empty reply → suite skip (not a framing hit). ICMP refused (connected mode) likewise skips.
- **EDNS-optional servers** — ignoring OPT without FORMERR is fine; only mishandling a valid OPT scores.
- **Real NXDOMAIN vs NOERROR/NODATA** — probe uses `.invalid`; NOERROR *with answers* is the stub tell, not empty NOERROR/NODATA alone.
- **Real open resolvers** — `dns.arbitrary_auth` can fire on intentional recursive faces; treat as a decoy signal in authorized honeypot audits, not as proof of malice alone.
