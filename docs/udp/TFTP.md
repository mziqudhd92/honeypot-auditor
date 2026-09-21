# TFTP probe

Honeypot-auditor’s TFTP engine speaks **RFC 1350**
([RFC 1350](https://www.rfc-editor.org/rfc/rfc1350.html)) with a light
[RFC 2347](https://www.rfc-editor.org/rfc/rfc2347.html) option probe over
**UDP/69** (lab **1069**).

It targets Conpot / IoT-class TFTP stubs with **RFC non-compliance** checks:
servers that reply from the service port instead of a new TID, reuse one TID
across transfers, serve canned identical DATA for distinct names, ignore illegal
modes, choke on `blksize`, or never retransmit OACK when ACK is withheld. It does
**not** upload DATA blocks or rely on product brand IOCs alone.

## Strategies

TFTP activates **two** of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["tftp"]`):

| Strategy | Why it applies to TFTP |
|----------|------------------------|
| **arbitrary_auth** | **Empty.** RFC 1350 has no credential exchange; we do not invent password probes. |
| **static_signature** | TID source-port, opcode/error/mode/WRQ facades, RFC 2347 option blindness, response clone, no OACK/DATA retransmit, DATA blocks over 512 bytes without a larger negotiated `blksize`, stock lure tokens in ERROR/DATA. |
| **state_nonpersist** | Server TID reused across independent missing-file RRQs (real tftpd allocates a new TID per transfer). |

Detection philosophy:

1. **Baseline speakership** — RRQ for a synthetic missing file (`hpaudit-<nonce>.bin`, mode `octet`). Parseable TFTP reply required; garbage → framing.
2. **TID fidelity** — reply `peer_port` must not equal the destination service port (69/1069).
3. **Second RRQ** — distinct filename: detect TID reuse (`state_nonpersist`) and canned identical DATA/stub ERROR clones (`response_clone`). Normal identical “File not found” ERROR is **not** scored as a clone.
4. **Opcode / error / mode / WRQ** — missing files and illegal modes must not serve DATA; WRQ must not return DATA.
5. **Options + retransmit** — RRQ + `blksize=512` expects OACK or a proper ERROR. On OACK/DATA, withhold ACK briefly; one-shot stubs that never retransmit score `no_retransmit`. Then ACK OACK (no DATA upload).
6. **Block-size arithmetic** — RFC 1350 caps DATA payloads at 512 bytes and the only `blksize` we ever request is 512, so any served DATA block over 512 bytes scores `block_size_violation` outright.
7. **Lure text last** — stock tokens in ERROR/DATA corroborate; weak strings are gated.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| RRQ for synthetic nonexistent filenames (mode `octet`) | Sending DATA blocks (upload / bulk read completion) |
| RRQ with an illegal mode string | Directory walks or multi-block downloads |
| WRQ header only (no subsequent DATA) | Amplification or third-party redirection |
| RRQ + `blksize=512`; idle listen for OACK retransmit; ACK of OACK only | Writing files to the target |

Packet budget: ≤ **8** UDP exchanges per host (second RRQ + option retransmit watch share the budget).

## Ports

| Port | Mode |
|------|------|
| 69 | Production TFTP (UDP) |
| 1069 | Lab TFTP (UDP) |

## Probe flow

```text
RRQ hpaudit-<nonce>.bin octet  ──►  framing + TID + error/opcode/stock
        │
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ peer_port == dst_port → tftp.fixed_source_port
        ├─ RRQ hpaudit-<nonce2>.bin → tid_reuse / response_clone
        ├─ RRQ mode=hpaudit → tftp.mode_facade
        ├─ WRQ header only → tftp.wrq_stub
        ├─ RRQ + blksize=512 → OACK?
        │     ├─ idle listen (no ACK) → no_retransmit if silent
        │     └─ then ACK via udp_exchange_to(TID)
        │   else option_blindness / proper ERROR
        └─ ERROR/DATA lure tokens → tftp.stock_payload (corroboration-gated)
```

First exchanges use unconnected `udp_exchange` so the peer TID is learned.
Option OACK uses `udp_exchange_with_retransmit_watch` then `udp_exchange_to`
(never `connected=True` on the initial RRQ).

## Indicators

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `tftp.framing` | static_signature | high | no | UDP reply is not a parseable TFTP packet (opcode 1–6). |
| `tftp.fixed_source_port` | static_signature | **high** | no | Baseline reply `peer_port == dst_port` (RFC 1350 requires a new server TID). |
| `tftp.opcode_facade` | static_signature | high | no | RRQ for a missing file is answered with DATA or ACK instead of ERROR. |
| `tftp.error_stub` | static_signature | high | no | Missing-file RRQ returns DATA success, or ERROR code outside 0–7 (RFC 1350 §5). |
| `tftp.mode_facade` | static_signature | high | no | Illegal mode (`hpaudit`) still yields DATA (should ERROR / drop). |
| `tftp.wrq_stub` | static_signature | high | no | WRQ answered with DATA instead of ACK(0) or ERROR. |
| `tftp.option_blindness` | static_signature | high | no | RRQ+`blksize` yields `ERROR 0` with empty message (or equivalent option choke) instead of OACK / proper ERROR. |
| `tftp.tid_reuse` | **state_nonpersist** | high | no | Two independent RRQs reuse the same ephemeral server TID (`peer_port` equal and ≠ dst). |
| `tftp.response_clone` | static_signature | high | no | Bitwise-identical DATA/ACK (or stubby ERROR 0/empty / out-of-range) for distinct missing-file RRQs. Normal identical “File not found” is **not** a hit. |
| `tftp.no_retransmit` | static_signature | high | no | OACK or DATA from optioned RRQ is not retransmitted while ACK is withheld. |
| `tftp.block_size_violation` | static_signature | high | no | Any served DATA block exceeds 512 bytes (only `blksize=512` is ever requested; RFC 1350 §5 caps blocks at 512). |
| `tftp.stock_payload` | static_signature | medium | **yes** | ERROR message or DATA block matches stock lure tokens (`honeypot`, `conpot`, `tftp stub`, …). |

## Safe mode

`--safe-mode` / `safe_mode`: only TFTP framing on the baseline RRQ reply is
evaluated. TID, opcode, error, mode, WRQ, option, reuse/clone/retransmit, and
stock probes are skipped.

## Spec references

- [RFC 1350](https://www.rfc-editor.org/rfc/rfc1350.html) — The TFTP Protocol (Revision 2): opcodes, TID, ERROR codes
- [RFC 2347](https://www.rfc-editor.org/rfc/rfc2347.html) — TFTP Option Extension (OACK / `blksize`)
- IANA: 69/udp TFTP

## Scoring

`PROTOCOL_STRATEGIES["tftp"]` activates **static_signature** and
**state_nonpersist**. High-signal examples: `tftp.fixed_source_port`,
`tftp.tid_reuse`. See [`SCORING.md`](../SCORING.md).

## FP notes

- **TID middleboxes** — some NATs rewrite source ports; we fire
  `fixed_source_port` **only** when `peer_port == requested dst_port`
  (69 or 1069), not merely “non-ephemeral”. `tid_reuse` only scores when the
  reused port is an ephemeral TID (≠ dst).
- **Identical File not found** — many real daemons return the same ERROR text
  for any missing name; that alone is **not** `response_clone`.
- **Option-less servers** — a real tftpd that ignores RFC 2347 options and
  returns a normal missing-file ERROR (code 1) is **not** option blindness.
  Only `ERROR 0`/empty (or similar choke) scores. `no_retransmit` is skipped
  when there is no OACK/DATA to watch.
- **Filtered UDP** — timeout / ICMP refuse → suite skip, not a honeypot hit.
- **Retransmit window** — idle wait is a fraction of `--timeout` (capped ~1s);
  slow WANs may need a higher timeout to avoid false `no_retransmit` hits.
