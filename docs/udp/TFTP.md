# TFTP probe

Honeypot-auditor’s TFTP engine speaks **RFC 1350**
([RFC 1350](https://www.rfc-editor.org/rfc/rfc1350.html)) with a light
[RFC 2347](https://www.rfc-editor.org/rfc/rfc2347.html) option probe over
**UDP/69** (lab **1069**).

It targets Conpot / IoT-class TFTP stubs with **RFC non-compliance** checks:
servers that reply from the service port instead of a new TID, serve DATA for
missing files, ignore illegal modes, or choke on `blksize` options. It does
**not** upload DATA blocks or rely on product brand IOCs alone.

## Strategies

TFTP activates one of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["tftp"]`):

| Strategy | Why it applies to TFTP |
|----------|------------------------|
| **arbitrary_auth** | **Empty.** RFC 1350 has no credential exchange; we do not invent password probes. |
| **static_signature** | TID source-port, opcode/error/mode/WRQ facades, RFC 2347 option blindness, stock lure tokens in ERROR/DATA. |
| **state_nonpersist** | **Not used.** TFTP transfers are request/response over UDP with no session mailbox to contradict (and we never complete a write). |

Detection philosophy:

1. **Baseline speakership** — RRQ for a synthetic missing file (`hpaudit-<nonce>.bin`, mode `octet`). Parseable TFTP reply required; garbage → framing.
2. **TID fidelity** — reply `peer_port` must not equal the destination service port (69/1069).
3. **Opcode / error / mode / WRQ** — missing files and illegal modes must not serve DATA; WRQ must not return DATA.
4. **Options (light)** — RRQ + `blksize=512` expects OACK or a proper ERROR — not `ERROR 0` with an empty message.
5. **Lure text last** — stock tokens in ERROR/DATA corroborate; weak strings are gated.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| RRQ for a synthetic nonexistent filename (mode `octet`) | Sending DATA blocks (upload / bulk read completion) |
| RRQ with an illegal mode string | Directory walks or multi-block downloads |
| WRQ header only (no subsequent DATA) | Amplification or third-party redirection |
| RRQ + `blksize=512` option; ACK of OACK only | Writing files to the target |

Packet budget: ≤ **8** UDP exchanges per host.

## Ports

| Port | Mode |
|------|------|
| 69 | Production TFTP (UDP) |
| 1069 | Lab TFTP (UDP) |

## Probe flow

```text
RRQ hpaudit-<nonce>.bin octet  ──►  framing + TID (peer_port) + error/opcode/stock
        │
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ peer_port == dst_port → tftp.fixed_source_port
        ├─ RRQ mode=hpaudit → tftp.mode_facade
        ├─ WRQ header only → tftp.wrq_stub
        ├─ RRQ + blksize=512 → OACK? ACK via udp_exchange_to(TID)
        │                       else option_blindness
        └─ ERROR/DATA lure tokens → tftp.stock_payload (corroboration-gated)
```

First exchanges use unconnected `udp_exchange` so the peer TID is learned.
Follow-ups to that TID use `udp_exchange_to` (never `connected=True` on the
initial RRQ).

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
| `tftp.stock_payload` | static_signature | medium | **yes** | ERROR message or DATA block matches stock lure tokens (`honeypot`, `conpot`, `tftp stub`, …). |

## Safe mode

`--safe-mode` / `safe_mode`: only TFTP framing on the baseline RRQ reply is
evaluated. TID, opcode, error, mode, WRQ, option, and stock probes are skipped.

## Spec references

- [RFC 1350](https://www.rfc-editor.org/rfc/rfc1350.html) — The TFTP Protocol (Revision 2): opcodes, TID, ERROR codes
- [RFC 2347](https://www.rfc-editor.org/rfc/rfc2347.html) — TFTP Option Extension (OACK / `blksize`)
- IANA: 69/udp TFTP

## Scoring

`PROTOCOL_STRATEGIES["tftp"]` activates **static_signature** only.
High-signal example: `tftp.fixed_source_port` (`high` when hit). See
[`SCORING.md`](../SCORING.md) (rollup blurbs land after protocol merges).

## FP notes

- **TID middleboxes** — some NATs rewrite source ports; we fire
  `fixed_source_port` **only** when `peer_port == requested dst_port`
  (69 or 1069), not merely “non-ephemeral”.
- **Option-less servers** — a real tftpd that ignores RFC 2347 options and
  returns a normal missing-file ERROR (code 1) is **not** option blindness.
  Only `ERROR 0`/empty (or similar choke) scores.
- **Filtered UDP** — timeout / ICMP refuse → suite skip, not a honeypot hit.
