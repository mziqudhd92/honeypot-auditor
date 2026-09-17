# IPP / CUPS probe

Honeypot-auditor’s IPP/CUPS engine speaks **HTTP** on **631** (lab **1631**) and
sends a light **IPP Get-Printer-Attributes** POST. It targets CUPS admin skins and
print-service stubs that ignore path/method fidelity or return canned IPP
payloads. It never submits print jobs or changes queues.

## Strategies

IPP activates **one** of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["ipp"]`):

| Strategy | Why it applies to IPP/CUPS |
|----------|----------------------------|
| **static_signature** | Primary axis. Decoy CUPS faces are usually canned HTTP handlers: wrong root framing, stock `Server` strings, unknown paths that echo `/`, DELETE ignored, `/printers` stub/root echo, IPP POSTs that return HTML, bitwise-identical IPP replies, or honeypot phrases in the body. |
| **arbitrary_auth** | **Not used** on the basic read-only path (no password spraying against `/admin`). |
| **state_nonpersist** | **Not used.** No job queue resume to contradict. |

Detection philosophy:

1. **Baseline speakership** — `GET /` must look like CUPS/IPP HTTP (`Server: CUPS/…`, printer-ish HTML, or redirect into `/admin`/`/printers`/`/ipp`).
2. **Path and method fidelity** — unknown paths should 404/401; `DELETE /` should not echo `GET /`.
3. **Printers listing** — `/printers` should not be an empty stub that copies the root document.
4. **IPP framing** — `POST` with `Content-Type: application/ipp` should return IPP, not the HTML root.
5. **Clone** — distinct IPP request-ids must not return bitwise-identical bodies (decisive).
6. **Lure metadata** — decisive Server/body tokens score alone; frozen generic CUPS versions are corroboration-gated.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `GET /` | Print-job create / send-document |
| `GET /printers` | Pause/resume/cancel printers |
| `GET /_hpa_nonexistent_*` | Admin password spray |
| `DELETE /` (expect reject) | Queue configuration writes |
| `POST` Get-Printer-Attributes | CUPS-Add-Modify-* operations |

## Ports

| Port | Mode |
|------|------|
| 631 | Production CUPS / IPP HTTP |
| 1631 | Lab CUPS / IPP HTTP |

## Probe flow

```text
GET /  ──►  CUPS/IPP HTTP framing
        │
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ Server header stock? → server_header
        ├─ body lure? → stock_body
        ├─ GET /_hpa_nonexistent_* → path_facade
        ├─ DELETE / → method_stub
        ├─ GET /printers → printers_stub
        ├─ POST Get-Printer-Attributes → ipp_framing
        └─ second IPP request-id → ipp_clone
```

## Indicators

All indicators are category **`static_signature`**.

| ID | Fidelity | Corroboration | Trigger |
|----|----------|---------------|---------|
| `ipp.root_framing` | high | no | `GET /` is not a CUPS/IPP HTTP face. |
| `ipp.server_header` | medium | generic/frozen yes; decisive no | `Server` matches lure tokens. |
| `ipp.path_facade` | high | no | Unknown path returns 200 with the same body as `/`. |
| `ipp.method_stub` | high | no | `DELETE /` returns 200 like `GET /`. |
| `ipp.printers_stub` | medium | no | `/printers` echoes root, empty stub, or honeypot empty-queue copy. |
| `ipp.ipp_framing` | high | no | IPP POST is not `application/ipp` / IPP binary (or echoes HTML root). |
| `ipp.ipp_clone` | decisive | no | Distinct request-ids return identical IPP bodies. |
| `ipp.stock_body` | medium | generic yes; decisive no | HTML body contains honeypot lure phrases. |

## Safe mode

`--safe-mode` / `safe_mode`: root framing only; all other IPP indicators are skipped.

## Scoring notes

See [`docs/SCORING.md`](SCORING.md). `ipp.ipp_clone` is decisive when hit. Generic
`Server: CUPS/1.4.x` alone is corroboration-gated.

## False-positive notes

- Real CUPS often redirects `/` → `/admin` with little body; framing accepts that.
- Auth-walled `/printers` (401/403) is **not** a stub.
- IPP POST denied (401/403/426) is skipped for `ipp.ipp_framing`, not triggered.
- Filtered UDP/TCP or timeouts skip the suite (no false hits).
