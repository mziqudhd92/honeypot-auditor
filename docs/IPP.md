# IPP / CUPS probe

Honeypot-auditor’s IPP/CUPS engine speaks **HTTP** (with **TLS fallback**) on
**631** (lab **1631**) and sends light **IPP** POSTs (`Get-Printer-Attributes` plus
an illegal operation-id). It targets CUPS admin skins and print-service stubs that
ignore path/method/IPP fidelity or return canned IPP payloads. It never submits
print jobs or changes queues.

## Strategies

IPP activates **one** of the three basic scoring strategies
(`PROTOCOL_STRATEGIES["ipp"]`):

| Strategy | Why it applies to IPP/CUPS |
|----------|----------------------------|
| **static_signature** | Primary axis. Decoy CUPS faces are usually canned HTTP/IPP handlers: wrong root framing, stock `Server` strings, unknown paths that echo `/`, DELETE ignored, `/printers` stub/root echo, open `/admin`, frozen `Date`, IPP POSTs that return HTML, successful-ok for missing printers, non-echoed request-ids, bitwise-identical IPP replies, illegal ops accepted, or honeypot phrases in the body. |
| **arbitrary_auth** | **Not used** on the basic read-only path (no password spraying against `/admin`). |
| **state_nonpersist** | **Not used.** No job queue resume to contradict. |

Detection philosophy:

1. **Baseline speakership** — `GET /` must look like CUPS/IPP HTTP (`Server: CUPS/…`, CUPS HTML markers, or redirect into `/admin`/`/printers`/`/ipp`). Bare “printer” marketing HTML is **not** enough.
2. **TLS fallback** — cleartext first; if the peer returns a TLS record layer (or cleartext fails), retry the suite over TLS on the same port.
3. **Path and method fidelity** — unknown paths should 404/401; `DELETE /` should not **echo the GET `/` body** (status-alone 200 is not a hit).
4. **Printers listing** — `/printers` should not echo root or advertise honeypot empty-queue copy. A bare empty 200 is **not** a stub (fresh CUPS).
5. **Admin surface** — unauthenticated `GET /admin` 200 with a CUPS admin face is a decoy tell; 401/403 is clean.
6. **Frozen Date** — identical `Date` across two GETs is a hit; missing `Date` on both is corroboration-gated.
7. **IPP framing** — `POST` with `Content-Type: application/ipp` should return parseable IPP, not the HTML root.
8. **Ghost printer** — `Get-Printer-Attributes` for a nonexistent `printer-uri` must not return `successful-ok`.
9. **Request-id echo** — IPP response request-id must match the request.
10. **Clone** — distinct IPP request-ids must not return bitwise-identical bodies (decisive).
11. **Illegal operation** — operation-id `0x7FFF` must not return `successful-ok` or HTML.
12. **Lure metadata** — decisive Server/body tokens score alone; frozen generic CUPS versions and product-named tokens are corroboration-gated.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `GET /` | Print-job create / send-document |
| `GET /printers`, `GET /admin` | Pause/resume/cancel printers |
| `GET /_hpa_nonexistent_*` | Admin password spray |
| `DELETE /` (expect reject) | Queue configuration writes |
| `POST` Get-Printer-Attributes | CUPS-Add-Modify-* operations |
| `POST` illegal operation-id | Any mutating IPP op |

## Ports

| Port | Mode |
|------|------|
| 631 | Production CUPS / IPP (HTTP, TLS fallback) |
| 1631 | Lab CUPS / IPP (HTTP, TLS fallback) |

Exchange budget is ≤9 HTTP requests once transport (cleartext or TLS) is chosen
(extra only when `/ipp/print` 404s and `/` is tried).

## Probe flow

```text
GET /  ──►  cleartext; TLS retry if record-layer / empty
        │
        ├─ CUPS/IPP HTTP framing
        ├─ safe-mode ──► stop (framing only)
        │
        ├─ Server header stock? → server_header
        ├─ body lure? → stock_body
        ├─ GET /_hpa_nonexistent_* → path_facade (+ Date pair)
        ├─ DELETE / → method_stub (body echo only)
        ├─ GET /printers → printers_stub
        ├─ GET /admin → admin_open
        ├─ frozen Date across GETs → frozen_date
        ├─ POST Get-Printer-Attributes → ipp_framing / ghost_printer / request_id
        ├─ second IPP request-id → ipp_clone
        └─ POST illegal op 0x7FFF → illegal_op
```

## Indicators

All indicators are category **`static_signature`**.

| ID | Fidelity | Corroboration | Trigger |
|----|----------|---------------|---------|
| `ipp.root_framing` | high | no | `GET /` is not a CUPS/IPP HTTP face. |
| `ipp.server_header` | medium | generic/frozen/product-named yes; decisive no | `Server` matches lure tokens. |
| `ipp.path_facade` | high | no | Unknown path returns complete 200 with the same body as `/`. |
| `ipp.method_stub` | high | no | `DELETE /` returns 200 **with the same body** as `GET /`. |
| `ipp.printers_stub` | medium | no | `/printers` echoes root or honeypot empty-queue copy (not bare empty). |
| `ipp.admin_open` | medium | empty 200 yes; CUPS admin body no | Unauthenticated `/admin` 200. |
| `ipp.frozen_date` | medium | missing-only yes; identical Date no | Missing or identical `Date` across two GETs. |
| `ipp.ipp_framing` | high | no | IPP POST is not parseable IPP (or echoes HTML root). |
| `ipp.ghost_printer` | high | no | Missing `printer-uri` returns IPP `successful-ok`. |
| `ipp.request_id` | high | no | Response request-id does not echo the request. |
| `ipp.ipp_clone` | decisive | no | Distinct request-ids return identical IPP bodies. |
| `ipp.illegal_op` | high | no | Illegal operation-id returns success or non-IPP. |
| `ipp.stock_body` | medium | generic yes; decisive no | HTML body contains honeypot lure phrases. |

## Safe mode

`--safe-mode` / `safe_mode`: root framing only (including TLS fallback); all other IPP indicators are skipped.

## Scoring notes

See [`docs/SCORING.md`](SCORING.md). `ipp.ipp_clone` is decisive when hit. Generic
`Server: CUPS/1.4.x` and product-named Server tokens alone are corroboration-gated.

## False-positive notes

- Real CUPS often redirects `/` → `/admin` with little body; framing accepts that.
- Auth-walled `/printers` or `/admin` (401/403) is **not** a stub / open admin.
- Fresh CUPS with an empty `/printers` body is **not** a stub.
- `DELETE /` returning 200 with a distinct error page is **not** a method stub.
- IPP POST denied (401/403/426) is skipped for IPP-body indicators, not triggered.
- Truncated bodies (`Content-Length` > received bytes) do not fire equality façades.
- Filtered UDP/TCP or timeouts skip the suite (no false hits). Cleartext failure
  followed by successful TLS is not a framing hit.
