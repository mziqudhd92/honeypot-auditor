# C2 decoy vs live teamserver

Non-destructive HTTP tells that **never** treat “Cobalt Strike / Mythic / Sliver
detected” as proof of a honeypot. A stock C2 face may be a live panel, a
deception clone, or unrelated.

## Indicators

| ID | Meaning | Scoring |
|----|---------|---------|
| `http.c2_panel_or_decoy` | Ambiguous: stock CS-like empty 404/`text/plain`, or UI markers **with** a dynamic GraphQL/WebSocket/API backend | `requires_corroboration=True`, medium/low fidelity |
| `tls.c2_panel_or_decoy` | Ambiguous: default Cobalt Strike teamserver TLS CN/serial | `requires_corroboration=True`, low fidelity — never alone Confirmed |
| `http.c2_decoy_clone` | Static Mythic/CS/Sliver HTML UI **without** a live control-plane backend | high fidelity, `fingerprint_type=c2_decoy` |

## Rules of thumb

1. Empty `404` + `text/plain` alone is **not** Confirmed — it needs another ungated tell.
2. Static login/UI HTML without GraphQL / WebSocket upgrade / JSON API is scored as a decoy clone.
3. Default CS TLS serials stay in the ambiguous class only (do not alone raise honeypot confidence).

## Probing

Follow-up GETs/POSTs are read-only (`/graphql` typename, WebSocket upgrade headers, `/api/v1/info`) with short timeouts. No implant staging or credential attacks.
