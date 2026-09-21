# HTTP probe guide

HTTP/1.1 fingerprinting for the `honeypot-auditor` basic probe. The engine
scores decoy web faces: login skins, static canned responses, framework
session tells, and servers that answer before reading the request body.

Ports **80** (clear) and **443**/**8443** (TLS, via the `requests` transport),
lab alias **8081**. `8080`/`3128` map to the HTTP-proxy engine instead. See
`PROTOCOL_STRATEGIES["http"]`.

## Strategies

| Strategy | Why it applies to HTTP |
|----------|------------------------|
| **arbitrary_auth** | Anonymous `GET /admin` is **401/403**, then two entropy-varied Basic pairs both return **200**. A public 200 is not a bypass. Indicator: `http.arbitrary_auth`. |
| **state_nonpersist** | Cookie replay returns **401/403**, or an accepted POST leaves no session side-effect and the GET replies with an identical canned page. A new `Set-Cookie` on 200 is session rotation, not a lie. Indicator: `http.state_nonpersist`. |
| **static_signature** | Canned 200 on a malformed POST, a **2xx** before an unterminated chunked body completes, missing `Date`, empty 405 method stubs, stock login-form skins, proxy-lure 407s, lure header orderings, framework session-on-404, and silent TCP accepts. Indicators: `http.malformed_200`, `http.chunked_premature`, `http.dynamic_headers`, `http.method_stub`, `http.login_skin`, `http.proxy_lure`, `http.header_order`, `http.framework_404_session`, `http.silent_accept`. |
| **proto_conformance** | An invalid wildcard `Host` header is still served 200. Indicator: `http.wildcard_host`. |

## Detection philosophy

1. **Baseline speakership** — a malformed binary POST must not return a canned
   `200 OK`; silence after TCP accept is itself scored (`http.silent_accept`).
2. **Read-the-body coherence** — a legal but *unterminated* chunked POST (one
   chunk, no terminal `0\r\n\r\n`) must keep the server waiting; our read
   timeout is a clean non-hit, and a **2xx** status line back is a
   reply-before-body-reading skin (`http.chunked_premature`, gated for
   100-continue/early-408 intermediaries). 4xx/5xx are allowed by RFC 9112
   and are not scored. TLS faces skip this plaintext probe.
3. **Method fidelity** — `PUT`/`DELETE` answered by an empty `405` body is the
   classic stub (`http.method_stub`).
4. **Skin hunting** — `/` redirecting to `index.html`, username+password forms
   on `/` or `index.html`, and common admin paths (`/phpmyadmin/`, `/admin/`,
   `/login`) with stock login forms score `http.login_skin`.
5. **Dynamic headers** — real servers emit `Date`; frozen header sets score
   `http.dynamic_headers`.
6. **Proxy lures** — 407 responses with `Via: localhost`, frozen
   `squid 3.3.8`, or ISA deny phrases score `http.proxy_lure`; lure header
   *orderings* score `http.header_order` (only alongside another static hit
   and suppressed when a reverse proxy is detected).
7. **Host validation** — wildcard/invalid `Host` values must be rejected
   (400/421/444); a 200 scores `http.wildcard_host`.
8. **Framework tells** — 404s from Werkzeug/gunicorn/uvicorn that hand out
   session cookies score `http.framework_404_session`.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| `GET`/`HEAD` on `/`, `/index.html`, common admin paths | Credential reuse or password spraying (entropy-varied synthetic pairs only) |
| Malformed binary POST (8 bytes, closed immediately) | Exploit payloads / path traversal |
| Chunked POST with **one small chunk and no terminal chunk** | Request smuggling (pipelining/TE·CL games are out of scope) |
| `PUT`/`DELETE` with empty body | Writing content |
| `Basic` auth with entropy-varied synthetic credentials | — |

## Ports

| Port | Mode |
|------|------|
| 80 | Clear HTTP |
| 443 / 8443 | HTTPS (TLS via `requests`) |
| 8081 | Lab alias |

## Probe flow

```text
malformed POST  ──►  canned 200? → http.malformed_200 · silent TCP → http.silent_accept
        │
        ├─ safe-mode ──► GET/HEAD only (dynamic_headers / silent_accept)
        │
        ├─ GET / (+ TLS transport on 443)  → login_skin · dynamic_headers · framework_404_session
        ├─ PUT /index.html (empty)         → method_stub
        ├─ unterminated chunked POST       → chunked_premature (2xx only; TLS skipped)
        ├─ wildcard Host GET               → wildcard_host
        ├─ anon 401/403 then dual Basic    → arbitrary_auth
        └─ cookie replay 401/403?          → state_nonpersist
```

## Indicators

| ID | Category | Fidelity | Corroboration | Trigger |
|----|----------|----------|---------------|---------|
| `http.arbitrary_auth` | arbitrary_auth | decisive when hit | no | Anonymous `/admin` was 401/403, then two entropy-varied Basic pairs both 200. |
| `http.state_nonpersist` | state_nonpersist | high when hit | no | Cookie replay returns 401/403; accepted POST with identical canned page and no side-effect. A new Set-Cookie on 200 is not scored. |
| `http.malformed_200` | static_signature | medium | no | Canned `200 OK` on a malformed binary POST. |
| `http.chunked_premature` | static_signature | high | **yes** (gated) | **2xx** returned before the terminal chunk of an unterminated chunked POST. 4xx/5xx are not scored. TLS faces skip this plaintext probe. |
| `http.dynamic_headers` | static_signature | medium | no | Response set missing `Date` (static header template). |
| `http.method_stub` | static_signature | medium | no | `PUT` answered by an empty `405`. |
| `http.login_skin` | static_signature | medium | no | `/` → `index.html` redirect, username+password form on landing pages, or stock admin-path login forms. |
| `http.proxy_lure` | static_signature | medium | no | 407 with `Via: localhost` / frozen `squid 3.3.8` / ISA deny phrases. |
| `http.header_order` | static_signature | medium (edge tier) | no | Response header ordering matches a lure profile — only with another static hit; suppressed when a reverse proxy is detected. |
| `http.wildcard_host` | proto_conformance | medium (origin tier) | no | Invalid/wildcard `Host` served `200`. |
| `http.framework_404_session` | static_signature | medium | no | Werkzeug/gunicorn/uvicorn 404 issuing a session cookie. |
| `http.silent_accept` | static_signature | medium | no | TCP accepted, request sent, no HTTP bytes before timeout (tarpit face). |

## Safe mode

`--safe-mode` / `safe_mode`: `GET`/`HEAD` only. `http.dynamic_headers` and
`http.silent_accept` are evaluated; malformed POST, chunked, method, login
skin, proxy, header-order, wildcard Host, auth, state, and framework probes
are skipped.

## Spec references

- [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html) — HTTP/1.1 (chunked transfer coding, message framing)
- [RFC 7231](https://www.rfc-editor.org/rfc/rfc7231.html) — methods and 405 semantics
- IANA: 80/tcp HTTP · 443/tcp HTTPS
