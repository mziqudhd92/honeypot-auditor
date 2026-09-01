# Signatures

Declarative fingerprint packs for honeypot-auditor.

## Overview

- Core JSON packs ship with the package (`signatures/core/*.json`).
- Community YAML packs require `pip install "honeypot-auditor[full]"` (`pyyaml`).
- No arbitrary Python hooks in signature files — primitives only.

## Primitives

| Primitive | Description |
|-----------|-------------|
| `exact_bytes` | Raw response prefix match |
| `regex` | Banner/substring pattern |
| `header_sequence` | Ordered HTTP header names |
| `header_absent` | Missing header (e.g. Date) |
| `ja3s_equals` | TLS JA3S hash match |
| `http2_settings_sequence` | HTTP/2 SETTINGS ID order |
| `jmespath` | JSON probe response query |

## TLS fingerprints (JA3S / JA4S)

TLS stack tells live in deep mode (`probe_tls_stack` / `deep.tls_stack`) and in
declarative packs via `ja3s_equals`.

### How fingerprints are produced

1. **Audit profile (default)** — send a **fixed** ClientHello template so JA3S/JA4S
   are stable across auditor OS/Python/OpenSSL builds.
2. **Blend profile** (`--profile blend`) — rotate seeded browser-like ClientHello
   templates; JA3S is reported informationally and **does not** score lure matches.
3. Parse ServerHello:
   - **TLS 1.2** → **JA3S** (`md5` of version,cipher,extensions)
   - **TLS 1.3+** → **JA4S**-style hash (`compute_ja4s`)
4. Compare against packaged profiles in `data/tls_profiles.json`:
   - `lures` — stock honeypot TLS faces (score when matched in audit profile)
   - `cdn_edge` — known CDN edges (informational / suppression context)

### Signature primitive

```json
{
  "id": "tls.example_lure",
  "match": { "ja3s_equals": "aabbccddeeff00112233445566778899" },
  "category": "stack_fingerprint",
  "tell_tier": "edge"
}
```

Edge-tier TLS tells are **suppressed** when `proxy_detect` finds a CDN/reverse proxy;
origin/app tells continue scoring.

### Capturing lab baselines

Use the helper script against an authorized lab target:

```bash
./scripts/capture-tls-baseline.sh 127.0.0.1 443
```

Paste resulting JA3S/JA4S into `tls_profiles.json` lure entries (never commit live
production hashes without review). Wildcard SNI acceptance is a separate
behavioral tell (`tls.wildcard_sni`), not a JA3S hash.

### Related indicators

| Indicator | Notes |
|-----------|--------|
| `deep.tls_stack` | JA3S/JA4S lure match + cert CN + cipher stability |
| `tls.wildcard_sni` | Invalid SNI (`invalid.test.local`) still yields HTTP 200 |
| `deep.http2_settings` | HTTP/2 SETTINGS ID order after ALPN `h2` |

## Proxy suppression

Edge-tier tells (`http_header_order`, `tls_ja3s` / `deep.tls_stack`, `http2_settings`,
`tls.wildcard_sni`, `deep.tcp_synack_options`) are suppressed when a CDN/reverse
proxy is detected. Origin/app tells continue scoring.

## Developer workflow

```bash
honeypot-auditor check-sig path/to/signature.yaml
```

See contributor tests in `tests/fixtures/signatures/`.
