# Deception audit workflow

Blue/purple team guide for validating deception deployments before attackers find leaks.

## Quick start

```bash
honeypot-auditor --target YOUR_DECOY --preset deception-audit --deep -v \
  --confirm-authorized
```

## Honeyscore vs Confidence

- **Honeyscore (0–100%)**: weighted indicator sum — same engine as CTI use.
- **Confidence (low/medium/high)**: audit breadth — how many protocols and categories contributed.

## Output fields

- `deception_leaks`: ranked remediation list for blue teams
- `proxy_detected` / `proxy_context`: edge proxy awareness
- `suppressed`: edge tells masked by CDN (still listed for visibility)

## Temporal realism (deep)

Low-interaction decoys often answer every client in the same few milliseconds.
With `--deep`, the auditor checks:

1. **Serial** uniformity (`deep.latency`)
2. **Concurrent load** (`deep.latency_under_load`) — several parallel banner RTTs;
   traps that stay fast and flat (no stretch vs baseline) score as a temporal leak

Remediation: add connection limits / scheduling jitter so RTTs vary under parallel clients.

## Preset: deception-audit

Enables deep probes, verbose output, and deception-focused port map. Pair with `--signature-pack community` only after reviewing pack contents.

See [SCORING.md](SCORING.md) for weight tables.
