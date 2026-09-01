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

## Preset: deception-audit

Enables deep probes, verbose output, and deception-focused port map. Pair with `--signature-pack community` only after reviewing pack contents.

See [SCORING.md](SCORING.md) for weight tables.
