# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.6.x   | Yes       |
| 0.5.x   | Yes       |
| 0.4.x   | Yes       |
| 0.3.x   | Yes       |
| ≤ 0.2.x | No        |

## Reporting a vulnerability

Please **do not** open public GitHub issues for security problems.

Email **security@helloaeterna.com** privately with:

- Description and impact
- Steps to reproduce
- Affected version

We aim to acknowledge within 5 business days.

## Intended use

This tool performs **active network probes** against a single operator-chosen target.
It is for authorized defensive research, lab validation, and purple-team work only.

### Authorization gate

- **Private / loopback / RFC1918** targets run without extra flags.
- **Public IPs** require `--confirm-authorized`. This is **self-attestation** — the
  tool cannot verify permission. The JSON report records when the flag was used.
- Misuse against systems you do not own may violate law and provider terms.

### Data handling

- JSON reports and console output may contain **target banners, command output,
  and probe usernames** (never passwords). Treat `--output` files as sensitive.
- Shodan API keys are read from `--shodan-key` or `SHODAN_API_KEY` and sent only
  to Shodan's API for the resolved target IP.

### Deep mode (`--deep`)

- May run shell commands on the target **if SSH auth succeeds** (semantics checks,
  `/tmp` write/read, egress bait via `getent`/`nslookup`). Only use on systems
  you are cleared to test.
- TLS fingerprint probes use **certificate verification disabled** by design
  (banner/stack fingerprinting only).

### Safe mode (`--safe-mode`)

- Recommended for first touch on unknown subnets (authorized engagements).
- Disables deep shell/path/auth probes even when `--deep` is passed.
- Handshake-only: SSH KEXINIT/banner, HTTP GET/HEAD, pre-auth protocol phases.

### Proxy egress (`--proxy socks5h://…`)

- Prefer **`socks5h://`** (remote DNS) to avoid operator DNS leaks.
- Bare `socks5://` with hostname targets is rejected unless `--proxy-allow-local-dns`.
- Credentials are never logged; use `HONEYPOT_AUDITOR_PROXY` env var alternatively.

### Passive-first / OSINT (`--passive-first`, `--osint-only`)

- `--osint-only` runs Shodan intel only — no TCP probes.
- `--passive-first` skips active probes when passive Shodan score is high.
- Does not replace `--confirm-authorized` for public targets.

### External binaries

- Optional **Nmap** integration executes the host `nmap` binary. Use a trusted
  installation on CI runners and operator workstations.

### TLS lure profiles

- Packaged `data/tls_profiles.json` ships with placeholder JA3S values until you run
  `scripts/capture-tls-baseline.sh` against authorized lab lures. Placeholders are
  ignored at match time (no false positives).

### GitHub Action

- Pass `target` / `preset` only from trusted workflow inputs. Values are validated
  against a strict allowlist before argv construction.
- Public targets require `confirm_authorized: true` (same as CLI `--confirm-authorized`).
- Prefer installing from the checked-out repo (`pip install -e ".[full]"`) so CI uses
  the same package data as the commit under test.

## Safe defaults

- No exploit payloads or SMTP DATA exfiltration.
- Shodan lookups skipped on private addresses.
- Probe artifacts (FTP uploads, Redis keys) are deleted when possible.
