# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.7.x   | Yes       |
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
  to an allowlisted HTTPS Shodan API host for the resolved target IP.
- Other passive-intel providers run only after an explicit `--intel-provider NAME`.
  Prefer `HONEYPOT_AUDITOR_INTEL_<NAME>_KEY` over `--intel-key NAME=KEY` so keys
  do not enter shell history. Provider errors are redacted before logging or export.

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

### Passive-first / OSINT (`--passive-first`, `--osint-only`, `--passive-first-confirm`)

- `--osint-only` runs passive intel only — no TCP probes.
- `--passive-first` skips active probes when the passive score is high.
- `--passive-first-confirm` overrides that skip with a **safe-mode** active verify
  (handshake-only; never enables deep/shell probes).
- Does not replace `--confirm-authorized` for public targets.

### Passive-intel plugin boundary

- Installed providers are inert until selected by exact, validated name.
- Only the selected entry point is imported, and it runs once for the resolved host.
- Providers may emit only the passive-intel or informational category; they cannot
  escalate findings into arbitrary-authentication or active-probe categories.
- Provider packages execute third-party Python code. Install only reviewed packages
  from a trusted source and grant each key the minimum provider-side permissions.

### POP3 probe safety

- POP3 checks greeting framing, pre-authentication command state, unknown-command
  handling, and two independent synthetic login pairs.
- After a synthetic login is accepted, it sends `QUIT`. It never sends `LIST`, `RETR`,
  `TOP`, `DELE`, or other commands that read or modify a maildrop.

### External binaries

- Optional **Nmap** integration executes the host `nmap` binary. Use a trusted
  installation on CI runners and operator workstations.
- On Windows, raw-socket probes can require Npcap and an elevated terminal. Missing
  capabilities are reported and the affected probes are skipped rather than guessed.

### TLS lure profiles

- Packaged `data/tls_profiles.json` and `data/cdn_tls_profiles.json` ship with
  placeholder JA3S values until you run `scripts/capture-tls-baseline.sh` against
  authorized lab lures. Default output is `.lab-tls-capture/` (merge-safe);
  `--update-package` writes into the packaged files. Placeholders are ignored at
  match time (no false positives).

### GitHub Action

- Pass `target` / `preset` only from trusted workflow inputs. Values are validated
  against a strict allowlist before argv construction.
- Public targets require `confirm_authorized: true` (same as CLI `--confirm-authorized`).
- Prefer installing from the checked-out repo (`pip install -e ".[full]"`) so CI uses
  the same package data as the commit under test.

## Safe defaults

- No exploit payloads or SMTP DATA exfiltration.
- Shodan lookups skipped on private addresses.
- Passive-intel plugins are off unless named explicitly.
- Probe artifacts (FTP uploads, Redis keys) are deleted when possible.
