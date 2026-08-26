# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | Yes       |

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

### External binaries

- Optional **Nmap** integration executes the host `nmap` binary. Use a trusted
  installation on CI runners and operator workstations.

## Safe defaults

- No exploit payloads or SMTP DATA exfiltration.
- Shodan lookups skipped on private addresses.
- Probe artifacts (FTP uploads, Redis keys) are deleted when possible.
