# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] - 2026-08-26

### Added

- **`--deep` mode:** shell semantics, OS coherence, HASSH/TCP stack, protocol FSM fuzz, co-tenancy, latency/egress probes
- Nmap service-detection parsing for Cowrie/Dionaea product names (replaces missing `ssh-honeypot` NSE on Nmap 7.x)
- FTP welcome-banner tells (e.g. DiskStation / Dionaea)
- PyPI publish workflow (Trusted Publishing) and `docs/PUBLISHING.md`
- Expanded test suite with mocked recon/probes and Cowrie Docker integration job in CI
- Coverage gate raised to 60% (local suite ~73% with 96 tests)
- Coverage best practices: branch coverage, HTML/XML reports, dedicated CI job + artifacts, Makefile targets

### Changed

- Default deep co-tenancy requires corroboration from another emulator tell
- Nmap scans only open ports, prioritizes telnet/ssh for `-sV`

## [0.1.0] - 2026-08-26

### Added

- Initial release: multi-protocol honeypot fingerprint CLI
- Shodan Honeyscore + tag lookup
- Optional Nmap NSE integration
- Probes: SSH, Telnet, SMB, FTP, HTTP, Redis, SMTP, VNC, SIP
- Weighted Honeyscore with Rich console + JSON export
- Port presets: `iana`, `docker-research`
- Public-IP authorization gate (`--confirm-authorized`)
