# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- **IPv4 CIDR subnet scans** via `--target 192.168.1.0/24` (max `/24`, 254 hosts)
- `--scan-concurrency` for parallel host audits (default 8); subnet JSON with summary + per-host reports
- **CLI help UX:** `-h`, `--help`, `/help`, `/?` aliases; Rich-styled help; compact figlet **H-AUDITOR** ANSI header on run and help
- BBS-style GitHub Pages site (`docs/`) with `llms.txt`, `llms-full.txt`, `agents.md`, SEO/AEO/GEO files
- Animated Cowrie/Dionaea demo GIFs in README and `docs/demo/`
- Dionaea detection: FTP PASV private IP, STOR non-persistence, SMB framing fallback, HTTP/nginx tells, co-tenancy threshold tuning

### Changed

- Dependencies: `pyfiglet`, `rich-argparse` (figlet header + colored help)

## [0.2.1] - 2026-08-26

### Fixed

- FTP persist verify/login parity, banner on reconnect failure
- `normalize_uname` whitespace crash, VNC single-session handshake, SMTP RCPT 250 detection
- Public-target authorization note recorded in JSON when `--confirm-authorized` is used

### Security

- Expanded `SECURITY.md` (data handling, deep mode, Shodan keys, nmap trust)

## [0.2.0] - 2026-08-26

### Fixed

- FTP persist verify now uses the same login/CWD paths as upload (incl. `/` and anonymous)
- FTP banner indicator preserved when reconnect/LIST fails
- `normalize_uname` no longer crashes on whitespace-only output
- VNC probe uses one TCP session for the full RFB handshake
- SMTP deep FSM detects RCPT 250 success without relying on exceptions

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
