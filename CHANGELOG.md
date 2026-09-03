# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.7.0] - 2026-09-03

Thanks to [@fusiontechstrategies](https://github.com/fusiontechstrategies) (Jeffrey Friedler /
Fusion Technology Strategies) for the substantial contribution in
[#1](https://github.com/mziqudhd92/honeypot-auditor/pull/1), which this release builds on.

### Added

- Non-destructive POP3 engine on ports 110/1110: greeting framing, pre-auth state,
  unknown-command conformance, and repeated synthetic authentication
- Explicitly selected passive-intel providers through `honeypot_auditor.intel` entry points,
  with namespaced indicators, scoped keys, validation, and error redaction
- Machine-readable `score_breakdown`, JSON `schema_version`, indicator status/provenance,
  and stable SARIF fingerprints
- Security CI for Semgrep, Bandit, dependency auditing, and current/history secret scans;
  native Windows CI coverage
- Maintained mypy gate with a clean source-tree baseline
- Immutable commit pins for every third-party GitHub Actions dependency
- Offline POP3 replay fixture and passive-intel URL allowlist tests
- POP3 `pop3.auth_failed_blanket` (primary): identical auth-themed `-ERR` across distinct
  pre-auth commands including RFC 2449 `CAPA` (catches qeeqbox/Twisted POP3 skins)
- POP3 `pop3.stock_banner` (corroboration-gated): stock Exchange lure greeting fingerprint
- `pop3.auth_failed_blanket` is a high-signal tell (+15% bonus, same band as `ssh.kex_facade`)
  so a single-protocol POP3 lure clears Suspected instead of stalling at 20% / Likely Real
- Richer offline socket replays: TLS ServerHello, FTP Dionaea banner, and SSH Cowrie KEXINIT
  fixtures (plus `makefile` / `source_address` support in the replay harness)
- `deep.kexinit_rigid` when SSH KEXINIT matches Paramiko/Twisted trap templates
- `--passive-first-confirm` to run a safe-mode active verify after high passive score or
  `--osint-only` (handshake-only; does not enable deep/shell probes)
- Packaged `cdn_tls_profiles.json` merged into TLS CDN edge matching; lab capture helpers
  (`capture_tls_baseline`, `merge_tls_profile_entry`) and merge-safe
  `scripts/capture-tls-baseline.sh` (`--name`, `--cdn`, `--update-package`; default output
  under `.lab-tls-capture/`)
- `actionlint` CI job for workflows and the composite GitHub Action
- Offline `check-sig` signature fixtures under `tests/fixtures/signatures/`

### Fixed

- Windows startup failure when `os.geteuid` is unavailable
- Passive Shodan/provider work executing twice during progress-enabled host audits
- Silent broad exception handling across optional probes and connection cleanup
- Passive REST fallback now rejects non-HTTPS URLs and hosts outside the Shodan API allowlist
- Named `--intel-provider` plugins now run independently of Shodan / dual-stack IPv6 gating
- `--intel-key` warns on stderr; environment variables override argv keys when both are set
- POP3 `pop3.preauth_state` requires pre-auth **STAT** `+OK` (NOOP alone no longer triggers)
- POP3 response reading uses a buffered CRLF reader instead of per-byte `recv(1)`
- `--passive-first-confirm` now aligns `args` + `settings` and builds notes/report after job
  planning so JSON no longer claims `deep=True` for handshake-only verify passes
- `deep.kexinit_rigid` no longer double-fires when `deep.hassh` already covers the same KEX
- TLS capture target parsing accepts `[IPv6]:PORT`; actionlint CI verifies release checksums
- Signature evaluation no longer crashes when indicator evidence is a JSON number (e.g. SMTP
  reply code `"250"`)

### Changed

- Passive-intel category labeling now covers Shodan and selected providers while retaining the
  stable `shodan` category key for report compatibility
- JSON and SARIF outputs distinguish triggered, clear, skipped, and suppressed results
- SARIF export uses `report.triggered()` (excludes suppressed indicators); fingerprints are
  stable across multi-host runs
- Composite GitHub Action pins `actions/setup-python` to an immutable commit SHA
- README, GitHub Pages, `SECURITY.md`, and `scripts/sync-public-docs.sh` document
  `--passive-first-confirm` and the safer TLS baseline capture workflow

## [0.6.0] - 2026-09-02

### Added

- Clock-drift tell (`deep.clock_drift`): HTTP Date skew/frozen samples; optional SMB SystemTime hook
- HTTP invalid chunked length + SSH pre-KEXINIT FSM fuzz; SSH drop/reconnect continuity (`fsm.stateless_trap_behavior`)
- CLI `--jitter` fraction (alongside `--jitter-ms`); TLS wildcard SNI tell (`tls.wildcard_sni`)
- Concurrent load latency tell (`deep.latency_under_load`): parallel banner RTTs vs serial baseline
- `docs/SIGNATURES.md` TLS JA3S/JA4S section; nginx service in benchmark compose; Docker golden integration job
- HTTP framework 404+session tell (`http.framework_404_session`); probes common admin paths after empty `/`
- SARIF always emits a summary result when no indicators triggered (CI-friendly)
- Pre-auth `ssh.kex_facade` tell for password-gated Cowrie (OpenSSH banner + Twisted host-key/AEAD/MAC suite)
- Pre-auth `ssh.password_only` tell when OpenSSH banner advertises password auth without publickey
- Telnet Cowrie preamble tell (`IAC DO NAWS` + bare `login:`) on `telnet.banner` / `telnet.iac_negotiate`
- HTTP silent-accept / tarpit tell (`http.silent_accept`) when TCP connects but no HTTP bytes return
- HTTP-proxy silent-accept tell (`httpproxy.silent_accept`) for the same tarpit pattern on proxy ports
- SMB silent-accept tell (`smb.silent_accept`) when TCP/445 accepts but NETBIOS/SMB session times out
- Analyzer cotenancy tell when ≥2 ports hit silent-accept (`cotenancy.silent_accept_cluster`)
- High-signal bonus for `ssh.kex_facade` (+15%) so password-gated Cowrie alone reaches Suspected / medium confidence
- Lab-tour demo GIF (`docs/demo/honeypot-auditor-lab-tour-demo.gif`) covering three hosts with `-v` / `--deep` / silent-accept options

### Fixed

- Wheel/package data: ship `signatures/core/*.json` and packaged `data/*.json`; TLS/HTTP2 loaders use package-relative paths
- GitHub composite action: validate `target`/`preset` via env (no shell injection); install from checkout when present
- Plugin/signature load failures log warnings instead of silent no-ops
- SECURITY.md supported versions updated for 0.5.x / 0.6.x
- PyPI publish workflow with wheel package-data verification; golden CI packaging smoke + docs sync
- SARIF golden shape assertions; config barrel-export regression test
- `--preset deception-audit` crashed before probes (alias applied after port map); now normalizes first and enables `--deep`
- Deep probe job used the same 5s budget as single probes; dedicated deep timeout (≥90s) and non-empty `deep.error` detail
- Declarative `exact_bytes` with empty needle always matched; reject empty needles and remove broken `mysql_ssl.json` pack rule
- Confidence stayed `low` on Confirmed 100% due to Shodan/closed-port skips; ignore never-applicable skips; multi-user any-password → `high` / `SKIP_TARGET`
- Tactical coverage skip-ratio now uses the same never-applicable filter as confidence
- Never-applicable skip matcher no longer treats bare "filtered" (e.g. WAF content-filtered) as closed-port
- Any-password bonus no longer zeroes other category contributions in the scoreboard
- Safe-mode telnet passed strings into IAC matchers expecting bytes
- `http.dynamic_headers` detail always claimed "missing Date"; now reflects actual Date presence
- HTTP admin-path follow-ups after bare `/` 404 are bounded/logged and covered by tests
- SSH KEXINIT parser skipped the identification string so HASSH/Cowrie facade tells never fired
- MySQL seq-order tell only matched classic ER 1156; also match modern emulator `Expected seq(N) got seq(M)` replies
- `--ports` help clarifies it remaps inside the preset; `-p/--port` is required to limit scan scope
- SSH/Telnet identity scoring for canned `Command not handled` / `Internal error. Please try again later` refusals
- Per-probe job budget was equal to socket timeout, so silent-accept/tarpit faces raced the outer deadline; jobs now get `2×timeout+2s` headroom
- Confidence treated post-auth skips (`no session`) as coverage failures on password-gated hosts; those skips are never-applicable for confidence

### Changed

- Version 0.6.0; README and GitHub Pages use the lab-tour demo GIF as the primary live demo

## [0.5.0] - 2026-09-01

### Added

- Declarative signature engine (`signatures/loader.py`, `signatures/core/*.json`) and `check-sig` linter subcommand
- Entry-point plugin API (`plugins/api.py`) and SARIF export (`--format sarif`)
- `--preset deception-audit`, ranked `deception_leaks` in JSON, GitHub Action (`.github/action/action.yml`)
- Golden/replay CI (`.github/workflows/golden.yml`), `scripts/sync-public-docs.sh`, `docs/PLUGINS.md`
- Experimental LLM hallucination probes (`deep.llm_hallucination`) behind `--deep`

### Changed

- Version 0.5.0; README and GitHub Pages updated for v0.3.1–v0.5.0 CLI flags

## [0.4.1] - 2026-09-01

### Added

- HTTP/2 SETTINGS fingerprinting (`http2_fingerprint.py`, packaged `data/http2_settings_profiles.json`)
- `ProbeTransportManager` with `--max-concurrent`, `--jitter-ms`, `--seed`; blend profile TLS/UA mimesis
- Deep behavioral probes: state continuity (`fsm.stateless_trap_behavior`), shell entropy, mtime uniformity
- GHCR Docker image (`Dockerfile`, `.github/workflows/publish-ghcr.yml`)

## [0.4.0] - 2026-09-01

### Added

- Fixed ClientHello TLS fingerprinting wired into `probe_tls_stack` with JA3S/JA4S and packaged `data/tls_profiles.json`
- Raw KEXINIT hex in HASSH probe evidence; TCP SYN-ACK option order tell (`deep.tcp_synack_options`)
- `--passive-first`, `--osint-only`, `--dual-stack`; formal `tactical_action` matrix
- Offline socket replay harness (`tests/fixtures/replays/`, `pytest -m replay`)
- `scripts/capture-tls-baseline.sh` for lab TLS profile capture

## [0.3.1] - 2026-09-01

### Added

- HTTP header-order tell, wildcard Host, tiered proxy detection, Confidence metric
- `--safe-mode`, SOCKS5h proxy (`--proxy`), honeytoken redaction, Python SDK (`Auditor` class)
- `--output-nmap-exclude`, capabilities degradation pipeline, TLS stack rename/stability

## [0.3.0] - 2026-08-31

### Added

- Deny-all FSM tells aimed at Trapster-class stacks: FTP **command desert** (FEAT/PWD/PASV/NOOP → uniform `500 Unknown Command`), MySQL **CLIENT_SSL silent drop**, MSSQL **TLS close after ENCRYPT_NOT_SUP**, and a new **Postgres** probe (`SSLRequest → N` + cleartext-only + frozen `auth.c:326`).
- `-p` / `--port` is nmap-style: **only** the listed TCP ports are scanned (e.g. `-p 22` or `-p22` is SSH 22 only). Omit `-p` to use the `--preset` map. `--ports proto=N` still overrides a protocol on top of that.
- Basic Cowrie checks: SSH `exec_command` fails after any-password login (fake shell only) → **state non-persistence**; default hostname `svr04`/`nas3` and stock Debian MOTD even with a modern OpenSSH banner
- SSH/Telnet CTI playbook on the basic path: second random login, `whoami`/prompt vs lure account, honeyfs (`cowrie.txt`), bash arithmetic, and a `/tmp` canary that a new session cannot read
- Telnet pre-auth CTI: Cisco-class `User Access Verification` / Microsoft Telnet banners, canned `Wrong password.` rejects, and IAC WILL/DO option spray then `Username:` (scored even when any-password login fails)
- FTP class-level CTI: stock default `220 ProFTPD 1.2.10` (and other EOL 220s); canned 530; stock decoy login (`test` + empty/`test`); PASV IP that does not match the control connection; QUIT 550
- SMTP class-level CTI: AUTH with random credentials (any-password), greeting/EHLO identity that is loopback/localhost, and MAIL FROM accepted then RCPT 503 need-sender (envelope not stored)
- Protocol table and console use the same three **strategies** on every service: **arbitrary auth**, **state non-persistence**, **static signature** (`PROTOCOL_STRATEGIES` in config)
- Nmap `-sV`: unrecognized fingerprint on **any** protocol (data but no product match), `-sV` vs banner **family mismatch** (e.g. vsftpd vs ProFTPD 220), ambiguous EOL FTP (`vsftpd … or WU-FTPD`), and lure banners — **static signature**. Version-scans every open preset port (`tcpwrapped` ignored; confident OpenSSH/nginx/etc. stay clean).
- Redis class-level CTI: AUTH with random credentials (any-password); FLUSHALL that does not clear keys; COMMAND `+OK` / frozen INFO / HELP returning redis-cli text / missing ECHO or SELECT
- CLI `-v` / `--verbose`: strategy contributions, per-protocol matrix, indicator table, why-this-score, and run notes. Default console is the score panel only (JSON is always written).
- Sixteen first-class probes: Postgres joins SSH/Telnet/FTP/SMTP/HTTP/SMB/SIP/VNC/Redis/MySQL/Git/RDP/HTTP proxy/MSSQL/MongoDB. Class-level tells only. UDP-mute faces (NTP/TFTP/SIP-no-reply) are not scored as standalone detectors.
- MySQL drop-after-1045, RDP canned negotiation-failure, VNC canned Authentication failure, and MongoDB ping-unauthorized-after-hello are **state non-persistence** (deny-all is not scored as arbitrary auth).

### Fixed

- JSON export crash on `--deep` when SMTP EHLO evidence was raw bytes (`TypeError: Object of type bytes is not JSON serializable`)
- Redis probe no longer sends `FLUSHALL` (destructive on mis-targeted real instances); reconnect `GET` covers in-memory stubs and COMMAND/INFO tells cover flush stubs.
- SMB NTLM challenge capture serializes the impacket hook with a lock so parallel `smb:445` / `smb:1445` jobs do not race.
- Multi-user any-password scoring sets `category_hits` to 100% for `arbitrary_auth` so JSON matches the Honeyscore.

### Changed

- Honeyscore adds a **multi-protocol corroboration bonus**: +5% for each protocol lure beyond the **first** when basic tells already fire (max +35%), so deny-all buffets and Trapster-class FSM stacks score without Shodan or any-password.
- FTP command desert is scored as **state non-persistence** (shallow FSM), so it stacks with static banner tells instead of colliding in one category.
- `state_nonpersist` corroborates co-tenancy / protocol-buffet bonuses (deny-all FSM stacks).
- **Nmap is opt-in** (`-n` / `--with-nmap`); default audits skip the slow `-sV`/NSE phase. Replaces `--skip-nmap`.
- Default port map is **`both`**: IANA well-known ports **and** docker/lab aliases (SSH 22 and 2222, HTTP 80/443 and 8081, VNC 5900 and 5000, HTTP proxy 3128 and 8080, …) so Cowrie on 22 is not missed when the old default was only 2222.
- Telnet IAC: send unknown option 99 + AUTH/NAWS subnegotiation (blind WILL/DO or reset). Shell CTI adds `tty`, piped `grep|awk`, `/dev` nodes, DMI product.
- SMTP VRFY/EXPN/STARTTLS/ETRN monotone replies; `--deep` RSET during DATA. FTP PORT bounce to an unrelated address, SIZE after STOR, FEAT/REST. VNC security type 0 still yielding a 16-byte challenge.
- `--deep`: banner vs TCP TTL, TLS stock certificate CN, idle-accept burst, Telnet FSM, hypervisor/veth/`/dev` coherence.
- Basic probes are one module per protocol (`probes/ssh.py`, `telnet.py`, `http.py`, …) instead of `core.py` / `extended.py` grab-bags. Those two names still re-export the same `probe_*` functions.

## [0.2.2] - 2026-08-30

### Added

- **IPv4 CIDR subnet scans** via `--target 192.168.1.0/24` (max `/24`, 254 hosts)
- `--scan-concurrency` for parallel host audits (default 8); subnet JSON with summary + per-host reports
- **CLI help UX:** `-h`, `--help`, `/help`, `/?` aliases; Rich-styled help; compact figlet **H-AUDITOR** ANSI header on run and help
- BBS-style GitHub Pages site (`docs/`) with `llms.txt`, `llms-full.txt`, `agents.md`, SEO/AEO/GEO files
- Animated Cowrie/Dionaea demo GIFs in README and `docs/demo/`
- Dionaea detection: FTP PASV private IP, STOR non-persistence, SMB framing fallback, HTTP/nginx tells, co-tenancy threshold tuning

### Changed

- Dependencies: `pyfiglet`, `rich-argparse` (figlet header + colored help)
- README greets link [UHBS lab rats](https://uhbs.github.io/uhbs-standard/) and [CyberHalluciNet](https://cyberhallucinet.org/); LICENSE section links [MIT](LICENSE)

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
