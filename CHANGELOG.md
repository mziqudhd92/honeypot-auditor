# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
- Fifteen first-class probes: MySQL, Git, RDP, HTTP proxy, MSSQL, and MongoDB join SSH/Telnet/FTP/SMTP/HTTP/SMB/SIP/VNC/Redis. Class-level tells only, taken from honeypot source (canned RFB auth-fail, hello connectionId frozen at 1, empty HTTP 405, GET / → login skin). UDP-mute faces (NTP/TFTP/SIP-no-reply) are not scored as standalone detectors.
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
