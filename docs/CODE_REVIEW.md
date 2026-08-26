# Code review notes (0.1.0 extraction)

Review focused on OSS readiness, safety, and maintainability. Items marked **fixed** were addressed before the standalone release.

## Critical / high

| Issue | Status | Notes |
|-------|--------|-------|
| `sys.path` injection instead of installable package | **Fixed** | `src/honeypot_auditor` + `pyproject.toml` entry point |
| Global mutable `config.TIMEOUT_SECONDS` | **Fixed** | `settings.timeout_seconds` set once per invocation |
| Nested `asyncio.run()` in Telnet from async context | **Fixed** | Sync socket probe only (runs inside `asyncio.to_thread`) |
| No public-IP authorization gate | **Fixed** | `--confirm-authorized` required for non-RFC1918 targets |
| CHN-specific branding in user-agent / probe keys | **Fixed** | Neutral `honeypot-auditor/` UA and `hpaudit_` prefixes |

## Medium

| Issue | Status | Notes |
|-------|--------|-------|
| VNC tell matched bare substring `"vnc"` | **Fixed** | Require RFB banner; tighter desktop-name tokens |
| HTTP Date check could flip-flop on failed GET | **Fixed** | Malformed POST headers checked first; GET refines when available |
| Invalid port overrides accepted | **Fixed** | Validate 1–65535 in `parse_port_overrides` |
| Broad `except Exception` without user-visible skip | **Partial** | Probes return `skipped_indicator` with reason; still broad internally |
| `ssh-honeypot` NSE script may be absent on some nmap builds | **Open** | Skips gracefully when nmap fails; document in README |
| FTP probe assumes `incoming` upload dir | **Open** | Skips when STOR fails; common decoy layout only |

## Low / documentation

| Issue | Status | Notes |
|-------|--------|-------|
| Missing LICENSE / CONTRIBUTING / SECURITY | **Fixed** | MIT + policy files added |
| Missing CI | **Fixed** | GitHub Actions pytest workflow |
| Paramiko `AutoAddPolicy` | **Accepted** | Fingerprinting tool; document in SECURITY.md |
| Redis fallback persistence logic heuristic | **Open** | May false-negative on non-standard RESP |

## Test coverage

- Scoring engine and signature matchers covered in `tests/test_analyzer.py`
- Live protocol probes intentionally integration-tested manually (no mock servers in CI yet)

## Follow-ups (optional)

- Mock protocol servers for CI integration tests
- Optional AbuseIPDB read-only context panel (informational, not honeypot score)
- PyPI publish workflow
