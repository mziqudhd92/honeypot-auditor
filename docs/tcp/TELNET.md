# Telnet probe

TCP/23 (lab **2323**). Fingerprints telnet honeypots: any-password login,
canned rejects, IAC negotiation spray, and lure identity.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | Two random users both accepted |
| **state_nonpersist** | Canned reject · `/tmp` canary |
| **static_signature** | UAV / IAC spray · unknown-option WILL · lure whoami · fake tty |

## Indicators

| ID | Trigger |
|----|---------|
| `telnet.arbitrary_auth` | Two independent random credentials both succeed |
| `telnet.auth_lure` | Canned auth reject / lure login dialogue |
| `telnet.session_persist` | Session / canary state breaks across reconnect |
| `telnet.banner` | Stock telnet lure banner |
| `telnet.iac_negotiate` | Abnormal IAC / WILL spray |
| `telnet.whoami` / `telnet.uname` | Lure session identity |

## Ports

| Port | Mode |
|------|------|
| 23 | Production Telnet |
| 2323 | Lab |
