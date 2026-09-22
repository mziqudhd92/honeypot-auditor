# SSH probe

TCP/22 (lab **2222**). Fingerprints password-gated SSH lures (Cowrie / Kippo
class): any-password acceptance, fake PTY vs real `exec`, Twisted/Cowrie KEX
facades, and honeyfs identity tells.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | Two random users both accepted |
| **state_nonpersist** | `exec` denied after login · `/tmp` canary |
| **static_signature** | Banner · KEX facade · lure `whoami` / `uname` · honeyfs |

## Indicators

| ID | Trigger |
|----|---------|
| `ssh.arbitrary_auth` | Two independent random credentials both succeed |
| `ssh.exec_denied` | Interactive shell works but `exec_command` fails |
| `ssh.session_persist` | `/tmp` canary / session state breaks across reconnect |
| `ssh.banner` | Stock / EOL OpenSSH lure banner |
| `ssh.kex_facade` | Twisted/Cowrie-class KEX preference facade (high fidelity) |
| `ssh.password_only` | Password auth only / missing modern methods |
| `ssh.whoami` | Session identity is the random lure account |
| `ssh.uname` | Default Cowrie hostname / missing shell utilities |

## Non-destructive policy

Synthetic logins and lightweight shell probes only. Never installs backdoors or
exfiltrates real files beyond ephemeral canaries.

## Ports

| Port | Mode |
|------|------|
| 22 | Production SSH |
| 2222 | Lab / Cowrie default |
