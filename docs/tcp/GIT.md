# Git probe

TCP/9418 (and HTTP Basic where applicable). Fingerprints git-daemon decoys that
accept any repo auth, advertise capabilities that fail on follow-up, or always
ERR “no such repository”.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | Two entropy-varied HTTP Basic / pkt-line auth both accepted |
| **state_nonpersist** | Advertised upload-pack capabilities fail on follow-up |
| **static_signature** | `git-upload-pack` always ERR no such repository |

## Indicators

| ID | Trigger |
|----|---------|
| `git.arbitrary_auth` | Two synthetic credentials both accepted |
| `git.state_nonpersist` | Capability advertisement lies on follow-up negotiation |
| `git.signature` | Always-ERR / stock git-daemon lure |

## Non-destructive policy

Info/refs and capability probes only. Never pushes objects.

## Ports

| Port | Mode |
|------|------|
| 9418 | git-daemon |
