# Syslog probe

UDP/514 (lab **10514**), TCP/514 (RFC 6587). Syslog has **no request/response
channel by design** — RFC 5426 datagrams are fire-and-forget and RFC 6587 TCP
frames are consumed in silence. Detection is therefore purely RFC-behavioral:
the tell is *any* answer where the RFC mandates silence.

## Strategies

| Strategy | Axis |
|----------|------|
| **static_signature** | Reply on the ack-less UDP channel (RFC 5426 violation) |
| **static_signature** | Reply/echo on the TCP framing channel (RFC 6587 violation) |

## Indicators

| ID | Trigger |
|----|---------|
| `syslog.unexpected_reply` | RFC 3164 / RFC 5424 datagrams drew a UDP reply |
| `syslog.tcp_reply` | Well-formed TCP frame drew a reply or echo |

A silent open port is honest syslog and does not score. A syslog honeypot that
"acknowledges" messages (deception frameworks that want to look interactive)
violates the RFC and scores.

## Non-destructive policy

Two single-line synthetic messages per transport (one RFC 3164, one RFC 5424,
one RFC 6587 TCP frame). No floods, no log injection patterns.

## Ports

| Port | Mode |
|------|------|
| 514/udp | Production syslog (RFC 5426) |
| 514/tcp | Production syslog over TCP (RFC 6587) |
| 10514/udp | Lab |
