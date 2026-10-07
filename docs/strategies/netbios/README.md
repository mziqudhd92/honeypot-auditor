# NetBIOS probe

NBNS over **UDP 137** (lab **1137**) and the session service over **TCP 139**
(lab **1139**) — RFC 1001/1002. Strategies are RFC-behavioral: transaction-ID
echo, header/RR framing, canned node-status clones, and session grants for
names that cannot exist.

## Strategies

| Strategy | Axis |
|----------|------|
| **state_nonpersist** | NBNS transaction ID not echoed across two queries |
| **static_signature** | RFC 1002 header/RR framing · canned node-status clone for distinct names |
| **arbitrary_auth** | SESSION REQUEST granted (0x82) for a called name that cannot exist |

## Indicators

| ID | Trigger |
|----|---------|
| `netbios.trnid_echo` | Neither NBSTAT reply echoes its request TRN ID (RFC 1002 requires it) |
| `netbios.framing` | QR bit clear, empty reply, or malformed NBNS header/RR |
| `netbios.canned_nbstat` | Byte-identical node status for two distinct queried names |
| `netbios.session_grant` | Type-0x82 positive session response for a nonexistent called name |
| `netbios.session_framing` | Session response type outside 0x82/0x83/0x8F |

Real Windows/Samba hosts answer negative (0x83) or retarget (0x8F) for unknown
called names, and echo the queried name in node-status RRs.

## Non-destructive policy

Two NBSTAT name queries and one session request. Never any SMB payload, no
name registration/conflict packets.

## Ports

| Port | Mode |
|------|------|
| 137/udp | NBNS name service (also 138/udp datagram, not probed) |
| 139/tcp | NetBIOS session service (SSN) |
| 1137/udp, 1139/tcp | Lab |
