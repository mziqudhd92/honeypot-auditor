# DHCP probe

UDP **67** (lab **1067**) — RFC 2131. The probe binds the privileged client
port **68**, so it is **capability-gated**: without root/admin the suite skips
with a capability note instead of failing.

## Strategies

| Strategy | Axis |
|----------|------|
| **state_nonpersist** | Transaction ID (xid) not echoed across two DISCOVERs |
| **static_signature** | BOOTP framing: short reply, wrong op, missing cookie/option 53, ACK/NAK to DISCOVER |
| **static_signature** | Canned OFFER clone for DISCOVERs with distinct xid and chaddr |

## Indicators

| ID | Trigger |
|----|---------|
| `dhcp.xid_echo` | Neither reply copies the request xid (RFC 2131 §4.1 requires it) |
| `dhcp.framing` | Missing magic cookie, op ≠ BOOTREPLY, missing option 53, or ACK/NAK to DISCOVER |
| `dhcp.canned_offer` | Offers identical (or identical apart from xid/chaddr) across distinct clients |

Real servers answer DHCPOFFER (option 53 = 2), echo the xid, and vary the offer
per client. A responder that ACKs a DISCOVER or replays one canned template is
an emulator.

## Non-destructive policy

Two DHCPDISCOVER datagrams only. DISCOVER does not allocate a lease (that is
REQUEST); the probe never requests the offered address.

## Ports

| Port | Mode |
|------|------|
| 67/udp | DHCP server (client port 68 required to speak) |
| 1067/udp | Lab |
