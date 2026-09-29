# SMB probe

TCP/445 (lab **1445**). Fingerprints dual-credential façades, SMB1/EOL native
OS strings, static NTLM challenges, stock lure shares, bogus-pipe / ghost-share
NTSTATUS, and silent-accept tarpits.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | Two entropy-varied credentials both establish a session |
| **state_nonpersist** | Bogus pipe NTSTATUS · ghost share TREE_CONNECT |
| **static_signature** | SMB1/EOL `native_os` · static NTLM challenge · stock lure shares · silent accept |

## Indicators

| ID | Category | Trigger |
|----|----------|---------|
| `smb.arbitrary_auth` | arbitrary_auth | Two entropy-varied username/password pairs both establish an SMB session. Fidelity **decisive** when hit. |
| `smb.dialect` | static_signature | Dialect / session-setup unpack or emulator anomaly (SMB1 / EOL native OS) |
| `smb.ntlm_challenge` | static_signature | Static / reused NTLM challenge across sessions |
| `smb.stock_shares` | static_signature | Share list matches decisive lure names (`honey`, `honeypot`, …) or ≥2 generic lure names (`tmp`+`public`, …). Generics are corroboration-gated alone. |
| `smb.bogus_pipe` | state_nonpersist | Bogus named-pipe NTSTATUS facade |
| `smb.ghost_share` | state_nonpersist | Random share TREE_CONNECT **accepted**. Missing-share / access-denied NTSTATUS class (`BAD_NETWORK_NAME`, `OBJECT_NAME_NOT_FOUND`, `ACCESS_DENIED`, …) is clean. |
| `smb.silent_accept` | static_signature | TCP accept with no SMB bytes (tarpit) |

## Non-destructive policy

Session setup / pipe / share TREE_CONNECT probes only. Never writes shares or
drops payloads.

## Ports

| Port | Mode |
|------|------|
| 445 | Production SMB |
| 139 | NetBIOS session (mapped) |
| 1445 | Lab |

## Scoring

`PROTOCOL_STRATEGIES["smb"]` activates **all three** basic strategies.
