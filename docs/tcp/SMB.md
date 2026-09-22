# SMB probe

TCP/445 (lab **1445**). Fingerprints SMB1/EOL native OS strings, static NTLM
challenges, bogus-pipe NTSTATUS, and silent-accept tarpits.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | *(inactive)* |
| **state_nonpersist** | Bogus pipe NTSTATUS · session FSM |
| **static_signature** | SMB1/EOL `native_os` · static NTLM challenge |

## Indicators

| ID | Trigger |
|----|---------|
| `smb.dialect` | Dialect / session-setup unpack or emulator anomaly |
| `smb.ntlm_challenge` | Static / reused NTLM challenge |
| `smb.bogus_pipe` | Bogus named-pipe NTSTATUS facade |
| `smb.silent_accept` | TCP accept with no SMB bytes (tarpit) |

## Non-destructive policy

Session setup / pipe probes only. Never writes shares or drops payloads.

## Ports

| Port | Mode |
|------|------|
| 445 | Production SMB |
| 139 | NetBIOS session (mapped) |
| 1445 | Lab |
