# FTP probe

TCP/21 (lab **2121**). Fingerprints decoy FTP: stock logins, PASV/PORT
mismatches, STOR/SIZE non-persist, and Synology/OpenCanary-class banners.

## Strategies

| Strategy | Axis |
|----------|------|
| **arbitrary_auth** | Stock decoy login (`test` / anonymous lure) |
| **state_nonpersist** | PASV mismatch · canned 530 · STOR/SIZE · FEAT/PWD desert |
| **static_signature** | Stock 220 · SYST L8 · PORT bounce |

## Indicators

| ID | Trigger |
|----|---------|
| `ftp.arbitrary_auth` | Stock decoy credentials accepted |
| `ftp.auth_lure` | Canned 331/530 auth dialogue |
| `ftp.persist` | Upload / SIZE does not persist across reconnect |
| `ftp.banner` | Stock 220 / SYST lure |
| `ftp.bounce` | PORT bounce / PASV advertises non-routable address |
| `ftp.desert` | FEAT/PWD empty or desert facade |

## Non-destructive policy

Ephemeral STOR of probe payloads only; never retains malware samples.

## Ports

| Port | Mode |
|------|------|
| 21 | Production FTP |
| 2121 | Lab |
