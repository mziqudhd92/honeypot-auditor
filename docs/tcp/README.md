# TCP probe package

Guides for TCP (and TCP-fallback) engines. UDP engines live under
[`docs/udp/`](../udp/README.md). Community SNMP stays at
[`docs/SNMP.md`](../SNMP.md) until an optional UDP relocate.

## Layout

```text
src/honeypot_auditor/probes/
  ssh.py telnet.py ftp.py smtp.py http.py pop3.py imap.py smb.py …
  httpproxy.py mysql.py postgres.py git.py rdp.py mssql.py mongodb.py …
  redis.py mqtt.py elasticsearch.py docker.py ipp.py memcached.py kubernetes.py
  sip.py                 # UDP first, TCP fallback
  (udp/)                 # DNS / NTP / SSDP / TFTP — see docs/udp/

docs/tcp/
  README.md              # this file
  SSH.md TELNET.md FTP.md SMTP.md HTTP.md POP3.md IMAP.md SMB.md …
  … (one guide per TCP-capable protocol)
```

## Supported TCP protocols

| Protocol | IANA / common | Lab alias | Guide | Strategies |
|----------|---------------|-----------|-------|------------|
| SSH | 22 | 2222 | [SSH.md](SSH.md) | all three |
| Telnet | 23 | 2323 | [TELNET.md](TELNET.md) | all three |
| FTP | 21 | 2121 | [FTP.md](FTP.md) | all three |
| SMTP | 25 | 2525 | [SMTP.md](SMTP.md) | all three |
| HTTP(S) | 80 / 443 | 8081 | [HTTP.md](HTTP.md) | all three |
| POP3 | 110 | 1110 | [POP3.md](POP3.md) | all three |
| IMAP(S) | 143 / 993 | 1143 / 1993 | [IMAP.md](IMAP.md) | all three |
| SMB | 445 | 1445 | [SMB.md](SMB.md) | state + static |
| VNC | 5900 | 5000 | [VNC.md](VNC.md) | state + static |
| Redis | 6379 | 6379 | [REDIS.md](REDIS.md) | all three |
| MySQL | 3306 | 3306 | [MYSQL.md](MYSQL.md) | state + static |
| Postgres | 5432 | 5432 | [POSTGRES.md](POSTGRES.md) | state + static |
| Git | 9418 | 9418 | [GIT.md](GIT.md) | all three |
| RDP | 3389 | 3389 | [RDP.md](RDP.md) | state + static |
| HTTP proxy | 3128 | 8080 | [HTTPPROXY.md](HTTPPROXY.md) | all three |
| MSSQL | 1433 | 1433 | [MSSQL.md](MSSQL.md) | state + static |
| MongoDB | 27017 | 27017 | [MONGODB.md](MONGODB.md) | state + static |
| MQTT(S) | 1883 / 8883 | 11883 / 18883 | [MQTT.md](MQTT.md) | all three |
| Elasticsearch | 9200 | 19200 | [ELASTICSEARCH.md](ELASTICSEARCH.md) | all three |
| Docker Engine | 2375 | 12375 | [DOCKER.md](DOCKER.md) | static only |
| IPP / CUPS | 631 | 1631 | [IPP.md](IPP.md) | all three |
| Memcached | 11211 | 21211 | [MEMCACHED.md](MEMCACHED.md) | all three |
| Kubernetes | 6443 | 16443 | [KUBERNETES.md](KUBERNETES.md) | static only |
| SIP | 5060 | 5060 | [SIP.md](SIP.md) | all three (UDP→TCP) |

Lab aliases come from the `docker-research` / `both` presets in
`config/ports.py`.

## Shared rules

- Every engine uses the same three basic strategies when enabled:
  **arbitrary_auth**, **state_nonpersist**, **static_signature** (see
  `PROTOCOL_STRATEGIES` in config). Empty strategy strings mean that axis is
  inactive for the protocol.
- Ports and strategies stay in **config** — probe modules never feed config
  (avoids circular imports).
- Prefer protocol non-compliance over product honeypot brand IOCs.
- Closed / refused ports → suite skip (`closed_reason`), not a honeypot hit.
- `--safe-mode` limits each engine to framing / low-impact static checks; see
  the per-protocol guide.

## UDP siblings

| Protocol | Guide |
|----------|-------|
| DNS | [docs/udp/DNS.md](../udp/DNS.md) |
| NTP | [docs/udp/NTP.md](../udp/NTP.md) |
| TFTP | [docs/udp/TFTP.md](../udp/TFTP.md) |
| SSDP | [docs/udp/SSDP.md](../udp/SSDP.md) |
| SNMP | [docs/SNMP.md](../SNMP.md) |

## Scoring

Global Honeyscore, fidelity, and corroboration → [docs/SCORING.md](../SCORING.md).
