# TCP probe package

Transport notes for TCP (and TCP-fallback) engines. **Per-protocol strategy
guides live under [`docs/strategies/`](../strategies/)** — one folder per
protocol for auditors and reviewers.

UDP engines: [`docs/udp/`](../udp/README.md).

## Layout

```text
src/honeypot_auditor/probes/
  ssh.py telnet.py ftp.py smtp.py http.py pop3.py imap.py smb.py …
  httpproxy.py mysql.py postgres.py git.py rdp.py mssql.py mongodb.py …
  redis.py mqtt.py elasticsearch.py docker.py ipp.py memcached.py kubernetes.py
  sip.py                 # UDP first, TCP fallback
  (udp/)                 # DNS / NTP / SSDP / TFTP — see docs/udp/

docs/strategies/<protocol>/   # strategy guide + code map (start here)
docs/tcp/                     # this transport index (+ move stubs)
```

## Supported TCP protocols

| Protocol | IANA / common | Lab alias | Strategies guide | Axes |
|----------|---------------|-----------|------------------|------|
| SSH | 22 | 2222 | [strategies/ssh](../strategies/ssh/) | all three |
| Telnet | 23 | 2323 | [strategies/telnet](../strategies/telnet/) | all three |
| FTP | 21 | 2121 | [strategies/ftp](../strategies/ftp/) | all three |
| SMTP | 25 | 2525 | [strategies/smtp](../strategies/smtp/) | all three |
| HTTP(S) | 80 / 443 | 8081 | [strategies/http](../strategies/http/) | all three |
| POP3 | 110 | 1110 | [strategies/pop3](../strategies/pop3/) | all three |
| IMAP(S) | 143 / 993 | 1143 / 1993 | [strategies/imap](../strategies/imap/) | all three |
| SMB | 445 | 1445 | [strategies/smb](../strategies/smb/) | all three |
| VNC | 5900 | 5000 | [strategies/vnc](../strategies/vnc/) | state + static |
| Redis | 6379 | 6379 | [strategies/redis](../strategies/redis/) | all three |
| MySQL | 3306 | 3306 | [strategies/mysql](../strategies/mysql/) | state + static |
| Postgres | 5432 | 5432 | [strategies/postgres](../strategies/postgres/) | state + static |
| Git | 9418 | 9418 | [strategies/git](../strategies/git/) | all three |
| RDP | 3389 | 3389 | [strategies/rdp](../strategies/rdp/) | state + static |
| HTTP proxy | 3128 | 8080 | [strategies/httpproxy](../strategies/httpproxy/) | all three |
| MSSQL | 1433 | 1433 | [strategies/mssql](../strategies/mssql/) | state + static |
| MongoDB | 27017 | 27017 | [strategies/mongodb](../strategies/mongodb/) | state + static |
| MQTT(S) | 1883 / 8883 | 11883 / 18883 | [strategies/mqtt](../strategies/mqtt/) | all three |
| Elasticsearch | 9200 | 19200 | [strategies/elasticsearch](../strategies/elasticsearch/) | all three |
| Docker Engine | 2375 | 12375 | [strategies/docker](../strategies/docker/) | all three |
| IPP / CUPS | 631 | 1631 | [strategies/ipp](../strategies/ipp/) | all three |
| Memcached | 11211 | 21211 | [strategies/memcached](../strategies/memcached/) | all three |
| Kubernetes | 6443 | 16443 | [strategies/kubernetes](../strategies/kubernetes/) | all three |
| SIP | 5060 | 5060 | [strategies/sip](../strategies/sip/) | all three (UDP→TCP) |
| PPTP | 1723 | 11723 | [strategies/pptp](../strategies/pptp/) | all three |

Lab aliases come from the `docker-research` / `both` presets in
`config/ports.py`.

## Shared rules

- Every engine uses the same three basic strategies when enabled:
  **arbitrary_auth**, **state_nonpersist**, **static_signature** (see
  `PROTOCOL_STRATEGIES` in config). Empty strategy strings mean that axis is
  inactive for the protocol. README **Strategies** are axis counts; **Indicators**
  are scored tell counts.
- Ports and strategies stay in **config** — probe modules never feed config
  (avoids circular imports).
- Prefer protocol non-compliance over product honeypot brand IOCs.
- Closed / refused ports → suite skip (`closed_reason`), not a honeypot hit.
- `--safe-mode` limits each engine to framing / low-impact static checks; see
  the per-protocol guide under `docs/strategies/`.

## UDP siblings

| Protocol | Guide |
|----------|-------|
| DNS | [strategies/dns](../strategies/dns/) |
| NTP | [strategies/ntp](../strategies/ntp/) |
| TFTP | [strategies/tftp](../strategies/tftp/) |
| SSDP | [strategies/ssdp](../strategies/ssdp/) |
| SNMP | [strategies/snmp](../strategies/snmp/) |

## Scoring

Global Honeyscore, fidelity, and corroboration → [docs/SCORING.md](../SCORING.md).
