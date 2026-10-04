# Strategies (per protocol)

One folder per protocol engine. **Start here** when auditing or reviewing
detection strategies — each folder is the guide plus a code map to the probe,
matchers, and tests.

## Basic axes (every protocol)

| Axis | Role |
|------|------|
| **arbitrary_auth** | Dual synthetic credentials / communities accepted when they should not be |
| **state_nonpersist** | Session or object state that a real daemon would keep |
| **static_signature** | Framing, facade, stock lure, and conformance tells |

**30** protocol folders · **80** active axis slots · **255** scored indicators.
Host-level axes (Shodan / co-tenancy) are not per-protocol.

Source of truth for axes: `PROTOCOL_STRATEGIES` in
[`src/honeypot_auditor/config/scoring.py`](../../src/honeypot_auditor/config/scoring.py).

## Protocol index

| Protocol | Transport | Strategies | Indicators | Guide | Probe |
|----------|-----------|:----------:|:----------:|-------|-------|
| SSH | TCP | 3 | 10 | [`ssh/`](ssh/) | [`ssh.py`](../../src/honeypot_auditor/probes/ssh.py) |
| Telnet | TCP | 3 | 9 | [`telnet/`](telnet/) | [`telnet.py`](../../src/honeypot_auditor/probes/telnet.py) |
| FTP | TCP | 3 | 8 | [`ftp/`](ftp/) | [`ftp.py`](../../src/honeypot_auditor/probes/ftp.py) |
| SMTP | TCP | 3 | 7 | [`smtp/`](smtp/) | [`smtp.py`](../../src/honeypot_auditor/probes/smtp.py) |
| POP3 | TCP | 3 | 8 | [`pop3/`](pop3/) | [`pop3.py`](../../src/honeypot_auditor/probes/pop3.py) |
| IMAP | TCP | 3 | 6 | [`imap/`](imap/) | [`imap.py`](../../src/honeypot_auditor/probes/imap.py) |
| HTTP | TCP | 3 | 12 | [`http/`](http/) | [`http.py`](../../src/honeypot_auditor/probes/http.py) |
| HTTP proxy | TCP | 3 | 4 | [`httpproxy/`](httpproxy/) | [`httpproxy.py`](../../src/honeypot_auditor/probes/httpproxy.py) |
| SMB | TCP | 3 | 7 | [`smb/`](smb/) | [`smb.py`](../../src/honeypot_auditor/probes/smb.py) |
| Redis | TCP | 3 | 18 | [`redis/`](redis/) | [`redis.py`](../../src/honeypot_auditor/probes/redis.py) |
| MQTT | TCP | 3 | 10 | [`mqtt/`](mqtt/) | [`mqtt.py`](../../src/honeypot_auditor/probes/mqtt.py) |
| MySQL | TCP | 2 | 7 | [`mysql/`](mysql/) | [`mysql.py`](../../src/honeypot_auditor/probes/mysql.py) |
| Postgres | TCP | 2 | 2 | [`postgres/`](postgres/) | [`postgres.py`](../../src/honeypot_auditor/probes/postgres.py) |
| MSSQL | TCP | 2 | 6 | [`mssql/`](mssql/) | [`mssql.py`](../../src/honeypot_auditor/probes/mssql.py) |
| MongoDB | TCP | 2 | 5 | [`mongodb/`](mongodb/) | [`mongodb.py`](../../src/honeypot_auditor/probes/mongodb.py) |
| VNC | TCP | 2 | 3 | [`vnc/`](vnc/) | [`vnc.py`](../../src/honeypot_auditor/probes/vnc.py) |
| RDP | TCP | 2 | 2 | [`rdp/`](rdp/) | [`rdp.py`](../../src/honeypot_auditor/probes/rdp.py) |
| Git | TCP | 3 | 3 | [`git/`](git/) | [`git.py`](../../src/honeypot_auditor/probes/git.py) |
| Elasticsearch | TCP | 3 | 12 | [`elasticsearch/`](elasticsearch/) | [`elasticsearch.py`](../../src/honeypot_auditor/probes/elasticsearch.py) |
| Docker | TCP | 3 | 10 | [`docker/`](docker/) | [`docker.py`](../../src/honeypot_auditor/probes/docker.py) |
| Kubernetes | TCP | 3 | 10 | [`kubernetes/`](kubernetes/) | [`kubernetes.py`](../../src/honeypot_auditor/probes/kubernetes.py) |
| IPP / CUPS | TCP | 3 | 15 | [`ipp/`](ipp/) | [`ipp.py`](../../src/honeypot_auditor/probes/ipp.py) |
| Memcached | TCP | 3 | 13 | [`memcached/`](memcached/) | [`memcached.py`](../../src/honeypot_auditor/probes/memcached.py) |
| SIP | UDP→TCP | 3 | 5 | [`sip/`](sip/) | [`sip.py`](../../src/honeypot_auditor/probes/sip.py) |
| PPTP | TCP | 3 | 5 | [`pptp/`](pptp/) | [`pptp.py`](../../src/honeypot_auditor/probes/pptp.py) |
| SNMP | UDP | 2 | 10 | [`snmp/`](snmp/) | [`snmp.py`](../../src/honeypot_auditor/probes/snmp.py) |
| DNS | UDP | 3 | 12 | [`dns/`](dns/) | [`dns.py`](../../src/honeypot_auditor/probes/udp/dns.py) |
| NTP | UDP | 3 | 11 | [`ntp/`](ntp/) | [`ntp.py`](../../src/honeypot_auditor/probes/udp/ntp.py) |
| TFTP | UDP | 2 | 12 | [`tftp/`](tftp/) | [`tftp.py`](../../src/honeypot_auditor/probes/udp/tftp.py) |
| SSDP | UDP | 1 | 13 | [`ssdp/`](ssdp/) | [`ssdp.py`](../../src/honeypot_auditor/probes/udp/ssdp.py) |

## Review checklist (per protocol)

1. Open `docs/strategies/<protocol>/` — strategies table + indicators.
2. Open the probe module from the code map — confirm each indicator id fires as documented.
3. Open signature matchers (when listed) — FP gates and lure strings.
4. Open tests — conformant-clean + tell-positive cases.
5. Confirm `PROTOCOL_STRATEGIES["<protocol>"]` axis blurbs match the guide.

## Transport indexes

- TCP layout notes: [`docs/tcp/`](../tcp/README.md)
- UDP layout notes: [`docs/udp/`](../udp/README.md)
- Scoring formulas: [`docs/SCORING.md`](../SCORING.md)
- Narrative overview (legacy entry): [`docs/STRATEGIES.md`](../STRATEGIES.md)
