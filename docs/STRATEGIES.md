# Probe strategies & protocol details

**29** protocol engines (**24 TCP-capable** + **5 UDP-only**; SIP is UDP-first
with TCP fallback). Each uses up to **3** basic probe strategies:

| Strategy | Role |
|----------|------|
| **arbitrary_auth** | Dual synthetic credentials / communities accepted when they should not be |
| **state_nonpersist** | Session or object state that a real daemon would keep |
| **static_signature** | Framing, facade, stock lure, and conformance tells |

The **Strategies** column in the README port table is how many of those three
are active for that protocol in this release — not Shodan, co-tenancy, or
individual indicator checks (**72** active strategy slots across all protocols).
Source of truth: `PROTOCOL_STRATEGIES` in `src/honeypot_auditor/config/scoring.py`.

Full per-protocol guides:

- [`docs/tcp/`](tcp/README.md) — TCP (+ SIP)
- [`docs/udp/`](udp/README.md) — DNS / NTP / TFTP / SSDP
- [`docs/SNMP.md`](SNMP.md) — community SNMP (UDP)
- [`docs/SCORING.md`](SCORING.md) — Honeyscore formulas and fidelity

Default preset (`--preset both`) probes IANA well-known ports **and** common
lab/docker aliases on the same faces. Override ports with `-p` / `--ports`.
Closed faces are skipped, not scored. Port matrix:
[`README` · Supported protocols / ports](../README.md).

## `-p` extras

`-p` maps well-known extras the same way: `443`/`8443` → HTTP (TLS),
`8080`/`3128` → HTTP proxy, `139` → SMB, `993`/`1993` → IMAP (TLS/IMAPS),
`8883`/`18883` → MQTT (TLS/MQTTS), `161`/`1161`/`10161` → SNMP (UDP),
`53`/`15353` → DNS (UDP), `123`/`1123` → NTP (UDP), `69`/`1069` → TFTP (UDP),
`1900`/`11900` → SSDP (UDP), `9200`/`19200` → Elasticsearch,
`2375`/`12375` → Docker, `6443`/`16443` → Kubernetes API, `631`/`1631` → IPP,
`11211`/`21211` → Memcached, `5061` → SIP, `5000`/`5901` → VNC. Unknown numbers
are probed as SSH.

## Per-protocol notes

The POP3 engine checks response framing, pre-authentication state boundaries
(STAT), optional CAPA sampling, identical auth-failed `-ERR` blankets, stock
lure banners, unknown-command handling, and repeated synthetic logins. It never
lists, reads, retrieves, or deletes mail; see
[RFC 1939](https://www.rfc-editor.org/rfc/rfc1939.html) and
[RFC 2449](https://www.rfc-editor.org/rfc/rfc2449.html) (CAPA).

The IMAP engine pairs with POP3 for Exchange/mail skins (qeeqbox,
OpenCanary-class): RFC 3501 greetings (`* OK` / `* PREAUTH` / `* BYE`), pre-auth
`SELECT` bypass (LIST OK alone not scored), CAPABILITY-gated auth-failed NO/BAD
blankets, stock Exchange lure greetings, unknown-command handling, and repeated
synthetic `LOGIN` with `LOGOUT` cleanup. Ports **993** and lab **1993** use
implicit TLS (IMAPS); STARTTLS on 143 is out of scope. It never reads, deletes,
or modifies mailboxes. See [`docs/tcp/IMAP.md`](tcp/IMAP.md) and
[RFC 3501](https://www.rfc-editor.org/rfc/rfc3501.html).

The SNMP engine speaks community SNMPv1/v2c over UDP and scores RFC
non-compliance (any-community GetResponse, request-id mismatch, invalid version
facade, success on missing OID, BER framing, stock sysDescr, GetNext stubs,
wrong `sysObjectID`/`sysUpTime` ASN.1 types, OID-name mismatches, canned
identical replies). Never sends SetRequest or walks. See
[`docs/SNMP.md`](SNMP.md),
[RFC 1157](https://www.rfc-editor.org/rfc/rfc1157.html), and
[RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html).

The DNS engine speaks UDP/53 (lab **15353**) and scores RFC non-compliance under
all three basic strategies: open-resolver / bogus-TLD **arbitrary_auth**,
answer-section SOA / identical positive-answer **state_nonpersist**, plus
**static_signature** (header framing, txid echo, illegal OPCODE answered with
**NOERROR**, question echo, RCODE stub on `.invalid`, response clone,
corroboration-gated 0x20 case mismatch, EDNS OPT facade, message-length
incoherence, stock TXT/SOA lure). NOTIMP/NXDOMAIN/FORMERR on reserved OPCODE
are clean. Never sends AXFR/IXFR/ANY floods or updates. See
[`docs/udp/DNS.md`](udp/DNS.md) and
[RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html).

The NTP engine speaks UDP/123 (lab **1123**) and scores RFC 5905 non-compliance
under all three basic strategies: missing KoD RATE/DENY under mode-3 burst
(**arbitrary_auth**), transmit/receive timestamp monotonicity failures
(**state_nonpersist**; stable reference is normal), plus **static_signature**
(framing, mode/VN facade, originate echo, stratum facade, response clone,
corroboration-gated zeroed clock metrics / epoch-zero / implausible
precision-poll / stock refid). Never sends monlist or mode-7 control queries.
See [`docs/udp/NTP.md`](udp/NTP.md) and
[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905.html).

The TFTP engine speaks RFC 1350 over UDP/69 (lab 1069) with a light RFC 2347
`blksize` probe under **static_signature** + **state_nonpersist**: TID
`fixed_source_port`, TID reuse across RRQs, opcode/error/mode/WRQ facades,
option blindness, response clone, no OACK retransmit, DATA block-size
arithmetic, corroboration-gated stock ERROR/DATA lures. Never uploads DATA or
completes a write. See [`docs/udp/TFTP.md`](udp/TFTP.md),
[RFC 1350](https://www.rfc-editor.org/rfc/rfc1350.html), and
[RFC 2347](https://www.rfc-editor.org/rfc/rfc2347.html).

The SSDP/UPnP engine speaks UDP/1900 (lab 11900) and scores discovery
non-compliance under **static_signature** only: unicast `M-SEARCH` framing,
HTTP header facades, `ST` echo fidelity, bitwise-identical response clones,
corroboration-gated stock `SERVER` strings and loopback `LOCATION` URLs, and
illegal-method stubs. Never joins multicast groups or floods `NOTIFY`. See
[`docs/udp/SSDP.md`](udp/SSDP.md) and
[UPnP 1.0](https://openconnectivity.org/upnp/specs/UPnP_architecture_v1.0.pdf).

The IPP/CUPS engine speaks HTTP (with TLS fallback) on **631** / lab **1631**
and scores CUPS/IPP non-compliance under all three basic strategies: anonymous
401/403 then dual entropy-varied Basic on `/admin` (**arbitrary_auth**),
unsupported opcode / ghost-printer identity across reconnect
(**state_nonpersist**), plus **static_signature** (root framing, stock Server,
path/method stubs, open `/admin`, frozen Date, IPP Content-Type framing,
ghost-printer `successful-ok`, request-id echo, identical IPP replies, illegal
operation façade, stock HTML lure). Never submits print jobs. See
[`docs/tcp/IPP.md`](tcp/IPP.md).

The Memcached engine speaks the ASCII text protocol on **11211** / lab
**21211** and scores protocol non-compliance under all three basic strategies:
ASCII `set` accepted while binary SASL is answered as ASCII
(**arbitrary_auth**; open `set` alone is the protocol default), reconnect
`get` miss inside the TTL window and TTL-expiry enforcement
(**state_nonpersist**), plus **static_signature** (VERSION/stats framing,
unknown-command ERROR, get-miss END, gets/CAS façade, canned stats clone,
VERSION-vs-stats coherence, stock VERSION lure, bare-verbosity flush-stub
stand-in, noreply façade). Never sends `flush_all`; probe keys use an
`hpaudit_` prefix and are deleted when possible. See
[`docs/tcp/MEMCACHED.md`](tcp/MEMCACHED.md).

The Redis engine speaks RESP on TCP/6379 with **protocol non-compliance**
detection: dual random `AUTH` (decisive when both `+OK`), reconnect key
persistence + `DBSIZE` coherence, plus split static tells (`PING` stub,
`COMMAND`/`EVAL`/`CONFIG` stubs, frozen `INFO`, redis-cli `HELP`,
missing/mismatched `ECHO`/`SELECT`, OpenCanary AUTH+NOAUTH wall, `TYPE`/`INCR`
facades, wrong-arity `GET`, QUIT zombie). Never sends
`FLUSHALL`/`FLUSHDB`/`CONFIG SET`/`SCRIPT LOAD`; probe keys use an `hpaudit_`
prefix and are deleted. See [`docs/tcp/REDIS.md`](tcp/REDIS.md) and the
[Redis protocol spec](https://redis.io/docs/reference/protocol-spec/).

The Kubernetes engine speaks the API server on **6443** / lab **16443** (TLS,
read-only discovery paths) and scores decoy kube-API faces under
**static_signature** only: `/livez`/`/healthz` framing, `/version` shape,
`/api` APIVersions fidelity, unknown-path version-shaped 200s, method stubs,
stock `gitVersion` lures, and corroboration-gated unauthenticated `/api/v1`
object dumps. Never sends tokens or touches pods/secrets. See
[`docs/tcp/KUBERNETES.md`](tcp/KUBERNETES.md).

The Elasticsearch engine speaks the HTTP JSON API on **9200** / lab **19200**
and scores API non-compliance under all three basic strategies: anonymous
401/403 then dual entropy-varied Basic both return the root
(**arbitrary_auth**; open anonymous root is not a bypass), root vs `/_nodes` /
`/_cluster/health` metadata mismatch (**state_nonpersist**), plus
**static_signature** (root framing, stock cluster metadata/uuid, missing-index
**200**, unknown-path root facade, DELETE/PUT/HEAD method stubs,
`/_cluster/health` and `/_cat/health` shape facades, non-JSON Content-Type,
corroboration-gated `Accept: application/yaml` negotiation facade,
`X-Elastic-Product` mismatch). Never creates indices, bulks, or searches real
data. Strategies and probe flow:
[`docs/tcp/ELASTICSEARCH.md`](tcp/ELASTICSEARCH.md).

The Docker Engine API probe speaks the plain HTTP Engine API on **2375** / lab
**12375** and scores API non-compliance under **static_signature** only
(`/_ping` framing, `/version` Engine shape, path/method facades, thin `/info`
stubs, stock version lure metadata). Read-only only — never
create/start/exec/pull. TLS **2376** is out of scope. See
[`docs/tcp/DOCKER.md`](tcp/DOCKER.md).

The MQTT engine speaks OASIS MQTT v3.1.1 with **behavioral** honeypot detection
(not banner IOCs): dual synthetic CONNECT credentials when anonymous is
rejected, SUBSCRIBE-without-CONNECT, two-client pub/sub bus canary (granted
SUBACK + poll window), hollow `session_present` resume, keep-alive zombie
sockets (PINGRESP-after-expiry only; lab-oriented), plus conformance checks
(protocol-name facade, empty clientId + `clean_session=0`, QoS1 PUBACK
packet-id, PINGRESP). Ports **8883** and lab **18883** use implicit TLS
(MQTTS). It never publishes retained traffic or Will messages. See
[`docs/tcp/MQTT.md`](tcp/MQTT.md) and the
[MQTT 3.1.1 specification](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

The HTTP engine speaks HTTP/1.1 on **80/443** (lab **8081**) with decoy-web
detection: anonymous 401/403 then dual entropy-varied Basic on `/admin`
(**arbitrary_auth**), cookie replay 401/403 or POST without session side-effect
(**state_nonpersist**), plus **static_signature** — canned 200 on a malformed
POST, corroboration-gated **2xx** before an unterminated chunked body completes
(TLS skipped), missing `Date`, empty-405 method stubs, index.html login skins,
407 proxy-lure phrases, lure header orderings, framework session-on-404, and
silent TCP tarpit accepts; invalid wildcard `Host` values score
proto-conformance. Never smuggles requests or writes content. See
[`docs/tcp/HTTP.md`](tcp/HTTP.md).

The SIP engine speaks SIP/2.0 on **5060** (UDP with TCP fallback) with
transaction-coherence detection: two fake-Digest `REGISTER` 200s
(**arbitrary_auth**; nonce reuse alone is not scored), CSeq/Call-ID binding
drift across re-REGISTER (**state_nonpersist**), plus **static_signature**
(default User-Agent templates, corroboration-gated Via `received=`/`rport=`
coherence and per-transaction CSeq echo — requests carry distinct CSeqs and
randomized branches). Never sends INVITE/BYE/CANCEL or registers real users.
See [`docs/tcp/SIP.md`](tcp/SIP.md).

## Deep mode & optional layers

`--deep` adds cross-protocol axes (shell semantics, HASSH/TCP stack, FSM fuzz,
co-tenancy, serial + concurrent-load latency) on top of the basic strategies
above. Passive-intel providers and Nmap NSE (`-n`) are optional layers, not
protocol engines.
