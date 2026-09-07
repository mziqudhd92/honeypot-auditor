# MQTT probe

Honeypot-auditor’s MQTT engine speaks **OASIS MQTT v3.1.1** (protocol name `MQTT`,
protocol level `4`) over cleartext **1883** / lab **11883**, and implicit TLS
(**MQTTS**) on **8883** and lab **18883**.

It is designed to catch ACK-only stubs (OpenCanary-class and similar) using
**behavioral** checks — session state, message routing, keep-alive lifecycle —
not lure banner strings.

## Non-destructive policy

| Allowed | Never done |
|---------|------------|
| CONNECT / CONNACK | Retained PUBLISH (`retain=1`) |
| SUBSCRIBE to ephemeral `honeypot-auditor/probe/<token>` topics | Will messages |
| QoS0 / QoS1 PUBLISH of opaque random bytes | Broad `$SYS/#` harvesting |
| DISCONNECT | Password spraying beyond two synthetic pairs |

## Ports and TLS

| Port | Mode |
|------|------|
| 1883 | Cleartext MQTT |
| 11883 | Lab cleartext MQTT |
| 8883 | Implicit TLS (MQTTS) |
| 18883 | Lab MQTTS (implicit TLS) |

## Indicators

### Arbitrary auth

| ID | Trigger |
|----|---------|
| `mqtt.arbitrary_auth` | Anonymous CONNECT was **rejected**, but two independent random username/password CONNECTs both get CONNACK return code `0`. |

If anonymous CONNECT already succeeds (`allow_anonymous`), this tell is **skipped**
(inconclusive). Use `mqtt.message_bus` / session tells for those skins.

### State non-persistence (behavioral)

| ID | Trigger |
|----|---------|
| `mqtt.preconnect_subscribe` | SUBSCRIBE on a fresh TCP session with **no** prior CONNECT yields SUBACK (any return code — the frame itself is the tell). |
| `mqtt.message_bus` | Two accepted sessions: A gets a **granted** SUBACK for canary topic T, B PUBLISHes QoS0 to T, A never receives the canary after a full poll window (ACK-only stub). SUBACK failure (`0x80`, e.g. ACL deny) is **skipped**. |
| `mqtt.session_resume` | After granted `clean_session=0` SUBSCRIBE + DISCONNECT, resume CONNECT returns `session_present=1` but the resumed subscription does **not** receive a peer PUBLISH after polling. If `session_present=0` or SUBACK was denied, the tell is skipped (inconclusive). |
| `mqtt.keepalive_zombie` | CONNECT with `keep_alive=1`, idle past **1.5×** keep-alive, then PINGREQ still gets **PINGRESP** (server should have closed). Lab-oriented: silence, close, or non-PINGRESP after idle is **skipped** (cloud brokers often floor Keep Alive). |

### Static / conformance

| ID | Trigger |
|----|---------|
| `mqtt.connack` | Response is not a CONNACK (not an MQTT speaker). |
| `mqtt.protocol_facade` | CONNECT with protocol name `MXTT` still gets CONNACK `0` (should be return code `1`). |
| `mqtt.empty_clientid` | Empty `clientId` + `clean_session=0` gets CONNACK `0` (MQTT 3.1.1 §3.1.3.1 requires return code `2`). |
| `mqtt.qos1_packet_id` | QoS1 PUBLISH is answered with a non-PUBACK, or PUBACK packet id ≠ PUBLISH id. |
| `mqtt.ping_stub` | Accepted session answers PINGREQ with a non-PINGRESP payload. **Silence/timeout is skipped**, not triggered. |

## Safe mode

`--safe-mode` / `safe_mode`: only the baseline CONNECT/CONNACK framing check runs;
all other MQTT indicators are skipped.

## Spec references

- [OASIS MQTT v3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)
  — CONNECT/CONNACK, Keep Alive (§3.1.2.10), session present, SUBSCRIBE/SUBACK
  return codes, PUBACK packet identifiers
- IANA: 1883/tcp MQTT, 8883/tcp MQTT over TLS

## Scoring

All three basic strategies are active for MQTT (`PROTOCOL_STRATEGIES["mqtt"]`).
High-signal fidelity is set on `arbitrary_auth` (decisive when hit),
`message_bus`, `session_resume`, `protocol_facade`, and `empty_clientid` (high).
