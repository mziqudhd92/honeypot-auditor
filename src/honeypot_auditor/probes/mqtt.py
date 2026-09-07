"""MQTT 3.1.1 fingerprint engine.

Behavioral (non-signature) strategies:
  · arbitrary auth — anon rejected but two random CONNECT user/pass → CONNACK 0
  · state machine — SUBSCRIBE before CONNECT; clean-session resume hollow;
    two-client pub/sub bus canary; keep-alive zombie sockets
  · conformance — CONNACK framing; invalid protocol name; empty clientId +
    clean_session=0; QoS1 PUBACK packet-id fidelity; PINGRESP stub

Never publishes retained payloads, Will messages, or broad $SYS subscriptions.
Ephemeral topics use a unique ``honeypot-auditor/`` prefix and QoS0/1 only.

Port 8883 and lab 18883 use implicit TLS (MQTTS); 1883/11883 are cleartext.

See docs/MQTT.md and OASIS MQTT v3.1.1.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from contextlib import closing

from honeypot_auditor.models import Indicator, skipped_indicator
from honeypot_auditor.netutil import closed_reason
from honeypot_auditor.probes.common import is_safe_mode, random_creds, skip_suite
from honeypot_auditor.proxy_transport import create_connection, create_tls_connection
from honeypot_auditor.settings import settings

_MQTT_SKIP = (
    ("mqtt.arbitrary_auth", "MQTT accepts two random CONNECT credential pairs", "arbitrary_auth"),
    (
        "mqtt.preconnect_subscribe",
        "MQTT returns SUBACK without a prior CONNECT",
        "state_nonpersist",
    ),
    (
        "mqtt.message_bus",
        "MQTT acknowledges publish/subscribe but does not route messages",
        "state_nonpersist",
    ),
    (
        "mqtt.session_resume",
        "MQTT claims session_present without delivering resumed subscriptions",
        "state_nonpersist",
    ),
    (
        "mqtt.keepalive_zombie",
        "MQTT keeps the session alive past 1.5× keep-alive idle",
        "state_nonpersist",
    ),
    ("mqtt.connack", "MQTT CONNACK framing is invalid or absent", "static_signature"),
    (
        "mqtt.protocol_facade",
        "MQTT accepts CONNECT with an invalid protocol name",
        "static_signature",
    ),
    (
        "mqtt.empty_clientid",
        "MQTT accepts empty clientId with clean_session=0",
        "static_signature",
    ),
    (
        "mqtt.qos1_packet_id",
        "MQTT PUBACK packet id does not match the QoS1 PUBLISH",
        "static_signature",
    ),
    (
        "mqtt.ping_stub",
        "MQTT does not return PINGRESP after PINGREQ",
        "static_signature",
    ),
)

_MAX_RECV = 1024
_TLS_PORTS = frozenset({8883, 18883})  # 18883 = lab MQTTS (pairs with cleartext lab 11883)
_TOPIC_PREFIX = "honeypot-auditor/probe"
_DISCONNECT = b"\xe0\x00"
_PINGREQ = b"\xc0\x00"
# Spec: server closes after 1.5 × Keep Alive with no client packets. Tests patch this.
# Short keep-alive is lab-oriented; many cloud brokers floor Keep Alive and stay inconclusive.
_KEEPALIVE_SECONDS = 1
_KEEPALIVE_WAIT = 2.0  # > 1.5 × 1
_POLL_SLICE = 0.2
# MQTT 3.1.1 SUBACK return codes: 0x00/0x01/0x02 granted, 0x80 failure.
_SUBACK_GRANTED = frozenset({0x00, 0x01, 0x02})


def _encode_remaining_length(length: int) -> bytes:
    if length < 0 or length > 268_435_455:
        raise ValueError("MQTT remaining length out of range")
    out = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length > 0:
            digit |= 0x80
        out.append(digit)
        if length == 0:
            break
    return bytes(out)


def _decode_remaining_length(data: bytes, start: int = 1) -> tuple[int, int]:
    multiplier = 1
    value = 0
    pos = start
    for _ in range(4):
        if pos >= len(data):
            return -1, pos
        encoded = data[pos]
        pos += 1
        value += (encoded & 0x7F) * multiplier
        if (encoded & 0x80) == 0:
            return value, pos
        multiplier *= 128
    return -1, pos


def _mqtt_utf8(text: str | bytes) -> bytes:
    raw = text.encode("utf-8") if isinstance(text, str) else text
    if len(raw) > 65535:
        raise ValueError("MQTT UTF-8 string too long")
    return len(raw).to_bytes(2, "big") + raw


def build_connect(
    client_id: str,
    *,
    username: str | None = None,
    password: str | None = None,
    protocol_name: bytes = b"MQTT",
    protocol_level: int = 4,
    clean_session: bool = True,
    keep_alive: int = 60,
) -> bytes:
    """Build a MQTT 3.1.1 CONNECT packet."""
    variable = len(protocol_name).to_bytes(2, "big") + protocol_name
    flags = 0x02 if clean_session else 0x00
    if username is not None:
        flags |= 0x80
    if password is not None:
        flags |= 0x40
    variable += bytes([protocol_level & 0xFF, flags])
    variable += keep_alive.to_bytes(2, "big")
    payload = _mqtt_utf8(client_id)
    if username is not None:
        payload += _mqtt_utf8(username)
    if password is not None:
        payload += _mqtt_utf8(password)
    body = variable + payload
    return bytes([0x10]) + _encode_remaining_length(len(body)) + body


def build_subscribe(packet_id: int, topic: str, qos: int = 0) -> bytes:
    """Build a MQTT 3.1.1 SUBSCRIBE packet (flags must be 0b0010)."""
    payload = packet_id.to_bytes(2, "big") + _mqtt_utf8(topic) + bytes([qos & 0x03])
    return bytes([0x82]) + _encode_remaining_length(len(payload)) + payload


def build_publish(
    topic: str,
    payload: bytes,
    *,
    qos: int = 0,
    packet_id: int = 0,
    retain: bool = False,
) -> bytes:
    """Build a MQTT 3.1.1 PUBLISH (retain defaults off — non-destructive)."""
    flags = (qos & 0x03) << 1
    if retain:
        flags |= 0x01
    header = bytes([(0x30 | flags) & 0xFF])
    body = _mqtt_utf8(topic)
    if qos > 0:
        body += packet_id.to_bytes(2, "big")
    body += payload
    return header + _encode_remaining_length(len(body)) + body


def parse_connack(data: bytes) -> tuple[int, int] | None:
    """Return (acknowledge_flags, return_code) or None if not a CONNACK."""
    if not data or data[0] != 0x20:
        return None
    remaining, pos = _decode_remaining_length(data, 1)
    if remaining < 2 or pos + 2 > len(data):
        return None
    return data[pos], data[pos + 1]


def parse_puback(data: bytes) -> int | None:
    """Return PUBACK packet id or None."""
    if not data or (data[0] & 0xF0) != 0x40:
        return None
    remaining, pos = _decode_remaining_length(data, 1)
    if remaining < 2 or pos + 2 > len(data):
        return None
    return int.from_bytes(data[pos : pos + 2], "big")


def parse_suback(data: bytes) -> list[int] | None:
    """Return SUBACK return-code list, or None if no SUBACK frame is present."""
    for ptype, packet in _iter_packets(data):
        if (ptype & 0xF0) != 0x90:
            continue
        remaining, pos = _decode_remaining_length(packet, 1)
        if remaining < 3 or pos + remaining > len(packet):
            return None
        codes = list(packet[pos + 2 : pos + remaining])
        return codes or None
    return None


def _iter_packets(data: bytes):
    pos = 0
    while pos < len(data):
        ptype = data[pos]
        if pos + 1 >= len(data):
            break
        remaining, next_pos = _decode_remaining_length(data, pos + 1)
        if remaining < 0:
            break
        end = next_pos + remaining
        if end > len(data):
            break
        yield ptype, data[pos:end]
        pos = end


def _has_pingresp(data: bytes) -> bool:
    return any(ptype == 0xD0 for ptype, _ in _iter_packets(data))


def _has_suback(data: bytes) -> bool:
    """True if any SUBACK frame is present (used for pre-CONNECT tells)."""
    return parse_suback(data) is not None


def _subscription_granted(data: bytes) -> bool:
    """True only when SUBACK grants every topic (not 0x80 failure)."""
    codes = parse_suback(data)
    if not codes:
        return False
    return all(code in _SUBACK_GRANTED for code in codes)


def _has_publish(data: bytes) -> bool:
    return any((ptype & 0xF0) == 0x30 for ptype, _ in _iter_packets(data))


def _open_socket(host: str, port: int):
    timeout = settings.timeout_seconds
    if int(port) in _TLS_PORTS:
        return create_tls_connection(host, port, timeout)
    return create_connection(host, port, timeout)


def _recv(sock, max_bytes: int = _MAX_RECV) -> bytes:
    sock.settimeout(settings.timeout_seconds)
    try:
        return sock.recv(max_bytes) or b""
    except OSError:
        return b""


def _poll_for_canary(sock, token: bytes, *, deadline_s: float | None = None) -> bytes:
    """Poll subscriber socket until canary PUBLISH, any PUBLISH, or deadline."""
    budget = float(settings.timeout_seconds if deadline_s is None else deadline_s)
    deadline = time.monotonic() + max(0.05, budget)
    buf = bytearray()
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(_POLL_SLICE, remaining))
        try:
            chunk = sock.recv(_MAX_RECV) or b""
        except OSError:
            chunk = b""
        if not chunk:
            continue
        buf.extend(chunk)
        raw = bytes(buf)
        if _has_publish(raw):
            return raw
    return bytes(buf)


def _try_disconnect(sock) -> None:
    try:
        sock.sendall(_DISCONNECT)
    except OSError:
        pass


def _transact(host: str, port: int, payload: bytes) -> tuple[bytes, str]:
    try:
        with closing(_open_socket(host, port)) as sock:
            if payload:
                sock.sendall(payload)
            data = _recv(sock)
            connack = parse_connack(data)
            if connack is not None and connack[1] == 0:
                _try_disconnect(sock)
            return data, ""
    except OSError as exc:
        return b"", closed_reason(str(exc))


def _connect_session(
    host: str,
    port: int,
    packet: bytes,
    *,
    followups: list[bytes] | None = None,
    idle_before_followups: float = 0.0,
) -> tuple[bytes, list[bytes], str]:
    """CONNECT then optional follow-up packets on the same TCP/TLS session."""
    followups = followups or []
    replies: list[bytes] = []
    try:
        with closing(_open_socket(host, port)) as sock:
            sock.sendall(packet)
            first = _recv(sock)
            if idle_before_followups > 0:
                time.sleep(idle_before_followups)
            for item in followups:
                try:
                    sock.sendall(item)
                except OSError as exc:
                    return first, replies, closed_reason(str(exc))
                replies.append(_recv(sock))
            connack = parse_connack(first)
            if connack is not None and connack[1] == 0:
                _try_disconnect(sock)
            return first, replies, ""
    except OSError as exc:
        return b"", replies, closed_reason(str(exc))


def _client_id(prefix: str = "ha") -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def _probe_topic() -> str:
    return f"{_TOPIC_PREFIX}/{secrets.token_hex(6)}"


ConnectBuilder = Callable[..., bytes]


def _accepted_connect_builder(
    anonymous_ok: bool,
    auth_user: str | None,
    auth_pass: str | None,
) -> ConnectBuilder | None:
    if anonymous_ok:
        return lambda client_id, **kw: build_connect(client_id, **kw)
    if auth_user is not None and auth_pass is not None:
        user, pw = auth_user, auth_pass

        def _builder(client_id: str, **kw) -> bytes:
            kw.setdefault("username", user)
            kw.setdefault("password", pw)
            return build_connect(client_id, **kw)

        return _builder
    return None


def _qos1_check(
    host: str, port: int, builder: ConnectBuilder
) -> tuple[bool, bool, str, str]:
    """Return (triggered, skipped, detail, evidence)."""
    packet_id = 0x0A01
    topic = _probe_topic()
    payload = secrets.token_bytes(4)
    connect = builder(_client_id("qos"))
    first, replies, err = _connect_session(
        host,
        port,
        connect,
        followups=[build_publish(topic, payload, qos=1, packet_id=packet_id)],
    )
    connack = parse_connack(first)
    if connack is None or connack[1] != 0:
        return False, True, err or "could not CONNECT for QoS1 probe", ""
    puback_raw = replies[0] if replies else b""
    if not puback_raw:
        return False, True, "no PUBACK to QoS1 PUBLISH (timeout or silent)", ""
    got_id = parse_puback(puback_raw)
    if got_id is None:
        return (
            True,
            False,
            f"QoS1 PUBLISH answered with non-PUBACK: {puback_raw[:32]!r}",
            puback_raw[:_MAX_RECV].hex(),
        )
    if got_id != packet_id:
        return (
            True,
            False,
            f"PUBACK packet id {got_id:#06x} != PUBLISH id {packet_id:#06x}",
            puback_raw[:_MAX_RECV].hex(),
        )
    return False, False, "PUBACK packet id matched QoS1 PUBLISH", puback_raw[:_MAX_RECV].hex()


def _message_bus_check(
    host: str, port: int, builder: ConnectBuilder
) -> tuple[bool, bool, str, str]:
    """Two-session canary: subscriber must see publisher's QoS0 message."""
    topic = _probe_topic()
    token = secrets.token_hex(8).encode("ascii")
    sub_cid = _client_id("sub")
    pub_cid = _client_id("pub")
    try:
        with closing(_open_socket(host, port)) as sub_sock:
            sub_sock.sendall(builder(sub_cid))
            sub_connack = parse_connack(_recv(sub_sock))
            if sub_connack is None or sub_connack[1] != 0:
                return False, True, "subscriber CONNECT not accepted", ""
            sub_sock.sendall(build_subscribe(1, topic, qos=0))
            suback = _recv(sub_sock)
            if not _has_suback(suback):
                _try_disconnect(sub_sock)
                return False, True, "no SUBACK on subscriber session", suback[:64].hex()
            if not _subscription_granted(suback):
                _try_disconnect(sub_sock)
                codes = parse_suback(suback) or []
                return (
                    False,
                    True,
                    f"SUBSCRIBE denied (SUBACK codes={codes}); bus canary inconclusive",
                    suback[:64].hex(),
                )

            with closing(_open_socket(host, port)) as pub_sock:
                pub_sock.sendall(builder(pub_cid))
                pub_connack = parse_connack(_recv(pub_sock))
                if pub_connack is None or pub_connack[1] != 0:
                    _try_disconnect(sub_sock)
                    return False, True, "publisher CONNECT not accepted", ""
                pub_sock.sendall(build_publish(topic, token, qos=0))
                # QoS0 has no PUBACK; poll until canary, any PUBLISH, or timeout.
                delivered = _poll_for_canary(sub_sock, token)
                _try_disconnect(pub_sock)

            _try_disconnect(sub_sock)
            if _has_publish(delivered) and token in delivered:
                return False, False, "subscriber received publisher payload", delivered[:_MAX_RECV].hex()
            if _has_publish(delivered):
                return (
                    True,
                    False,
                    "subscriber got PUBLISH but payload did not match canary token",
                    delivered[:_MAX_RECV].hex(),
                )
            # Granted SUBACK + full poll silence: ACK-only stub (honeypot tell).
            return (
                True,
                False,
                "SUBSCRIBE/PUBLISH accepted but no routed PUBLISH on subscriber",
                delivered[:_MAX_RECV].hex(),
            )
    except OSError as exc:
        return False, True, closed_reason(str(exc)), ""


def _session_resume_check(
    host: str, port: int, builder: ConnectBuilder
) -> tuple[bool, bool, str, str]:
    """If broker claims session_present=1, resumed subscription must receive traffic."""
    topic = _probe_topic()
    token = secrets.token_hex(8).encode("ascii")
    cid = _client_id("sess")
    try:
        with closing(_open_socket(host, port)) as sock:
            sock.sendall(builder(cid, clean_session=False))
            first = parse_connack(_recv(sock))
            if first is None or first[1] != 0:
                return False, True, "initial clean_session=0 CONNECT not accepted", ""
            sock.sendall(build_subscribe(1, topic, qos=0))
            setup_suback = _recv(sock)
            if not _has_suback(setup_suback):
                _try_disconnect(sock)
                return False, True, "no SUBACK during session setup", ""
            if not _subscription_granted(setup_suback):
                _try_disconnect(sock)
                codes = parse_suback(setup_suback) or []
                return (
                    False,
                    True,
                    f"SUBSCRIBE denied during session setup (SUBACK codes={codes})",
                    setup_suback[:64].hex(),
                )
            _try_disconnect(sock)

        with closing(_open_socket(host, port)) as sock:
            sock.sendall(builder(cid, clean_session=False))
            raw = _recv(sock)
            resumed = parse_connack(raw)
            if resumed is None or resumed[1] != 0:
                return False, True, "resume CONNECT not accepted", raw[:64].hex()
            if (resumed[0] & 0x01) == 0:
                _try_disconnect(sock)
                return (
                    False,
                    True,
                    "session_present=0 after clean_session=0 resume (inconclusive)",
                    raw[:_MAX_RECV].hex(),
                )

            with closing(_open_socket(host, port)) as pub_sock:
                pub_sock.sendall(builder(_client_id("sesspub")))
                pub_ca = parse_connack(_recv(pub_sock))
                if pub_ca is None or pub_ca[1] != 0:
                    _try_disconnect(sock)
                    return False, True, "peer CONNECT failed during resume check", ""
                pub_sock.sendall(build_publish(topic, token, qos=0))
                delivered = _poll_for_canary(sock, token)
                _try_disconnect(pub_sock)
            _try_disconnect(sock)

            if _has_publish(delivered) and token in delivered:
                return (
                    False,
                    False,
                    "session_present=1 and resumed subscription delivered canary",
                    delivered[:_MAX_RECV].hex(),
                )
            return (
                True,
                False,
                "session_present=1 but resumed subscription did not receive canary PUBLISH",
                delivered[:_MAX_RECV].hex(),
            )
    except OSError as exc:
        return False, True, closed_reason(str(exc)), ""


def _keepalive_zombie_check(
    host: str, port: int, builder: ConnectBuilder
) -> tuple[bool, bool, str, str]:
    """Lab-oriented keep-alive check: only a clear PINGRESP after expiry is a tell.

    Silence, close, or non-PINGRESP traffic after idle is skipped (inconclusive) —
    many production brokers floor Keep Alive or defer disconnect.
    """
    connect = builder(_client_id("ka"), keep_alive=_KEEPALIVE_SECONDS)
    first, replies, err = _connect_session(
        host,
        port,
        connect,
        followups=[_PINGREQ],
        idle_before_followups=_KEEPALIVE_WAIT,
    )
    connack = parse_connack(first)
    if connack is None or connack[1] != 0:
        return False, True, err or "CONNECT for keep-alive probe failed", ""
    if err and not replies:
        # Send failed after idle — likely server closed (conformant).
        return False, False, f"session closed after idle ({err})", ""
    ping_raw = replies[0] if replies else b""
    if not ping_raw:
        # Closed or silent after idle — treat as conformant / inconclusive.
        return False, True, "no response after keep-alive idle (closed or timeout)", ""
    if _has_pingresp(ping_raw):
        return (
            True,
            False,
            f"PINGRESP after {_KEEPALIVE_WAIT:.1f}s idle with keep_alive={_KEEPALIVE_SECONDS} "
            f"(server should have disconnected at 1.5× keep-alive)",
            ping_raw[:_MAX_RECV].hex(),
        )
    # Responsive but not PINGRESP — ambiguous (proxy noise, broker quirk); do not score.
    return (
        False,
        True,
        "non-PINGRESP traffic after keep-alive expiry (inconclusive)",
        ping_raw[:_MAX_RECV].hex(),
    )


def probe_mqtt(host: str, port: int) -> list[Indicator]:
    base_packet = build_connect(_client_id("probe"))
    base_raw, base_err = _transact(host, port, base_packet)
    connack = parse_connack(base_raw)
    if base_err and not base_raw:
        return skip_suite(_MQTT_SKIP, base_err, protocol="mqtt", error=base_err)
    if connack is None:
        reason = "not an MQTT CONNACK speaker"
        out: list[Indicator] = []
        for spec in _MQTT_SKIP:
            if spec[0] == "mqtt.connack":
                out.append(
                    Indicator(
                        id="mqtt.connack",
                        title="MQTT CONNACK framing is invalid or absent",
                        category="static_signature",
                        triggered=bool(base_raw),
                        skipped=not base_raw,
                        skip_reason=base_err or reason if not base_raw else "",
                        error=base_err,
                        protocol="mqtt",
                        detail=(
                            f"expected CONNACK (type 0x20); received {base_raw[:64]!r}"
                            if base_raw
                            else reason
                        ),
                        evidence=base_raw[:_MAX_RECV].hex(),
                        remediation="Return a standards-conformant MQTT 3.1.1 CONNACK",
                    )
                )
            else:
                out.append(
                    skipped_indicator(*spec, reason, protocol="mqtt", error=base_err)
                )
        return out

    session_present, return_code = connack
    connack_ind = Indicator(
        id="mqtt.connack",
        title="MQTT CONNACK framing is invalid or absent",
        category="static_signature",
        triggered=False,
        protocol="mqtt",
        detail=(
            f"CONNACK return_code={return_code} session_present={session_present & 0x01}"
        ),
        evidence=base_raw[:_MAX_RECV].hex(),
        remediation="Return a standards-conformant MQTT 3.1.1 CONNACK",
    )

    if is_safe_mode():
        reason = "safe-mode: handshake-only probe"
        safe_out: list[Indicator] = []
        for spec in _MQTT_SKIP:
            if spec[0] == "mqtt.connack":
                safe_out.append(connack_ind)
            else:
                safe_out.append(skipped_indicator(*spec, reason, protocol="mqtt"))
        return safe_out

    # --- empty clientId + clean_session=0 (MQTT 3.1.1 §3.1.3.1) ---
    empty_raw, empty_err = _transact(
        host, port, build_connect("", clean_session=False)
    )
    empty_ca = parse_connack(empty_raw)
    empty_hit = empty_ca is not None and empty_ca[1] == 0
    empty_skipped = not empty_raw and bool(empty_err)

    # --- protocol-name facade ---
    facade_raw, facade_err = _transact(
        host,
        port,
        build_connect(_client_id("facade"), protocol_name=b"MXTT", protocol_level=4),
    )
    facade_connack = parse_connack(facade_raw)
    facade_hit = facade_connack is not None and facade_connack[1] == 0
    facade_skipped = not facade_raw and bool(facade_err)

    # --- dual random credentials ---
    attempts = [random_creds(), random_creds()]
    accepted_users: list[str] = []
    auth_evidence: list[str] = []
    auth_errors: list[str] = []
    anonymous_ok = return_code == 0
    working_user: str | None = None
    working_pass: str | None = None
    for username, password in attempts:
        raw, err = _transact(
            host,
            port,
            build_connect(_client_id("auth"), username=username, password=password),
        )
        parsed = parse_connack(raw)
        if parsed is not None and parsed[1] == 0:
            accepted_users.append(username)
            auth_evidence.append(f"{username}: CONNACK rc=0")
            working_user, working_pass = username, password
        elif parsed is not None:
            auth_evidence.append(f"{username}: CONNACK rc={parsed[1]}")
        elif err:
            auth_errors.append(f"{username}: {err}")
        else:
            auth_evidence.append(f"{username}: non-CONNACK {raw[:32]!r}")
    auth_both = len(accepted_users) == len(attempts)
    if anonymous_ok:
        auth_hit = False
        auth_skipped = True
        auth_skip_reason = (
            "anonymous CONNECT already accepted (rc=0); "
            "credential acceptance is inconclusive for arbitrary-auth"
        )
    else:
        auth_hit = auth_both
        auth_skipped = not auth_evidence and bool(auth_errors)
        auth_skip_reason = "; ".join(auth_errors) if auth_skipped else ""

    # --- preconnect SUBSCRIBE ---
    sub_raw, sub_err = _transact(host, port, build_subscribe(1, _probe_topic(), qos=0))
    sub_hit = _has_suback(sub_raw)
    sub_skipped = not sub_raw and bool(sub_err)

    builder = _accepted_connect_builder(anonymous_ok, working_user, working_pass)
    session_skip = "no accepted CONNECT path for authenticated session probes"

    if builder is None:
        bus_hit = sess_hit = ka_hit = qos_hit = ping_hit = False
        bus_skipped = sess_skipped = ka_skipped = qos_skipped = ping_skipped = True
        bus_detail = sess_detail = ka_detail = qos_detail = ping_detail = session_skip
        bus_ev = sess_ev = ka_ev = qos_ev = ping_ev = ""
    else:
        qos_hit, qos_skipped, qos_detail, qos_ev = _qos1_check(host, port, builder)
        bus_hit, bus_skipped, bus_detail, bus_ev = _message_bus_check(host, port, builder)
        sess_hit, sess_skipped, sess_detail, sess_ev = _session_resume_check(
            host, port, builder
        )
        ka_hit, ka_skipped, ka_detail, ka_ev = _keepalive_zombie_check(
            host, port, builder
        )

        ping_hit = False
        ping_skipped = False
        ping_detail = "PINGRESP received after PINGREQ"
        ping_ev = ""
        if anonymous_ok or working_user is not None:
            ping_connect = builder(_client_id("ping"))
            first, follow_replies, ping_err = _connect_session(
                host, port, ping_connect, followups=[_PINGREQ]
            )
            ping_raw = follow_replies[0] if follow_replies else b""
            ping_connack = parse_connack(first)
            if ping_connack is None or ping_connack[1] != 0:
                ping_skipped = True
                ping_detail = ping_err or "could not establish CONNECT for PINGREQ"
            elif not ping_raw:
                ping_skipped = True
                ping_detail = ping_err or "no response to PINGREQ (timeout or silent close)"
            else:
                ping_hit = not _has_pingresp(ping_raw)
                ping_detail = (
                    "non-PINGRESP payload after PINGREQ on an accepted session"
                    if ping_hit
                    else "PINGRESP received after PINGREQ"
                )
                ping_ev = ping_raw[:_MAX_RECV].hex()
        else:
            ping_skipped = True
            ping_detail = session_skip

    return [
        Indicator(
            id="mqtt.arbitrary_auth",
            title="MQTT accepts two random CONNECT credential pairs",
            category="arbitrary_auth",
            triggered=auth_hit,
            skipped=auth_skipped,
            skip_reason=auth_skip_reason,
            error="; ".join(auth_errors),
            protocol="mqtt",
            detail=(
                "anonymous CONNECT was rejected but two random username/password "
                "CONNECT packets both received CONNACK return code 0"
                if auth_hit
                else (
                    auth_skip_reason
                    if auth_skipped and anonymous_ok
                    else "random CONNECT credentials were not both accepted after anonymous rejection"
                )
            ),
            evidence=",".join(accepted_users) if auth_hit else "; ".join(auth_evidence),
            remediation="Reject unknown MQTT credentials instead of always returning CONNACK 0",
            fidelity="decisive" if auth_hit else "medium",
        ),
        Indicator(
            id="mqtt.preconnect_subscribe",
            title="MQTT returns SUBACK without a prior CONNECT",
            category="state_nonpersist",
            triggered=sub_hit,
            skipped=sub_skipped,
            skip_reason=sub_err if sub_skipped else "",
            error=sub_err,
            protocol="mqtt",
            detail=(
                "SUBACK received with no preceding CONNECT on the session"
                if sub_hit
                else "SUBSCRIBE without CONNECT did not yield SUBACK"
            ),
            evidence=sub_raw[:_MAX_RECV].hex(),
            remediation="Ignore or close sessions that send control packets before CONNECT",
        ),
        Indicator(
            id="mqtt.message_bus",
            title="MQTT acknowledges publish/subscribe but does not route messages",
            category="state_nonpersist",
            triggered=bus_hit,
            skipped=bus_skipped,
            skip_reason=bus_detail if bus_skipped else "",
            protocol="mqtt",
            detail=bus_detail,
            evidence=bus_ev,
            remediation="Implement a real broker message bus between clients, not per-socket ACKs",
            fidelity="high" if bus_hit else "medium",
        ),
        Indicator(
            id="mqtt.session_resume",
            title="MQTT claims session_present without delivering resumed subscriptions",
            category="state_nonpersist",
            triggered=sess_hit,
            skipped=sess_skipped,
            skip_reason=sess_detail if sess_skipped else "",
            protocol="mqtt",
            detail=sess_detail,
            evidence=sess_ev,
            remediation="Honor clean_session=0: restore subscriptions when session_present=1",
            fidelity="high" if sess_hit else "medium",
        ),
        Indicator(
            id="mqtt.keepalive_zombie",
            title="MQTT keeps the session alive past 1.5× keep-alive idle",
            category="state_nonpersist",
            triggered=ka_hit,
            skipped=ka_skipped,
            skip_reason=ka_detail if ka_skipped else "",
            protocol="mqtt",
            detail=ka_detail,
            evidence=ka_ev,
            remediation="Disconnect clients that exceed 1.5 × Keep Alive without packets",
        ),
        connack_ind,
        Indicator(
            id="mqtt.protocol_facade",
            title="MQTT accepts CONNECT with an invalid protocol name",
            category="static_signature",
            triggered=facade_hit,
            skipped=facade_skipped,
            skip_reason=facade_err if facade_skipped else "",
            error=facade_err,
            protocol="mqtt",
            detail=(
                "CONNECT with protocol name 'MXTT' received CONNACK return code 0"
                if facade_hit
                else (
                    f"invalid protocol name rejected (rc={facade_connack[1]})"
                    if facade_connack is not None
                    else "invalid protocol name did not return accepting CONNACK"
                )
            ),
            evidence=facade_raw[:_MAX_RECV].hex(),
            remediation="Return CONNACK return code 1 for unacceptable protocol names",
            fidelity="high" if facade_hit else "medium",
        ),
        Indicator(
            id="mqtt.empty_clientid",
            title="MQTT accepts empty clientId with clean_session=0",
            category="static_signature",
            triggered=empty_hit,
            skipped=empty_skipped,
            skip_reason=empty_err if empty_skipped else "",
            error=empty_err,
            protocol="mqtt",
            detail=(
                "empty clientId + clean_session=0 received CONNACK return code 0 "
                "(MQTT 3.1.1 requires return code 2)"
                if empty_hit
                else (
                    f"empty clientId rejected (rc={empty_ca[1]})"
                    if empty_ca is not None
                    else "empty clientId did not return accepting CONNACK"
                )
            ),
            evidence=empty_raw[:_MAX_RECV].hex(),
            remediation="Return CONNACK return code 2 when clientId is empty and clean_session=0",
            fidelity="high" if empty_hit else "medium",
        ),
        Indicator(
            id="mqtt.qos1_packet_id",
            title="MQTT PUBACK packet id does not match the QoS1 PUBLISH",
            category="static_signature",
            triggered=qos_hit,
            skipped=qos_skipped,
            skip_reason=qos_detail if qos_skipped else "",
            protocol="mqtt",
            detail=qos_detail,
            evidence=qos_ev,
            remediation="Echo the PUBLISH packet identifier in PUBACK",
        ),
        Indicator(
            id="mqtt.ping_stub",
            title="MQTT does not return PINGRESP after PINGREQ",
            category="static_signature",
            triggered=ping_hit,
            skipped=ping_skipped,
            skip_reason=ping_detail if ping_skipped else "",
            protocol="mqtt",
            detail=ping_detail,
            evidence=ping_ev,
            remediation="Answer PINGREQ with PINGRESP on established sessions",
        ),
    ]


__all__ = [
    "build_connect",
    "build_publish",
    "build_subscribe",
    "parse_connack",
    "parse_puback",
    "parse_suback",
    "probe_mqtt",
]
