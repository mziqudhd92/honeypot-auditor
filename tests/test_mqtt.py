"""MQTT 3.1.1 probe tests with a scripted socket transport."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.mqtt as mqtt
from honeypot_auditor.settings import settings


class ScriptedSocket:
    """One recv() returns the next queued chunk (MQTT multi-packet sessions)."""

    def __init__(self, *chunks: bytes) -> None:
        self._chunks = list(chunks)
        self.sent: list[bytes] = []
        self.closed = False

    def recv(self, size: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def settimeout(self, _timeout: float) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _connack(rc: int = 0, session_present: int = 0) -> bytes:
    return bytes([0x20, 0x02, session_present & 0x01, rc & 0xFF])


def _suback(packet_id: int = 1, return_code: int = 0) -> bytes:
    return bytes([0x90, 0x03]) + packet_id.to_bytes(2, "big") + bytes([return_code])


def _puback(packet_id: int) -> bytes:
    return bytes([0x40, 0x02]) + packet_id.to_bytes(2, "big")


def _pingresp() -> bytes:
    return b"\xd0\x00"


def _publish(topic: str, payload: bytes) -> bytes:
    return mqtt.build_publish(topic, payload, qos=0)


def _clean_session_checks():
    """Patch behavioral session probes to no-op so legacy suites stay small."""
    clean = (False, False, "ok", "")
    return (
        patch.object(mqtt, "_qos1_check", return_value=clean),
        patch.object(mqtt, "_message_bus_check", return_value=clean),
        patch.object(mqtt, "_session_resume_check", return_value=(False, True, "skip", "")),
        patch.object(mqtt, "_keepalive_zombie_check", return_value=(False, True, "skip", "")),
    )


def _run_with_sessions(*sessions: ScriptedSocket, port: int = 1883):
    with patch.object(mqtt, "create_connection", side_effect=sessions):
        with patch.object(mqtt, "create_tls_connection", side_effect=sessions):
            return mqtt.probe_mqtt("127.0.0.1", port)


def _anon_builder(client_id: str, **kw):
    return mqtt.build_connect(client_id, **kw)


def test_mqtt_packet_helpers_round_trip():
    packet = mqtt.build_connect("cid", username="u", password="p")
    assert packet[0] == 0x10
    assert mqtt.parse_connack(_connack(0)) == (0, 0)
    assert mqtt.parse_puback(_puback(0x0A01)) == 0x0A01
    pub = mqtt.build_publish("t/x", b"hi", qos=1, packet_id=7)
    assert pub[0] & 0xF0 == 0x30


def test_mqtt_conformant_broker_is_clean():
    sessions = [
        ScriptedSocket(_connack(0)),  # baseline
        ScriptedSocket(_connack(2)),  # empty clientId rejected
        ScriptedSocket(_connack(1)),  # facade
        ScriptedSocket(_connack(5)),  # auth a
        ScriptedSocket(_connack(5)),  # auth b
        ScriptedSocket(b""),  # preconnect
        ScriptedSocket(_connack(0), _pingresp()),  # ping
    ]
    patches = _clean_session_checks()
    with patches[0], patches[1], patches[2], patches[3]:
        inds = _run_with_sessions(*sessions)
    assert not any(ind.triggered for ind in inds)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["mqtt.arbitrary_auth"].skipped
    assert len(inds) == 10


def test_mqtt_anonymous_open_broker_does_not_score_arbitrary_auth():
    sessions = [
        ScriptedSocket(_connack(0)),
        ScriptedSocket(_connack(2)),
        ScriptedSocket(_connack(1)),
        ScriptedSocket(_connack(0)),
        ScriptedSocket(_connack(0)),
        ScriptedSocket(b""),
        ScriptedSocket(_connack(0), _pingresp()),
    ]
    patches = _clean_session_checks()
    with patches[0], patches[1], patches[2], patches[3]:
        with patch.object(
            mqtt, "random_creds", side_effect=[("user_a", "pass_a"), ("user_b", "pass_b")]
        ):
            inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert not by_id["mqtt.arbitrary_auth"].triggered
    assert by_id["mqtt.arbitrary_auth"].skipped


def test_mqtt_honeypot_tells_fire():
    sessions = [
        ScriptedSocket(_connack(5)),  # anon rejected
        ScriptedSocket(_connack(0)),  # empty clientId accepted (tell)
        ScriptedSocket(_connack(0)),  # facade accepted
        ScriptedSocket(_connack(0)),  # auth a
        ScriptedSocket(_connack(0)),  # auth b
        ScriptedSocket(_suback()),  # preconnect
        # builder available via auth → ping session
        ScriptedSocket(_connack(0), _connack(0)),  # ping wrong payload
    ]
    patches = _clean_session_checks()
    with patches[0], patches[1], patches[2], patches[3]:
        with patch.object(
            mqtt, "random_creds", side_effect=[("user_a", "pass_a"), ("user_b", "pass_b")]
        ):
            inds = _run_with_sessions(*sessions)
    by_id = {ind.id: ind for ind in inds}
    assert by_id["mqtt.arbitrary_auth"].triggered
    assert by_id["mqtt.protocol_facade"].triggered
    assert by_id["mqtt.empty_clientid"].triggered
    assert by_id["mqtt.preconnect_subscribe"].triggered
    assert by_id["mqtt.ping_stub"].triggered


def test_mqtt_qos1_packet_id_mismatch():
    sock = ScriptedSocket(_connack(0), _puback(0x0001))  # wrong id vs 0x0A01
    with patch.object(mqtt, "create_connection", side_effect=[sock]):
        hit, skipped, detail, _ = mqtt._qos1_check("127.0.0.1", 1883, _anon_builder)
    assert hit and not skipped
    assert "packet id" in detail


def test_mqtt_qos1_packet_id_match_is_clean():
    sock = ScriptedSocket(_connack(0), _puback(0x0A01))
    with patch.object(mqtt, "create_connection", side_effect=[sock]):
        hit, skipped, _, _ = mqtt._qos1_check("127.0.0.1", 1883, _anon_builder)
    assert not hit and not skipped


def test_mqtt_message_bus_missing_route():
    sub = ScriptedSocket(_connack(0), _suback(), b"")  # no routed publish
    pub = ScriptedSocket(_connack(0))
    with patch.object(mqtt, "create_connection", side_effect=[sub, pub]):
        with patch.object(mqtt.settings, "timeout_seconds", 0.05):
            hit, skipped, detail, _ = mqtt._message_bus_check(
                "127.0.0.1", 1883, _anon_builder
            )
    assert hit and not skipped
    assert "no routed PUBLISH" in detail


def test_mqtt_message_bus_suback_failure_is_skipped():
    sub = ScriptedSocket(_connack(0), _suback(return_code=0x80))
    with patch.object(mqtt, "create_connection", side_effect=[sub]):
        hit, skipped, detail, _ = mqtt._message_bus_check(
            "127.0.0.1", 1883, _anon_builder
        )
    assert not hit and skipped
    assert "SUBSCRIBE denied" in detail


def test_mqtt_message_bus_delivers_canary():
    topic_holder: list[str] = []
    token_holder: list[bytes] = []

    class BusSub(ScriptedSocket):
        def recv(self, size: int) -> bytes:
            if self._chunks:
                return super().recv(size)
            if token_holder:
                return _publish(topic_holder[0], token_holder[0])
            return b""

    sub = BusSub(_connack(0), _suback())
    pub = ScriptedSocket(_connack(0))

    real_publish = mqtt.build_publish

    def capture_publish(topic, payload, **kw):
        topic_holder.clear()
        topic_holder.append(topic)
        token_holder.clear()
        token_holder.append(payload)
        return real_publish(topic, payload, **kw)

    with patch.object(mqtt, "build_publish", side_effect=capture_publish):
        with patch.object(mqtt, "create_connection", side_effect=[sub, pub]):
            hit, skipped, detail, _ = mqtt._message_bus_check(
                "127.0.0.1", 1883, _anon_builder
            )
    assert not hit and not skipped
    assert "received publisher payload" in detail


def test_mqtt_message_bus_delayed_canary_is_clean():
    """Slow brokers that deliver after the first empty recv must not false-trigger."""
    topic_holder: list[str] = []
    token_holder: list[bytes] = []

    class DelayedBusSub(ScriptedSocket):
        def __init__(self, *chunks: bytes) -> None:
            super().__init__(*chunks)
            self._empty_polls = 0

        def recv(self, size: int) -> bytes:
            if self._chunks:
                return super().recv(size)
            self._empty_polls += 1
            if self._empty_polls < 3 or not token_holder:
                return b""
            return _publish(topic_holder[0], token_holder[0])

    sub = DelayedBusSub(_connack(0), _suback())
    pub = ScriptedSocket(_connack(0))
    real_publish = mqtt.build_publish

    def capture_publish(topic, payload, **kw):
        topic_holder.clear()
        topic_holder.append(topic)
        token_holder.clear()
        token_holder.append(payload)
        return real_publish(topic, payload, **kw)

    with patch.object(mqtt, "build_publish", side_effect=capture_publish):
        with patch.object(mqtt, "create_connection", side_effect=[sub, pub]):
            with patch.object(mqtt, "_POLL_SLICE", 0.01):
                with patch.object(mqtt.settings, "timeout_seconds", 0.5):
                    hit, skipped, detail, _ = mqtt._message_bus_check(
                        "127.0.0.1", 1883, _anon_builder
                    )
    assert not hit and not skipped
    assert "received publisher payload" in detail
    assert sub._empty_polls >= 3


def test_mqtt_session_resume_hollow():
    setup = ScriptedSocket(_connack(0), _suback())
    resume = ScriptedSocket(_connack(0, session_present=1), b"")  # claim session, no delivery
    peer = ScriptedSocket(_connack(0))
    with patch.object(mqtt, "create_connection", side_effect=[setup, resume, peer]):
        with patch.object(mqtt.settings, "timeout_seconds", 0.05):
            hit, skipped, detail, _ = mqtt._session_resume_check(
                "127.0.0.1", 1883, _anon_builder
            )
    assert hit and not skipped
    assert "session_present=1" in detail


def test_mqtt_session_resume_suback_failure_is_skipped():
    setup = ScriptedSocket(_connack(0), _suback(return_code=0x80))
    with patch.object(mqtt, "create_connection", side_effect=[setup]):
        hit, skipped, detail, _ = mqtt._session_resume_check(
            "127.0.0.1", 1883, _anon_builder
        )
    assert not hit and skipped
    assert "SUBSCRIBE denied" in detail


def test_mqtt_session_resume_absent_is_skipped():
    setup = ScriptedSocket(_connack(0), _suback())
    resume = ScriptedSocket(_connack(0, session_present=0))
    with patch.object(mqtt, "create_connection", side_effect=[setup, resume]):
        hit, skipped, _, _ = mqtt._session_resume_check(
            "127.0.0.1", 1883, _anon_builder
        )
    assert not hit and skipped


def test_mqtt_keepalive_zombie():
    sock = ScriptedSocket(_connack(0), _pingresp())
    with patch.object(mqtt, "_KEEPALIVE_WAIT", 0):
        with patch.object(mqtt, "create_connection", side_effect=[sock]):
            hit, skipped, detail, _ = mqtt._keepalive_zombie_check(
                "127.0.0.1", 1883, _anon_builder
            )
    assert hit and not skipped
    assert "PINGRESP after" in detail


def test_mqtt_keepalive_non_pingresp_is_skipped():
    sock = ScriptedSocket(_connack(0), _connack(0))  # garbage after idle
    with patch.object(mqtt, "_KEEPALIVE_WAIT", 0):
        with patch.object(mqtt, "create_connection", side_effect=[sock]):
            hit, skipped, detail, _ = mqtt._keepalive_zombie_check(
                "127.0.0.1", 1883, _anon_builder
            )
    assert not hit and skipped
    assert "inconclusive" in detail


def test_mqtt_parse_suback_return_codes():
    assert mqtt.parse_suback(_suback(return_code=0)) == [0]
    assert mqtt.parse_suback(_suback(return_code=0x80)) == [0x80]
    assert mqtt._subscription_granted(_suback(return_code=0))
    assert not mqtt._subscription_granted(_suback(return_code=0x80))
    assert mqtt._has_suback(_suback(return_code=0x80))


def test_mqtt_empty_clientid_accepted():
    sessions = [
        ScriptedSocket(_connack(0)),
        ScriptedSocket(_connack(0)),  # empty id accepted
        ScriptedSocket(_connack(1)),
        ScriptedSocket(_connack(5)),
        ScriptedSocket(_connack(5)),
        ScriptedSocket(b""),
        ScriptedSocket(_connack(0), _pingresp()),
    ]
    patches = _clean_session_checks()
    with patches[0], patches[1], patches[2], patches[3]:
        inds = _run_with_sessions(*sessions)
    assert {i.id: i for i in inds}["mqtt.empty_clientid"].triggered


def test_mqtt_safe_mode_handshake_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        inds = _run_with_sessions(ScriptedSocket(_connack(0)))
    finally:
        settings.safe_mode = old
    by_id = {ind.id: ind for ind in inds}
    assert len(inds) == 10
    assert not by_id["mqtt.connack"].skipped
    assert by_id["mqtt.message_bus"].skipped
    assert by_id["mqtt.empty_clientid"].skipped


def test_mqtt_connection_error_skips_suite():
    with patch.object(mqtt, "create_connection", side_effect=OSError("refused")):
        inds = mqtt.probe_mqtt("127.0.0.1", 1883)
    assert len(inds) == 10
    assert all(ind.skipped for ind in inds)


def test_mqtt_port_8883_uses_tls():
    sessions = [
        ScriptedSocket(_connack(0)),
        ScriptedSocket(_connack(2)),
        ScriptedSocket(_connack(1)),
        ScriptedSocket(_connack(5)),
        ScriptedSocket(_connack(5)),
        ScriptedSocket(b""),
        ScriptedSocket(_connack(0), _pingresp()),
    ]
    patches = _clean_session_checks()
    with patches[0], patches[1], patches[2], patches[3]:
        with patch.object(mqtt, "create_tls_connection", side_effect=sessions) as tls:
            with patch.object(mqtt, "create_connection") as plain:
                inds = mqtt.probe_mqtt("127.0.0.1", 8883)
    assert tls.call_count >= 1
    plain.assert_not_called()
    assert not any(ind.triggered for ind in inds)


def test_mqtt_lab_port_18883_uses_tls():
    sessions = [
        ScriptedSocket(_connack(0)),
        ScriptedSocket(_connack(2)),
        ScriptedSocket(_connack(1)),
        ScriptedSocket(_connack(5)),
        ScriptedSocket(_connack(5)),
        ScriptedSocket(b""),
        ScriptedSocket(_connack(0), _pingresp()),
    ]
    patches = _clean_session_checks()
    with patches[0], patches[1], patches[2], patches[3]:
        with patch.object(mqtt, "create_tls_connection", side_effect=sessions) as tls:
            with patch.object(mqtt, "create_connection") as plain:
                inds = mqtt.probe_mqtt("127.0.0.1", 18883)
    assert tls.call_count >= 1
    plain.assert_not_called()
    assert not any(ind.triggered for ind in inds)
