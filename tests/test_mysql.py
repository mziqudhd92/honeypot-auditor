"""MySQL probe tests with mocks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import honeypot_auditor.probes.mysql as mysql


def _greeting(version: str) -> bytes:
    payload = (
        b"\x0a"
        + version.encode("ascii")
        + b"\x00"
        + b"\x01\x00\x00\x00"
        + b"\xff\xf7\x08\x02\x00\x0f\x80"
        + b"mysql_native_password\x00"
    )
    return bytes([len(payload), 0, 0, 0]) + payload


def _denied() -> bytes:
    payload = b"\xff\x29\x04#28000Access denied for user 'x'@'1.2.3.4'"
    return bytes([len(payload), 0, 0, 2]) + payload


def _pkt_order() -> bytes:
    payload = b"\xff\x84\x04#08S01Got packets out of order"
    return bytes([len(payload), 0, 0, 2]) + payload


@patch.object(mysql, "tcp_roundtrips")
@patch.object(
    mysql, "_mysql_ssl_drop_probe", return_value=(True, "CLIENT_SSL closed", "closed", False)
)
def test_mysql_eol_greeting_and_stock_handshake(mock_ssl, mock_rt):
    mock_rt.side_effect = [
        ([_greeting("5.5.43-0ubuntu0.14.04.1"), _denied(), b""], ""),
        ([_greeting("5.5.43-0ubuntu0.14.04.1"), _pkt_order(), b""], ""),
    ]
    inds = mysql.probe_mysql("127.0.0.1", 3306)
    by_id = {i.id: i for i in inds}
    assert by_id["mysql.signature"].triggered
    assert by_id["mysql.handshake"].triggered
    assert by_id["mysql.persist"].triggered
    assert by_id["mysql.seq_order"].triggered
    assert by_id["mysql.ssl_drop"].triggered


@patch.object(mysql, "tcp_roundtrips")
@patch.object(
    mysql, "_mysql_ssl_drop_probe", return_value=(False, "session stayed open", "open", False)
)
def test_mysql_modern_greeting_keeps_session(mock_ssl, mock_rt):
    greeting = _greeting("8.0.36-0ubuntu0.22.04.1").replace(
        b"\xff\xf7\x08\x02\x00\x0f\x80", b"\xff\xf7\x00"
    )
    mock_rt.side_effect = [
        ([greeting, _denied(), b"\xff\x29\x04"], ""),
        ([greeting, _denied(), b""], ""),
    ]
    inds = mysql.probe_mysql("127.0.0.1", 3306)
    by_id = {i.id: i for i in inds}
    assert not by_id["mysql.signature"].triggered
    assert not by_id["mysql.handshake"].triggered
    assert not by_id["mysql.persist"].triggered
    assert not by_id["mysql.seq_order"].triggered
    assert not by_id["mysql.ssl_drop"].triggered


@patch.object(mysql, "tcp_roundtrips")
def test_mysql_closed_port(mock_rt):
    mock_rt.return_value = ([], "Connection refused")
    inds = mysql.probe_mysql("127.0.0.1", 3306)
    assert len(inds) == 5
    assert all(i.skipped for i in inds)


def test_mysql_expected_seq_fsm_is_honeypot_tell():
    from honeypot_auditor.config.signatures.mysql import match_mysql_pkt_order

    raw = bytes.fromhex(
        "23000002ff1304313833353a2045787065637465642073657128312920676f7420736571283029"  # pragma: allowlist secret
    )
    hit = match_mysql_pkt_order(raw)
    assert hit is not None
    assert "Expected seq" in hit or "emulator seq FSM" in hit


def test_mysql_ssl_request_sets_client_ssl_flag():
    pkt = mysql._mysql_ssl_request()
    assert len(pkt) >= 5
    # payload length + seq + CLIENT_SSL bit set in capability dword
    assert pkt[3] == 1
    caps = int.from_bytes(pkt[4:8], "little")
    assert caps & mysql._CLIENT_SSL


@patch("socket.create_connection")
def test_mysql_ssl_drop_probe_silent_close(mock_conn):
    greeting = _greeting("5.5.43-0ubuntu0.14.04.1")
    sock = MagicMock()
    mock_conn.return_value.__enter__.return_value = sock
    # greeting then EOF to end read loop; empty follow after CLIENT_SSL
    sock.recv.side_effect = [greeting, b"", b""]
    sock.sendall.side_effect = [None, OSError("Broken pipe")]
    triggered, detail, evidence, skipped = mysql._mysql_ssl_drop_probe("127.0.0.1", 3306)
    assert triggered and not skipped
    assert "closed" in detail.lower() or evidence == "closed"


@patch("socket.create_connection")
def test_mysql_ssl_drop_probe_err_packet(mock_conn):
    greeting = _greeting("8.0.36")
    sock = MagicMock()
    mock_conn.return_value.__enter__.return_value = sock
    sock.recv.side_effect = [greeting, b"", _denied()]
    sock.sendall.return_value = None
    triggered, detail, _evidence, skipped = mysql._mysql_ssl_drop_probe("127.0.0.1", 3306)
    assert not triggered and not skipped
    assert "ERR" in detail


@patch("socket.create_connection")
def test_mysql_ssl_drop_probe_stays_open(mock_conn):
    greeting = _greeting("8.0.36")
    sock = MagicMock()
    mock_conn.return_value.__enter__.return_value = sock
    sock.recv.side_effect = [greeting, b"", b"\x00"]
    sock.sendall.return_value = None
    triggered, detail, evidence, skipped = mysql._mysql_ssl_drop_probe("127.0.0.1", 3306)
    assert not triggered and not skipped
    assert "stayed open" in detail.lower() or evidence


@patch("socket.create_connection")
def test_mysql_ssl_drop_probe_connection_error(mock_conn):
    mock_conn.side_effect = OSError("Connection refused")
    triggered, detail, _evidence, skipped = mysql._mysql_ssl_drop_probe("127.0.0.1", 3306)
    assert skipped and not triggered
    assert "refused" in detail.lower() or "closed" in detail.lower()
