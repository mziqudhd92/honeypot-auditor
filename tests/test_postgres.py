"""Postgres probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.postgres as postgres


def _auth_cleartext() -> bytes:
    return b"R\x00\x00\x00\x08\x00\x00\x00\x03"


def _auth_fail_blob(user: str = "user_a10") -> bytes:
    message = f'Mpassword authentication failed for user "{user}"\x00'.encode()
    length = (4 + 21 + len(message) + 27).to_bytes(4, byteorder="big")
    return (
        b"E"
        + length
        + b"SFATAL\x00VFATAL\x00C28P01\x00"
        + message
        + b"Fauth.c\x00L326\x00Rauth_failed\x00\x00"
    )


@patch.object(postgres, "tcp_roundtrips")
def test_postgres_cleartext_and_auth_c_blob(mock_rt):
    mock_rt.return_value = ([b"N", _auth_cleartext(), _auth_fail_blob()], "")
    inds = postgres.probe_postgres("127.0.0.1", 5432)
    by_id = {i.id: i for i in inds}
    assert by_id["postgres.cleartext"].triggered
    assert by_id["postgres.auth_blob"].triggered


@patch.object(postgres, "tcp_roundtrips")
def test_postgres_closed_port(mock_rt):
    mock_rt.return_value = ([], "Connection refused")
    inds = postgres.probe_postgres("127.0.0.1", 5432)
    assert len(inds) == 2
    assert all(i.skipped for i in inds)
