"""SIP probe tests with mocks."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.sip as sip

_CREDS = (("user_low", "pass_low"), ("user_HIGH_entropy_xx", "pass_HIGH_entropy_yy"))

_OPTS_OK = (
    b"SIP/2.0 200 OK\r\n"
    b"Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bKhpaudit;"
    b"received=198.51.100.7;rport=51515\r\n"
    b"User-Agent: Asterisk PBX\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

_CHALLENGE = (
    b"SIP/2.0 401 Unauthorized\r\n"
    b"WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"frozen-nonce-1\"\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)

_REG_200 = (
    b"SIP/2.0 200 OK\r\n"
    b"Contact: <sip:user@0.0.0.0:5060>\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)


@patch.object(sip, "udp_transact")
def test_sip_probe(mock_udp):
    mock_udp.return_value = (_OPTS_OK, "")
    with (
        patch.object(sip, "entropy_varied_creds", return_value=_CREDS),
        patch.object(sip, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = sip.probe_sip("127.0.0.1", 5060)
    assert {i.id for i in inds} == {
        "sip.user_agent",
        "sip.via_coherence",
        "sip.cseq_echo",
        "sip.arbitrary_auth",
        "sip.state_nonpersist",
    }
    assert len(inds) >= 1


@patch.object(sip, "udp_transact")
def test_sip_arbitrary_auth_fake_digest_200(mock_udp):
    # OPTIONS ok, second OPTIONS ok, two REGISTER with fake digest both 200,
    # then state re-REGISTER pair.
    mock_udp.side_effect = [
        (_OPTS_OK, ""),
        (_OPTS_OK, ""),
        (_REG_200, ""),
        (_REG_200, ""),
        (_REG_200, ""),
        (_REG_200, ""),
    ]
    with (
        patch.object(sip, "entropy_varied_creds", return_value=_CREDS),
        patch.object(sip, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = sip.probe_sip("127.0.0.1", 5060)
    by_id = {i.id: i for i in inds}
    assert by_id["sip.arbitrary_auth"].triggered


@patch.object(sip, "udp_transact")
def test_sip_arbitrary_auth_static_nonce(mock_udp):
    mock_udp.side_effect = [
        (_CHALLENGE, ""),
        (_CHALLENGE, ""),
        (_CHALLENGE, ""),
        (_CHALLENGE, ""),
        (_CHALLENGE, ""),
        (_CHALLENGE, ""),
    ]
    with (
        patch.object(sip, "entropy_varied_creds", return_value=_CREDS),
        patch.object(sip, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = sip.probe_sip("127.0.0.1", 5060)
    by_id = {i.id: i for i in inds}
    assert not by_id["sip.arbitrary_auth"].triggered
    assert "not scored" in by_id["sip.arbitrary_auth"].detail


@patch.object(sip, "udp_transact")
def test_sip_state_canned_identical_register(mock_udp):
    mock_udp.side_effect = [
        (_OPTS_OK, ""),
        (_OPTS_OK, ""),
        (_CHALLENGE, ""),  # auth reg 1
        (_CHALLENGE, ""),  # auth reg 2
        (_REG_200, ""),  # state cseq1
        (_REG_200, ""),  # state cseq2 identical body
    ]
    with (
        patch.object(sip, "entropy_varied_creds", return_value=_CREDS),
        patch.object(sip, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = sip.probe_sip("127.0.0.1", 5060)
    by_id = {i.id: i for i in inds}
    assert by_id["sip.state_nonpersist"].triggered


@patch.object(sip, "udp_transact")
def test_sip_via_coherence_verbatim_echo_gated(mock_udp):
    """Skin echoes the request Via verbatim (no received/rport) → gated hit."""
    verbatim = (
        b"SIP/2.0 200 OK\r\n"
        b"Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bKhpaudit;rport\r\n"
        b"User-Agent: Asterisk PBX\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    mock_udp.return_value = (verbatim, "")
    with (
        patch.object(sip, "entropy_varied_creds", return_value=_CREDS),
        patch.object(sip, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = sip.probe_sip("127.0.0.1", 5060)
    by_id = {i.id: i for i in inds}
    via = by_id["sip.via_coherence"]
    assert via.triggered
    assert via.requires_corroboration is True
    # The branch was echoed; only received/rport are listed as missing.
    assert "received=<source-ip>" in via.detail
    assert "rport=<source-port>" in via.detail
    assert "branch echo" not in via.detail


@patch.object(sip, "udp_transact")
def test_sip_via_coherence_conformant_clean(mock_udp):
    """Branch echo plus received=/rport= additions stay clean."""
    mock_udp.return_value = (_OPTS_OK, "")
    with (
        patch.object(sip, "entropy_varied_creds", return_value=_CREDS),
        patch.object(sip, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = sip.probe_sip("127.0.0.1", 5060)
    by_id = {i.id: i for i in inds}
    assert not by_id["sip.via_coherence"].triggered
    assert not by_id["sip.via_coherence"].skipped


def _opts_ok(cseq: int) -> bytes:
    return (
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bKhpauditdeadbeef;"
        "received=198.51.100.7;rport=51515\r\n"
        f"CSeq: {cseq} OPTIONS\r\n"
        "User-Agent: Asterisk PBX\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode()


@patch.object(sip, "udp_transact")
def test_sip_cseq_echo_wrong_number_gated(mock_udp):
    """Skin echoes a canned 'CSeq: 1 OPTIONS' for every transaction → gated hit."""
    wrong = _opts_ok(1)  # canned echo; requests carry 7 and 9
    mock_udp.side_effect = [
        (wrong, ""),
        (wrong, ""),
        (_REG_200, ""),
        (_REG_200, ""),
        (_REG_200, ""),
        (_REG_200, ""),
    ]
    with (
        patch.object(sip, "entropy_varied_creds", return_value=_CREDS),
        patch.object(sip, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = sip.probe_sip("127.0.0.1", 5060)
    by_id = {i.id: i for i in inds}
    cseq = by_id["sip.cseq_echo"]
    assert cseq.triggered
    assert cseq.requires_corroboration is True
    assert "!= request" in cseq.detail
    # Isolation: Via handling is conformant in these replies.
    assert not by_id["sip.via_coherence"].triggered


@patch.object(sip, "udp_transact")
def test_sip_cseq_echo_conformant_clean(mock_udp):
    """Per-transaction CSeq echoes (7 then 9) stay clean."""
    mock_udp.side_effect = [
        (_opts_ok(7), ""),
        (_opts_ok(9), ""),
        (_REG_200, ""),
        (_REG_200, ""),
        (_REG_200, ""),
        (_REG_200, ""),
    ]
    with (
        patch.object(sip, "entropy_varied_creds", return_value=_CREDS),
        patch.object(sip, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = sip.probe_sip("127.0.0.1", 5060)
    by_id = {i.id: i for i in inds}
    assert not by_id["sip.cseq_echo"].triggered
    assert not by_id["sip.cseq_echo"].skipped
