"""IPP/CUPS non-compliance probe tests."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.ipp as ipp
from honeypot_auditor.config import PORT_PRESET_DOCKER_RESEARCH, PORT_PRESET_IANA, probe_port_map
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.settings import settings

_IPP_IDS = (
    "ipp.arbitrary_auth",
    "ipp.state_nonpersist",
    "ipp.root_framing",
    "ipp.server_header",
    "ipp.path_facade",
    "ipp.method_stub",
    "ipp.printers_stub",
    "ipp.admin_open",
    "ipp.frozen_date",
    "ipp.ipp_framing",
    "ipp.ghost_printer",
    "ipp.request_id",
    "ipp.ipp_clone",
    "ipp.illegal_op",
    "ipp.stock_body",
)

_DATE_A = "Wed, 01 Jan 2020 00:00:00 GMT"
_DATE_B = "Thu, 02 Jan 2020 12:00:00 GMT"
_FIXED_CREDS = (("probeuser10", "probepass79"), ("hpa_highentropyuser0001", "HighEntropyPassw0rd!!!!!!!!"))


def _http_bytes(
    status: int,
    body: bytes | str,
    *,
    headers: dict[str, str] | None = None,
    reason: str = "OK",
) -> bytes:
    payload = body if isinstance(body, bytes) else body.encode()
    hdrs = {"Content-Length": str(len(payload)), "Content-Type": "text/html"}
    if headers:
        hdrs.update(headers)
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        + "\r\n"
    )
    return head.encode() + payload


_CUPS_ROOT = b"<html><title>CUPS 2.4.2</title><body>Home - CUPS</body></html>"
_PRINTERS = b"<html><title>Printers - CUPS 2.4.2</title><body>Printer Queue</body></html>"
_ADMIN = b"<html><title>Admin - CUPS</title><body>Administration</body></html>"
_IPP_OK = b"\x01\x01\x00\x00\x00\x00\x00\x01\x03"  # version 1.1, status successful, end


def _ipp_reply(status: int, request_id: int) -> bytes:
    return (
        b"\x01\x01"
        + status.to_bytes(2, "big")
        + (request_id & 0xFFFFFFFF).to_bytes(4, "big")
        + b"\x03"
    )


def _conformant_tcp(host, port, payload=b"", **kwargs):
    del host, port, kwargs
    text = payload.decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0]
    base_hdrs = {"Server": "CUPS/2.4.2", "Date": _DATE_A}
    if first.startswith("GET / "):
        return _http_bytes(200, _CUPS_ROOT, headers=base_hdrs), ""
    if first.startswith("GET /_hpa_nonexistent_"):
        return (
            _http_bytes(404, b"Not Found", headers={**base_hdrs, "Date": _DATE_B}),
            "",
        )
    if first.startswith("DELETE / "):
        return (
            _http_bytes(405, b"Method Not Allowed", headers={**base_hdrs, "Date": _DATE_B}),
            "",
        )
    if first.startswith("GET /printers"):
        return _http_bytes(200, _PRINTERS, headers={**base_hdrs, "Date": _DATE_B}), ""
    if first.startswith("GET /admin"):
        # Reject both anon and bogus Basic (real CUPS challenges unknown creds).
        return (
            _http_bytes(
                401,
                b"Unauthorized",
                headers={
                    **base_hdrs,
                    "Date": _DATE_B,
                    "WWW-Authenticate": 'Basic realm="CUPS"',
                },
                reason="Unauthorized",
            ),
            "",
        )
    if first.startswith("POST /ipp/print") or first.startswith("POST / "):
        _, _, body = payload.partition(b"\r\n\r\n")
        rid = int.from_bytes(body[4:8], "big") if len(body) >= 8 else 1
        op = int.from_bytes(body[2:4], "big") if len(body) >= 4 else 0
        if op == 0x7FFF:
            # Illegal operation → operation-not-supported
            ipp_body = _ipp_reply(0x0501, rid)
        elif op == 0x000B:
            # Get-Printer-Attributes for unknown printer → not-found
            ipp_body = _ipp_reply(0x0406, rid)
        else:
            ipp_body = _ipp_reply(0x0400, rid)
        return (
            _http_bytes(
                200,
                ipp_body,
                headers={
                    "Server": "CUPS/2.4.2",
                    "Content-Type": "application/ipp",
                    "Date": _DATE_B,
                },
            ),
            "",
        )
    return b"", "unexpected"


def test_ipp_helper_shapes():
    assert ipp._is_cups_root(200, {"server": "CUPS/2.4.2"}, b"x")
    assert ipp._is_cups_root(200, {}, b"<html>Home - CUPS</html>")
    assert not ipp._is_cups_root(200, {"server": "nginx"}, b"welcome to my printer shop")
    assert not ipp._is_cups_root(200, {}, b"buy a printer today")
    assert ipp._is_ipp_content_type({"content-type": "application/ipp"})
    assert ipp._is_ipp_binary(_IPP_OK)
    parsed = ipp._parse_ipp_header(_IPP_OK)
    assert parsed is not None
    assert parsed.status == 0x0000
    assert parsed.request_id == 1
    req = ipp._build_get_printer_attributes(7, "ipp://127.0.0.1:631/printers/x")
    assert req[:2] == b"\x01\x01"
    assert req[2:4] == b"\x00\x0b"
    illegal = ipp._build_illegal_operation(9)
    assert illegal[2:4] == b"\x7f\xff"
    assert ipp._looks_like_tls(b"\x16\x03\x01\x00\x01")
    assert not ipp._looks_like_tls(b"HTTP/1.1 200 OK\r\n")


def test_ipp_conformant_cups_is_clean():
    with (
        patch.object(ipp, "tcp_transact", side_effect=_conformant_tcp),
        patch.object(ipp, "entropy_varied_creds", return_value=_FIXED_CREDS),
        patch.object(ipp, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id for i in inds} == set(_IPP_IDS)
    assert not any(i.triggered for i in inds)
    assert not any(i.skipped for i in inds)


def test_ipp_root_framing_on_garbage():
    with patch.object(
        ipp,
        "tcp_transact",
        return_value=(_http_bytes(200, b"hello nginx", headers={"Server": "nginx"}), ""),
    ):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    by_id = {i.id: i for i in inds}
    assert by_id["ipp.root_framing"].triggered
    assert all(i.skipped or i.id == "ipp.root_framing" for i in inds)


def test_ipp_transport_error_skips_suite():
    with patch.object(ipp, "tcp_transact", return_value=(b"", "timed out")):
        with patch.object(ipp, "create_tls_connection", side_effect=OSError("tls fail")):
            inds = ipp.probe_ipp("127.0.0.1", 631)
    assert len(inds) == len(_IPP_IDS)
    assert all(i.skipped for i in inds)
    assert not any(i.triggered for i in inds)


def test_ipp_safe_mode_framing_only():
    old = settings.safe_mode
    settings.safe_mode = True
    try:
        with patch.object(ipp, "tcp_transact", side_effect=_conformant_tcp):
            inds = ipp.probe_ipp("127.0.0.1", 631)
        by_id = {i.id: i for i in inds}
        assert {i.id for i in inds} == set(_IPP_IDS)
        assert not by_id["ipp.root_framing"].triggered
        assert not by_id["ipp.root_framing"].skipped
        assert by_id["ipp.arbitrary_auth"].skipped
        assert by_id["ipp.state_nonpersist"].skipped
        assert all(i.skipped for i in inds if i.id != "ipp.root_framing")
    finally:
        settings.safe_mode = old


def test_ipp_path_facade():
    root = _http_bytes(200, _CUPS_ROOT, headers={"Server": "CUPS/2.4.2", "Date": _DATE_A})

    def _facade(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /_hpa_nonexistent_"):
            return root, ""
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_facade):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    by_id = {i.id: i for i in inds}
    assert by_id["ipp.path_facade"].triggered
    assert not by_id["ipp.root_framing"].triggered


def test_ipp_truncated_body_not_path_facade():
    """Short/truncated equal bodies must not fire path_facade."""
    short = b"<html>CUPS"

    def _trunc(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        hdrs = {"Server": "CUPS/2.4.2", "Date": _DATE_A, "Content-Length": "5000"}
        if first.startswith("GET / "):
            # Claim large body but deliver truncated payload
            head = (
                "HTTP/1.1 200 OK\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
                + "\r\n"
            ).encode() + short
            return head, ""
        if first.startswith("GET /_hpa_nonexistent_"):
            head = (
                "HTTP/1.1 200 OK\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
                + "\r\n"
            ).encode() + short
            return head, ""
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_trunc):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert not {i.id: i for i in inds}["ipp.path_facade"].triggered


def test_ipp_method_stub():
    def _stub(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("DELETE / "):
            return (
                _http_bytes(200, _CUPS_ROOT, headers={"Server": "CUPS/2.4.2", "Date": _DATE_B}),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_stub):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.method_stub"].triggered


def test_ipp_method_stub_requires_body_echo():
    """DELETE 200 with a different body is not a method stub."""

    def _stub(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("DELETE / "):
            return (
                _http_bytes(
                    200,
                    b"<html>method not implemented</html>",
                    headers={"Server": "CUPS/2.4.2", "Date": _DATE_B},
                ),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_stub):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert not {i.id: i for i in inds}["ipp.method_stub"].triggered


def test_ipp_empty_printers_not_stub():
    def _empty(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /printers"):
            return (
                _http_bytes(200, b"", headers={"Server": "CUPS/2.4.2", "Date": _DATE_B}),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_empty):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert not {i.id: i for i in inds}["ipp.printers_stub"].triggered


def test_ipp_server_header_decisive():
    def _stock(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / "):
            return (
                _http_bytes(
                    200,
                    _CUPS_ROOT,
                    headers={"Server": "CUPS-honeypot/1.0", "Date": _DATE_A},
                ),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_stock):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    by_id = {i.id: i for i in inds}
    assert by_id["ipp.server_header"].triggered
    assert not by_id["ipp.server_header"].requires_corroboration


def test_ipp_server_header_generic_gated():
    def _stock(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / "):
            return (
                _http_bytes(
                    200,
                    _CUPS_ROOT,
                    headers={"Server": "CUPS/1.4.2", "Date": _DATE_A},
                ),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_stock):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    by_id = {i.id: i for i in inds}
    assert by_id["ipp.server_header"].triggered
    assert by_id["ipp.server_header"].requires_corroboration


def test_ipp_ipp_framing_html_echo():
    def _echo(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("POST "):
            return (
                _http_bytes(200, _CUPS_ROOT, headers={"Server": "CUPS/2.4.2", "Date": _DATE_B}),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_echo):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.ipp_framing"].triggered


def test_ipp_ipp_clone():
    canned = b"\x01\x01\x00\x00\x00\x00\x00\x00\x03"

    def _clone(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("POST "):
            return (
                _http_bytes(
                    200,
                    canned,
                    headers={
                        "Server": "CUPS/2.4.2",
                        "Content-Type": "application/ipp",
                        "Date": _DATE_B,
                    },
                ),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_clone):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.ipp_clone"].triggered


def test_ipp_ghost_printer():
    def _ghost(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("POST "):
            _, _, body = payload.partition(b"\r\n\r\n")
            rid = int.from_bytes(body[4:8], "big") if len(body) >= 8 else 1
            op = int.from_bytes(body[2:4], "big") if len(body) >= 4 else 0
            if op == 0x7FFF:
                ipp_body = _ipp_reply(0x0501, rid)
            else:
                # successful-ok for nonexistent printer
                ipp_body = _ipp_reply(0x0000, rid)
            return (
                _http_bytes(
                    200,
                    ipp_body,
                    headers={
                        "Server": "CUPS/2.4.2",
                        "Content-Type": "application/ipp",
                        "Date": _DATE_B,
                    },
                ),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_ghost):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.ghost_printer"].triggered


def test_ipp_request_id_mismatch():
    def _bad_rid(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("POST "):
            _, _, body = payload.partition(b"\r\n\r\n")
            op = int.from_bytes(body[2:4], "big") if len(body) >= 4 else 0
            # Always echo frozen request-id 1
            if op == 0x7FFF:
                ipp_body = _ipp_reply(0x0501, 1)
            else:
                ipp_body = _ipp_reply(0x0406, 1)
            return (
                _http_bytes(
                    200,
                    ipp_body,
                    headers={
                        "Server": "CUPS/2.4.2",
                        "Content-Type": "application/ipp",
                        "Date": _DATE_B,
                    },
                ),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_bad_rid):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.request_id"].triggered


def test_ipp_admin_open():
    def _open(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET /admin"):
            return (
                _http_bytes(200, _ADMIN, headers={"Server": "CUPS/2.4.2", "Date": _DATE_B}),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_open):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.admin_open"].triggered


def test_ipp_frozen_date():
    frozen = "Wed, 01 Jan 2020 00:00:00 GMT"

    def _frozen(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        # Force same Date on every response while staying otherwise conformant.
        raw, err = _conformant_tcp("127.0.0.1", 631, payload)
        if err or not raw:
            return raw, err
        # Rewrite Date header
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        out_lines = [lines[0]]
        saw_date = False
        for line in lines[1:]:
            if line.lower().startswith(b"date:"):
                out_lines.append(f"Date: {frozen}".encode())
                saw_date = True
            else:
                out_lines.append(line)
        if not saw_date:
            out_lines.append(f"Date: {frozen}".encode())
        return b"\r\n".join(out_lines) + b"\r\n\r\n" + body, ""

    with patch.object(ipp, "tcp_transact", side_effect=_frozen):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.frozen_date"].triggered


def test_ipp_illegal_op_success():
    def _bad(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("POST "):
            _, _, body = payload.partition(b"\r\n\r\n")
            rid = int.from_bytes(body[4:8], "big") if len(body) >= 8 else 1
            op = int.from_bytes(body[2:4], "big") if len(body) >= 4 else 0
            if op == 0x7FFF:
                ipp_body = _ipp_reply(0x0000, rid)  # success on illegal op
            else:
                ipp_body = _ipp_reply(0x0406, rid)
            return (
                _http_bytes(
                    200,
                    ipp_body,
                    headers={
                        "Server": "CUPS/2.4.2",
                        "Content-Type": "application/ipp",
                        "Date": _DATE_B,
                    },
                ),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_bad):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.illegal_op"].triggered


def test_ipp_tls_fallback_on_record_layer():
    calls: list[bool] = []

    def _cleartext(host, port, payload=b"", **kwargs):
        del host, port, payload, kwargs
        calls.append(False)
        return b"\x15\x03\x03\x00\x02\x02\x28", ""

    class _TlsSock:
        def __init__(self):
            self._sent = b""

        def sendall(self, data):
            self._sent = data

        def recv(self, _n):
            text = self._sent.decode("latin-1", "replace")
            first = text.split("\r\n", 1)[0]
            if first.startswith("GET / "):
                return _http_bytes(
                    200, _CUPS_ROOT, headers={"Server": "CUPS/2.4.2", "Date": _DATE_A}
                )
            # Minimal responses so suite does not explode; mark as TLS path used
            if first.startswith("GET /_hpa"):
                return _http_bytes(404, b"nf", headers={"Server": "CUPS/2.4.2", "Date": _DATE_B})
            if first.startswith("DELETE"):
                return _http_bytes(405, b"no", headers={"Server": "CUPS/2.4.2", "Date": _DATE_B})
            if first.startswith("GET /printers"):
                return _http_bytes(200, _PRINTERS, headers={"Server": "CUPS/2.4.2", "Date": _DATE_B})
            if first.startswith("GET /admin"):
                return _http_bytes(
                    401,
                    b"no",
                    headers={
                        "Server": "CUPS/2.4.2",
                        "Date": _DATE_B,
                        "WWW-Authenticate": 'Basic realm="CUPS"',
                    },
                    reason="Unauthorized",
                )
            if first.startswith("POST"):
                _, _, body = self._sent.partition(b"\r\n\r\n")
                rid = int.from_bytes(body[4:8], "big") if len(body) >= 8 else 1
                op = int.from_bytes(body[2:4], "big") if len(body) >= 4 else 0
                st = 0x0501 if op == 0x7FFF else 0x0406
                return _http_bytes(
                    200,
                    _ipp_reply(st, rid),
                    headers={
                        "Server": "CUPS/2.4.2",
                        "Content-Type": "application/ipp",
                        "Date": _DATE_B,
                    },
                )
            return b""

        def settimeout(self, _t):
            return None

        def close(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def _tls_conn(host, port, timeout):
        del host, port, timeout
        calls.append(True)
        return _TlsSock()

    with patch.object(ipp, "tcp_transact", side_effect=_cleartext):
        with patch.object(ipp, "create_tls_connection", side_effect=_tls_conn):
            inds = ipp.probe_ipp("127.0.0.1", 631)
    assert True in calls  # TLS path used
    assert not {i.id: i for i in inds}["ipp.root_framing"].triggered


def test_ipp_stock_body():
    body = b"<html>This is not a real printer honeypot UI</html>"

    def _body(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / "):
            return (
                _http_bytes(200, body, headers={"Server": "CUPS/2.4.2", "Date": _DATE_A}),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_body):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.stock_body"].triggered


def test_ipp_registry_and_ports():
    assert "ipp" in PROBE_BY_PROTOCOL
    assert PROBE_BY_PROTOCOL["ipp"] is ipp.probe_ipp
    assert PORT_PRESET_IANA["ipp"] == 631
    assert PORT_PRESET_DOCKER_RESEARCH["ipp"] == 1631
    both = probe_port_map("both")
    assert 631 in both["ipp"]
    assert 1631 in both["ipp"]


def test_ipp_arbitrary_auth_dual_basic():
    def _auth(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        has_auth = "authorization:" in text.lower()
        if first.startswith("GET /admin") and has_auth:
            return (
                _http_bytes(200, _ADMIN, headers={"Server": "CUPS/2.4.2", "Date": _DATE_B}),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with (
        patch.object(ipp, "tcp_transact", side_effect=_auth),
        patch.object(ipp, "entropy_varied_creds", return_value=_FIXED_CREDS),
        patch.object(ipp, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    auth = {i.id: i for i in inds}["ipp.arbitrary_auth"]
    assert auth.triggered
    assert auth.fidelity == "decisive"
    assert auth.category == "arbitrary_auth"


def test_ipp_state_nonpersist_illegal_op():
    def _bad(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("POST "):
            _, _, body = payload.partition(b"\r\n\r\n")
            rid = int.from_bytes(body[4:8], "big") if len(body) >= 8 else 1
            op = int.from_bytes(body[2:4], "big") if len(body) >= 4 else 0
            if op == 0x7FFF:
                ipp_body = _ipp_reply(0x0000, rid)
            else:
                ipp_body = _ipp_reply(0x0406, rid)
            return (
                _http_bytes(
                    200,
                    ipp_body,
                    headers={
                        "Server": "CUPS/2.4.2",
                        "Content-Type": "application/ipp",
                        "Date": _DATE_B,
                    },
                ),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with (
        patch.object(ipp, "tcp_transact", side_effect=_bad),
        patch.object(ipp, "entropy_varied_creds", return_value=_FIXED_CREDS),
        patch.object(ipp, "jittered_reconnect_pause", return_value=0.0),
    ):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    by_id = {i.id: i for i in inds}
    assert by_id["ipp.illegal_op"].triggered
    assert by_id["ipp.state_nonpersist"].triggered
    assert by_id["ipp.state_nonpersist"].category == "state_nonpersist"
