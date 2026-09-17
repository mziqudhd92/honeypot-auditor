"""IPP/CUPS non-compliance probe tests."""

from __future__ import annotations

from unittest.mock import patch

import honeypot_auditor.probes.ipp as ipp
from honeypot_auditor.config import PORT_PRESET_DOCKER_RESEARCH, PORT_PRESET_IANA, probe_port_map
from honeypot_auditor.probes import PROBE_BY_PROTOCOL
from honeypot_auditor.settings import settings

_IPP_IDS = (
    "ipp.root_framing",
    "ipp.server_header",
    "ipp.path_facade",
    "ipp.method_stub",
    "ipp.printers_stub",
    "ipp.ipp_framing",
    "ipp.ipp_clone",
    "ipp.stock_body",
)


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
_IPP_OK = b"\x01\x01\x00\x00\x00\x00\x00\x01\x03"  # version 1.1, status successful, end


def _conformant_tcp(host, port, payload=b"", **kwargs):
    del host, port, kwargs
    text = payload.decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0]
    if first.startswith("GET / "):
        return (
            _http_bytes(200, _CUPS_ROOT, headers={"Server": "CUPS/2.4.2"}),
            "",
        )
    if first.startswith("GET /_hpa_nonexistent_"):
        return _http_bytes(404, b"Not Found", headers={"Server": "CUPS/2.4.2"}), ""
    if first.startswith("DELETE / "):
        return _http_bytes(405, b"Method Not Allowed", headers={"Server": "CUPS/2.4.2"}), ""
    if first.startswith("GET /printers"):
        return _http_bytes(200, _PRINTERS, headers={"Server": "CUPS/2.4.2"}), ""
    if first.startswith("POST /ipp/print") or first.startswith("POST / "):
        # Echo distinct request-ids so ipp_clone stays clean.
        _, _, body = payload.partition(b"\r\n\r\n")
        rid = body[4:8] if len(body) >= 8 else b"\x00\x00\x00\x01"
        ipp_body = b"\x01\x01\x00\x00" + rid + b"\x03"
        return (
            _http_bytes(
                200,
                ipp_body,
                headers={"Server": "CUPS/2.4.2", "Content-Type": "application/ipp"},
            ),
            "",
        )
    return b"", "unexpected"


def test_ipp_helper_shapes():
    assert ipp._is_cups_root(200, {"server": "CUPS/2.4.2"}, b"x")
    assert ipp._is_cups_root(200, {}, b"<html>CUPS printers</html>")
    assert not ipp._is_cups_root(200, {"server": "nginx"}, b"welcome")
    assert ipp._is_ipp_content_type({"content-type": "application/ipp"})
    assert ipp._is_ipp_binary(_IPP_OK)
    req = ipp._build_get_printer_attributes(7, "ipp://127.0.0.1:631/printers/x")
    assert req[:2] == b"\x01\x01"
    assert req[2:4] == b"\x00\x0b"


def test_ipp_conformant_cups_is_clean():
    with patch.object(ipp, "tcp_transact", side_effect=_conformant_tcp):
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
        assert not by_id["ipp.root_framing"].triggered
        assert not by_id["ipp.root_framing"].skipped
        assert all(i.skipped for i in inds if i.id != "ipp.root_framing")
    finally:
        settings.safe_mode = old


def test_ipp_path_facade():
    root = _http_bytes(200, _CUPS_ROOT, headers={"Server": "CUPS/2.4.2"})

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


def test_ipp_method_stub():
    def _stub(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("DELETE / "):
            return _http_bytes(200, _CUPS_ROOT, headers={"Server": "CUPS/2.4.2"}), ""
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_stub):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.method_stub"].triggered


def test_ipp_server_header_decisive():
    def _stock(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / "):
            return (
                _http_bytes(200, _CUPS_ROOT, headers={"Server": "CUPS-honeypot/1.0"}),
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
                _http_bytes(200, _CUPS_ROOT, headers={"Server": "CUPS/1.4.2"}),
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
            return _http_bytes(200, _CUPS_ROOT, headers={"Server": "CUPS/2.4.2"}), ""
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
                    headers={"Server": "CUPS/2.4.2", "Content-Type": "application/ipp"},
                ),
                "",
            )
        return _conformant_tcp("127.0.0.1", 631, payload)

    with patch.object(ipp, "tcp_transact", side_effect=_clone):
        inds = ipp.probe_ipp("127.0.0.1", 631)
    assert {i.id: i for i in inds}["ipp.ipp_clone"].triggered


def test_ipp_stock_body():
    body = b"<html>This is not a real printer honeypot UI</html>"

    def _body(host, port, payload=b"", **kwargs):
        del host, port, kwargs
        text = payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        if first.startswith("GET / "):
            return _http_bytes(200, body, headers={"Server": "CUPS/2.4.2"}), ""
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
