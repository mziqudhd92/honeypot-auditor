"""CLI behavior tests."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from honeypot_auditor.cli import build_parser, main, run_audit
from honeypot_auditor.models import Indicator


def _clean_indicator(**kwargs) -> Indicator:
    defaults = {
        "id": "test.ind",
        "title": "test",
        "category": "static_signature",
        "triggered": False,
    }
    defaults.update(kwargs)
    return Indicator(**defaults)


def test_parser_version():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_public_ip_refused_without_confirm():
    code = main(["--target", "8.8.8.8", "--skip-nmap"])
    assert code == 2


@patch("honeypot_auditor.cli.run_audit")
def test_public_ip_allowed_with_confirm(mock_run):
    mock_run.return_value = 0
    code = main(
        [
            "--target",
            "8.8.8.8",
            "--confirm-authorized",
            "--skip-nmap",
        ]
    )
    assert code == 0
    mock_run.assert_called_once()


def test_parser_deep_flag():
    args = build_parser().parse_args(["--target", "127.0.0.1", "--deep"])
    assert args.deep is True


def test_invalid_timeout():
    code = main(["--target", "127.0.0.1", "--timeout", "0", "--skip-nmap"])
    assert code == 2


def test_invalid_target():
    code = main(["--target", "", "--skip-nmap"])
    assert code == 2


@patch("honeypot_auditor.cli.export")
@patch("honeypot_auditor.cli.render")
@patch("honeypot_auditor.cli.run_deep_probes", return_value=[])
@patch("honeypot_auditor.cli.probe_sip", return_value=[])
@patch("honeypot_auditor.cli.probe_vnc", return_value=[])
@patch("honeypot_auditor.cli.probe_smtp", return_value=[])
@patch("honeypot_auditor.cli.probe_redis", return_value=[])
@patch("honeypot_auditor.cli.probe_http", return_value=[])
@patch("honeypot_auditor.cli.probe_ftp", return_value=[])
@patch("honeypot_auditor.cli.probe_smb", return_value=[])
@patch("honeypot_auditor.cli.probe_telnet", return_value=[])
@patch("honeypot_auditor.cli.probe_ssh", return_value=[_clean_indicator(id="ssh.banner", triggered=True)])
@patch("honeypot_auditor.cli.nmap_scan", return_value=[])
@patch("honeypot_auditor.cli.shodan_lookup", return_value=[])
def test_run_audit_local_smoke(
    mock_shodan,
    mock_nmap,
    mock_ssh,
    mock_telnet,
    mock_smb,
    mock_ftp,
    mock_http,
    mock_redis,
    mock_smtp,
    mock_vnc,
    mock_sip,
    mock_deep,
    mock_render,
    mock_export,
    tmp_path,
):
    out = tmp_path / "audit.json"
    args = build_parser().parse_args(
        ["--target", "127.0.0.1", "--skip-nmap", "--output", str(out), "--deep"]
    )
    code = asyncio.run(run_audit(args))
    assert code == 0
    mock_export.assert_called_once()
    mock_render.assert_called_once()


@patch("honeypot_auditor.cli.asyncio.to_thread", side_effect=RuntimeError("probe boom"))
@patch("honeypot_auditor.cli.export")
@patch("honeypot_auditor.cli.render")
@patch("honeypot_auditor.cli.run_deep_probes", return_value=[])
@patch("honeypot_auditor.cli.probe_sip", return_value=[])
@patch("honeypot_auditor.cli.probe_vnc", return_value=[])
@patch("honeypot_auditor.cli.probe_smtp", return_value=[])
@patch("honeypot_auditor.cli.probe_redis", return_value=[])
@patch("honeypot_auditor.cli.probe_http", return_value=[])
@patch("honeypot_auditor.cli.probe_ftp", return_value=[])
@patch("honeypot_auditor.cli.probe_smb", return_value=[])
@patch("honeypot_auditor.cli.probe_telnet", return_value=[])
@patch("honeypot_auditor.cli.probe_ssh", return_value=[])
@patch("honeypot_auditor.cli.nmap_scan", return_value=[])
@patch("honeypot_auditor.cli.shodan_lookup", return_value=[])
def test_run_audit_probe_error_indicator(
    mock_shodan,
    mock_nmap,
    mock_ssh,
    mock_telnet,
    mock_smb,
    mock_ftp,
    mock_http,
    mock_redis,
    mock_smtp,
    mock_vnc,
    mock_sip,
    mock_deep,
    mock_render,
    mock_export,
    mock_to_thread,
    tmp_path,
):
    args = build_parser().parse_args(
        ["--target", "127.0.0.1", "--skip-nmap", "--output", str(tmp_path / "audit.json")]
    )
    code = asyncio.run(run_audit(args))
    assert code == 0
