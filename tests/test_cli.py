"""CLI behavior tests."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from honeypot_auditor.cli import build_parser, main, run_audit
from honeypot_auditor.models import Indicator
from honeypot_auditor.probes import PROBE_BY_PROTOCOL


def _clean_indicator(**kwargs) -> Indicator:
    defaults = {
        "id": "test.ind",
        "title": "test",
        "category": "static_signature",
        "triggered": False,
    }
    defaults.update(kwargs)
    return Indicator(**defaults)


def _stub_cli_probes(**overrides):
    stubs = {name: MagicMock(return_value=[]) for name in PROBE_BY_PROTOCOL}
    stubs.update(overrides)
    return patch.dict("honeypot_auditor.cli.PROBE_BY_PROTOCOL", stubs, clear=True)


def test_parser_version():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_help_flags(capsys):
    for flag in ("-h", "--help", "/help"):
        code = main(["--target", "127.0.0.1", flag])
        assert code == 0
        out = capsys.readouterr().out
        assert "--target" in out
        assert "H-AUDITOR" in out or "honeypot-auditor" in out
        assert "--port" in out
        assert "--verbose" in out


def test_help_text_is_windows_console_safe():
    build_parser().format_help().encode("cp1252")


def test_public_ip_refused_without_confirm():
    code = main(["--target", "8.8.8.8"])
    assert code == 2


@patch("honeypot_auditor.cli.run_audit")
def test_public_ip_allowed_with_confirm(mock_run):
    mock_run.return_value = 0
    code = main(
        [
            "--target",
            "8.8.8.8",
            "--confirm-authorized",
        ]
    )
    assert code == 0
    mock_run.assert_called_once()


def test_parser_verbose_flag():
    parser = build_parser()
    assert parser.parse_args(["--target", "127.0.0.1", "-v"]).verbose is True
    assert parser.parse_args(["--target", "127.0.0.1", "--verbose"]).verbose is True
    assert parser.parse_args(["--target", "127.0.0.1"]).verbose is False


def test_parser_deep_flag():
    args = build_parser().parse_args(["--target", "127.0.0.1", "--deep"])
    assert args.deep is True


def test_parser_port_flags():
    args = build_parser().parse_args(["--target", "127.0.0.1", "-p", "22", "--port", "2223,8080"])
    assert args.preset == "both"
    assert args.extra_ports == ["22", "2223,8080"]


def test_parser_attached_short_port():
    args = build_parser().parse_args(["--target", "127.0.0.1", "-p22"])
    assert args.extra_ports == ["22"]


def test_parser_with_nmap_flag():
    parser = build_parser()
    assert parser.parse_args(["--target", "127.0.0.1", "-n"]).with_nmap is True
    assert parser.parse_args(["--target", "127.0.0.1", "--with-nmap"]).with_nmap is True
    assert parser.parse_args(["--target", "127.0.0.1"]).with_nmap is False


def test_invalid_extra_port():
    code = main(["--target", "127.0.0.1", "-p", "0"])
    assert code == 2


def test_invalid_timeout():
    code = main(["--target", "127.0.0.1", "--timeout", "0"])
    assert code == 2


def test_invalid_target():
    code = main(["--target", ""])
    assert code == 2


@patch("honeypot_auditor.cli.export")
@patch("honeypot_auditor.cli.render")
@patch("honeypot_auditor.cli.run_deep_probes", return_value=[])
@patch("honeypot_auditor.cli.nmap_scan", return_value=[])
@patch("honeypot_auditor.cli.shodan_lookup", return_value=[])
def test_run_audit_local_smoke(
    mock_shodan,
    mock_nmap,
    mock_deep,
    mock_render,
    mock_export,
    tmp_path,
):
    ssh = MagicMock(return_value=[_clean_indicator(id="ssh.banner", triggered=True)])
    out = tmp_path / "audit.json"
    args = build_parser().parse_args(["--target", "127.0.0.1", "--output", str(out), "--deep"])
    with _stub_cli_probes(ssh=ssh):
        code = asyncio.run(run_audit(args))
    assert code == 0
    mock_nmap.assert_not_called()
    mock_export.assert_called_once()
    mock_render.assert_called_once()
    assert mock_render.call_args.kwargs.get("verbose") is False
    ssh_ports = sorted(call.args[1] for call in ssh.call_args_list)
    assert ssh_ports == [22, 2222]


@patch("honeypot_auditor.cli.export")
@patch("honeypot_auditor.cli.render")
@patch("honeypot_auditor.cli.run_deep_probes", return_value=[])
@patch("honeypot_auditor.cli.nmap_scan", return_value=[])
@patch("honeypot_auditor.cli.shodan_lookup", return_value=[])
def test_run_audit_dash_p_only_selected_ports(
    mock_shodan,
    mock_nmap,
    mock_deep,
    mock_render,
    mock_export,
    tmp_path,
):
    ssh = MagicMock(return_value=[])
    sip = MagicMock(return_value=[])
    http = MagicMock(return_value=[])
    telnet = MagicMock(return_value=[])
    args = build_parser().parse_args(
        [
            "--target",
            "127.0.0.1",
            "-p22",
            "--output",
            str(tmp_path / "audit.json"),
        ]
    )
    with _stub_cli_probes(ssh=ssh, sip=sip, http=http, telnet=telnet):
        code = asyncio.run(run_audit(args))
    assert code == 0
    ssh.assert_called_once_with("127.0.0.1", 22)
    sip.assert_not_called()
    http.assert_not_called()
    telnet.assert_not_called()


@patch("honeypot_auditor.cli.export_subnet")
@patch("honeypot_auditor.cli.render_subnet_summary")
@patch("honeypot_auditor.cli._audit_host", new_callable=AsyncMock)
def test_run_audit_subnet_smoke(mock_audit_host, mock_render_summary, mock_export_subnet, tmp_path):
    from honeypot_auditor.models import AuditReport

    mock_audit_host.return_value = AuditReport(
        target="192.168.1.1",
        resolved_ip="192.168.1.1",
        score=0.0,
        threat_level="Likely Real Host",
        category_hits={},
    )
    args = build_parser().parse_args(
        [
            "--target",
            "192.168.1.0/30",
            "--scan-concurrency",
            "2",
            "--output",
            str(tmp_path / "subnet.json"),
        ]
    )
    code = asyncio.run(run_audit(args))
    assert code == 0
    assert mock_audit_host.await_count == 2
    mock_render_summary.assert_called_once()
    mock_export_subnet.assert_called_once()


def test_subnet_public_requires_confirm():
    args = build_parser().parse_args(["--target", "8.8.8.0/30"])
    code = asyncio.run(run_audit(args))
    assert code == 2


def test_parser_scan_concurrency():
    args = build_parser().parse_args(["--target", "127.0.0.1", "--scan-concurrency", "4"])
    assert args.scan_concurrency == 4


@patch("honeypot_auditor.cli.asyncio.to_thread", side_effect=RuntimeError("probe boom"))
@patch("honeypot_auditor.cli.export")
@patch("honeypot_auditor.cli.render")
@patch("honeypot_auditor.cli.run_deep_probes", return_value=[])
@patch("honeypot_auditor.cli.nmap_scan", return_value=[])
@patch("honeypot_auditor.cli.shodan_lookup", return_value=[])
def test_run_audit_probe_error_indicator(
    mock_shodan,
    mock_nmap,
    mock_deep,
    mock_render,
    mock_export,
    mock_to_thread,
    tmp_path,
):
    args = build_parser().parse_args(
        ["--target", "127.0.0.1", "--output", str(tmp_path / "audit.json")]
    )
    with _stub_cli_probes():
        code = asyncio.run(run_audit(args))
    assert code == 0


@patch("honeypot_auditor.cli.export")
@patch("honeypot_auditor.cli.render")
@patch("honeypot_auditor.cli.run_deep_probes", return_value=[])
@patch("honeypot_auditor.cli.nmap_scan", return_value=[])
@patch("honeypot_auditor.cli.shodan_lookup", return_value=[])
def test_run_audit_with_nmap_opt_in(
    mock_shodan, mock_nmap, mock_deep, mock_render, mock_export, tmp_path
):
    args = build_parser().parse_args(
        ["--target", "127.0.0.1", "-n", "--output", str(tmp_path / "audit.json")]
    )
    with _stub_cli_probes():
        code = asyncio.run(run_audit(args))
    assert code == 0
    mock_nmap.assert_called_once()


def test_deception_audit_preset_normalizes_before_port_map():
    from honeypot_auditor.cli import _normalize_preset_alias

    args = build_parser().parse_args(["--target", "127.0.0.1", "--preset", "deception-audit"])
    assert args.preset == "deception-audit"
    _normalize_preset_alias(args)
    assert args.preset == "both"
    assert args.deep is True


@patch("honeypot_auditor.cli.export")
@patch("honeypot_auditor.cli.render")
@patch("honeypot_auditor.cli.run_deep_probes", return_value=[])
@patch("honeypot_auditor.cli.nmap_scan", return_value=[])
@patch("honeypot_auditor.cli.shodan_lookup", return_value=[])
def test_run_audit_deception_audit_preset(
    mock_shodan, mock_nmap, mock_deep, mock_render, mock_export, tmp_path
):
    args = build_parser().parse_args(
        [
            "--target",
            "127.0.0.1",
            "--preset",
            "deception-audit",
            "--output",
            str(tmp_path / "audit.json"),
        ]
    )
    with _stub_cli_probes():
        code = asyncio.run(run_audit(args))
    assert code == 0
    assert args.preset == "both"
    assert args.deep is True
    mock_deep.assert_called_once()


def test_job_timeout_deep_has_dedicated_budget():
    from honeypot_auditor.cli import _job_timeout_seconds
    from honeypot_auditor.settings import settings

    settings.timeout_seconds = 3.0
    settings.deep_timeout_seconds = 90.0
    assert _job_timeout_seconds("ssh:22") == 12.0
    assert _job_timeout_seconds("deep") >= 90.0


def test_format_job_error_timeout_and_generic():
    from honeypot_auditor.cli import _format_job_error

    assert _format_job_error(TimeoutError(), timeout=90.0) == "timed out after 90s"
    assert "ValueError" in _format_job_error(ValueError("boom"), timeout=5.0)
    assert _format_job_error(RuntimeError(), timeout=5.0) == "RuntimeError"
