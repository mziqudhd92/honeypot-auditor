"""CLI behavior tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from honeypot_auditor.cli import build_parser, main


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
