"""TDD: Shodan history sudden_buffet — entropy + guards (fixtures only)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from honeypot_auditor.probes.history_intel import (
    evaluate_sudden_buffet,
    fetch_shodan_history,
    project_history_row,
    shodan_history_indicators,
)


def _ts(days_ago: float = 1.0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")


def test_eip_web_mail_ssh_burst_not_high_fidelity():
    # 9 common EIP ports — web/mail/ssh only
    ports = [22, 25, 80, 110, 143, 443, 993, 995, 8080]
    rows = [{"port": p, "transport": "tcp", "timestamp": _ts(1), "product": ""} for p in ports]
    ind = evaluate_sudden_buffet(rows)
    assert ind is not None
    assert ind.id == "shodan.sudden_buffet"
    assert ind.triggered is False or ind.fidelity != "high"
    assert ind.fidelity == "low"


def test_diverse_legacy_db_ics_is_high_sudden_buffet():
    ports = [23, 445, 3306, 6379, 21, 1433, 5432, 502]  # 8 ports, ≥4 families
    rows = [
        {"port": p, "transport": "tcp", "timestamp": _ts(0.5), "product": ""} for p in ports
    ]
    ind = evaluate_sudden_buffet(rows)
    assert ind is not None
    assert ind.triggered is True
    assert ind.fidelity == "high"


def test_history_oversize_skips():
    from honeypot_auditor.probes.history_intel import HISTORY_MAX_BYTES

    with patch("honeypot_auditor.probes.history_intel.urlopen") as mock_open:
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = b"x" * (HISTORY_MAX_BYTES + 10)
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_open.return_value = resp
        rows, err = fetch_shodan_history("203.0.113.10", "key")
    assert rows == []
    assert "exceeded" in err


def test_history_error_scrubs_api_key_from_detail():
    keyed_url = "https://api.shodan.io/shodan/host/1.2.3.4?key=super-secret-key&history=true"
    with patch(
        "honeypot_auditor.probes.history_intel.urlopen",
        side_effect=OSError(f"HTTP Error 401: {keyed_url}"),
    ):
        rows, err = fetch_shodan_history("1.2.3.4", "super-secret-key")
    assert rows == []
    assert "super-secret-key" not in err
    assert "[REDACTED]" in err


def test_history_timeout_skips():
    with patch(
        "honeypot_auditor.probes.history_intel.urlopen",
        side_effect=TimeoutError("timed out"),
    ):
        rows, err = fetch_shodan_history("203.0.113.10", "key")
    assert rows == []
    assert "timed out" in err


def test_projection_keeps_only_cheap_fields():
    row = project_history_row(
        {
            "port": 3306,
            "transport": "tcp",
            "timestamp": "2024-01-01T00:00:00",
            "product": "MySQL",
            "data": "HUGE BANNER " * 1000,
            "opts": {"raw": "nope"},
        }
    )
    assert row is not None
    assert set(row) <= {"port", "transport", "timestamp", "product", "family"}
    assert row["family"] == "mysql"


def test_shodan_history_indicators_skip_on_error():
    with patch(
        "honeypot_auditor.probes.history_intel.fetch_shodan_history",
        return_value=([], "history request timed out; skipped"),
    ):
        inds = shodan_history_indicators("203.0.113.10", "key")
    assert len(inds) == 1
    assert inds[0].skipped is True
    assert inds[0].id == "shodan.sudden_buffet"


def test_shodan_history_cli_flag_defaults_off():
    from honeypot_auditor.cli import build_parser

    args = build_parser().parse_args(["--target", "127.0.0.1"])
    assert getattr(args, "shodan_history", False) is False


def test_unparseable_timestamps_excluded_from_window():
    # Eight diverse ports but only with empty / garbage timestamps → no buffet.
    ports = [23, 445, 3306, 6379, 21, 1433, 5432, 502]
    rows = [{"port": p, "transport": "tcp", "timestamp": "", "product": ""} for p in ports]
    rows[0]["timestamp"] = "not-a-date"
    assert evaluate_sudden_buffet(rows) is None


def test_old_timestamps_outside_window_excluded():
    ports = [23, 445, 3306, 6379, 21, 1433, 5432, 502]
    rows = [
        {"port": p, "transport": "tcp", "timestamp": _ts(30), "product": ""} for p in ports
    ]
    assert evaluate_sudden_buffet(rows) is None


def test_fetch_shodan_history_uses_host_endpoint_with_history_flag():
    captured: dict = {}

    class _Resp:
        status = 200

        def read(self, _n=-1):
            return b'{"data":[{"port":22,"timestamp":"2099-01-01T00:00:00","transport":"tcp"}]}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        captured["full_url"] = req.full_url
        return _Resp()

    with patch("honeypot_auditor.probes.history_intel.urlopen", side_effect=fake_urlopen):
        rows, err = fetch_shodan_history("203.0.113.10", "test-key")
    assert err == ""
    assert rows
    assert "/shodan/host/203.0.113.10?" in captured["full_url"]
    assert "history=true" in captured["full_url"]
    assert "/history?" not in captured["full_url"]
