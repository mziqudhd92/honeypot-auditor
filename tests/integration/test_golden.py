"""Live Docker golden fixtures (cowrie / dionaea / nginx).

Requires: docker compose -f deploy/docker-compose.benchmark.yml up -d
Skipped automatically when services are unreachable.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime

import pytest

from honeypot_auditor.analyzer import build_report
from honeypot_auditor.models import Indicator
from honeypot_auditor.probes.http import probe_http
from honeypot_auditor.probes.ssh import probe_ssh

pytestmark = pytest.mark.integration


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _require(host: str, port: int) -> None:
    if not _port_open(host, port):
        pytest.skip(f"{host}:{port} not reachable (start deploy/docker-compose.benchmark.yml)")


def _report(host: str, indicators: list[Indicator], *, http_port: int) -> object:
    now = datetime.now(UTC).isoformat()
    return build_report(
        target=host,
        resolved_ip=host,
        ports={"http": http_port},
        indicators=indicators,
        notes=[],
        started_at=now,
        finished_at=now,
    )


def test_nginx_baseline_clean():
    """Production-like nginx should not look like a stock HTTP lure."""
    _require("127.0.0.1", 8088)
    inds = probe_http("127.0.0.1", 8088)
    report = _report("127.0.0.1", inds, http_port=8088)
    assert report.score < 40, f"nginx baseline score too high: {report.score}"
    by_id = {i.id: i for i in inds}
    if "http.wildcard_host" in by_id:
        assert not by_id["http.wildcard_host"].triggered


def test_cowrie_ssh_banner_attempted():
    """Cowrie lab port should yield SSH indicators (triggered or skipped with reason)."""
    _require("127.0.0.1", 8022)
    inds = probe_ssh("127.0.0.1", 8022)
    assert inds, "expected SSH probe indicators against cowrie"
    assert any(isinstance(i, Indicator) and i.id.startswith("ssh.") for i in inds)


def test_dionaea_http_face_attempted():
    """Dionaea HTTP face should be probeable without crashing."""
    _require("127.0.0.1", 8024)
    inds = probe_http("127.0.0.1", 8024)
    assert inds
    report = _report("127.0.0.1", inds, http_port=8024)
    assert report.score >= 0
