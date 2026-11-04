"""Censys passive_intel provider — snapshot must not emit high sudden_buffet."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from honeypot_auditor.plugins.censys_provider import censys_provider


def _ts(days_ago: float = 0.5) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")


def test_censys_diverse_snapshot_is_medium_not_high_sudden():
    ports = [23, 445, 3306, 6379, 21, 1433, 5432, 502]
    services = [
        {
            "port": p,
            "transport_protocol": "tcp",
            "service_name": "",
            "observed_at": _ts(0.5),
        }
        for p in ports
    ]
    payload = json.dumps({"result": {"services": services}}).encode()

    resp = MagicMock()
    resp.read.return_value = payload
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)

    with patch("honeypot_auditor.plugins.censys_provider.urlopen", return_value=resp):
        inds = censys_provider("203.0.113.10", "id:secret")

    assert len(inds) == 1
    assert inds[0].triggered is True
    assert inds[0].id == "multi_family_services"
    assert inds[0].fidelity == "medium"
    assert inds[0].requires_corroboration is True
    assert "sudden_buffet" not in inds[0].id
