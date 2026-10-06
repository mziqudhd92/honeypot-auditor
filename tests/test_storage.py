"""SQLite storage layer tests (wizard + web UI persistence)."""

from __future__ import annotations

import pytest

from honeypot_auditor import storage
from honeypot_auditor.engine import Auditor


@pytest.fixture()
def db(tmp_path, monkeypatch):
    path = tmp_path / "audits.db"
    monkeypatch.setenv("HONEYPOT_AUDITOR_DB", str(path))
    return path


def _run_report(target: str = "127.0.0.1"):
    return Auditor(target=target, extra_ports=["9"], timeout=1).run()


def test_save_and_list_roundtrip(db):
    report = _run_report()
    audit_id = storage.save_report(report)
    assert isinstance(audit_id, int) and audit_id >= 1

    rows = storage.list_audits()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == audit_id
    assert row["target"] == "127.0.0.1"
    assert row["threat_level"] == report.threat_level
    assert row["deep"] == 0


def test_get_audit_returns_full_payload(db):
    report = _run_report()
    audit_id = storage.save_report(report, deep=True)
    record = storage.get_audit(audit_id)
    assert record is not None
    assert record["deep"] == 1
    assert record["report"]["target"] == "127.0.0.1"
    assert "indicators" in record["report"]


def test_get_audit_missing_returns_none(db):
    assert storage.get_audit(9999) is None


def test_delete_audit(db):
    report = _run_report()
    audit_id = storage.save_report(report)
    assert storage.delete_audit(audit_id) is True
    assert storage.get_audit(audit_id) is None
    assert storage.delete_audit(audit_id) is False


def test_explicit_db_path_argument(db):
    other = db.parent / "other.db"
    report = _run_report()
    storage.save_report(report, db_path=other)
    assert storage.list_audits(db_path=other)
    assert storage.list_audits(db_path=db.parent / "unused.db") == []
