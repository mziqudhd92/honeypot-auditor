"""Local SQLite persistence for audit results.

Shared by the CLI wizard (`honeypot-auditor wizard`) and the local web UI
(`honeypot-auditor serve`). The database lives under the user's home directory
by default — override with the ``HONEYPOT_AUDITOR_DB`` environment variable or
an explicit ``db_path`` argument.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path

from honeypot_auditor.models import AuditReport
from honeypot_auditor.reporters.json_export import _report_payload as report_payload

DEFAULT_DB_PATH = Path.home() / ".honeypot-auditor" / "audits.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    target TEXT NOT NULL,
    resolved_ip TEXT NOT NULL,
    score REAL NOT NULL,
    threat_level TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT '',
    triggered_count INTEGER NOT NULL DEFAULT 0,
    deep INTEGER NOT NULL DEFAULT 0,
    report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audits_created ON audits (created_at DESC);
"""


def default_db_path() -> Path:
    env = os.environ.get("HONEYPOT_AUDITOR_DB", "").strip()
    return Path(env) if env else DEFAULT_DB_PATH


def _connect(db_path: str | Path | None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else default_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Restrict the DB directory/file — reports can include target metadata.
    with suppress(OSError):
        os.chmod(path.parent, 0o700)
    conn = sqlite3.connect(path)
    with suppress(OSError):
        os.chmod(path, 0o600)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def save_report(
    report: AuditReport,
    *,
    deep: bool = False,
    db_path: str | Path | None = None,
) -> int:
    """Persist one finished audit; returns the new row id."""
    payload = report_payload(report)
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "INSERT INTO audits (created_at, target, resolved_ip, score, threat_level,"
            " confidence, triggered_count, deep, report_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",  # lastrowid is int on insert

            (
                created,
                str(report.target),
                str(report.resolved_ip),
                float(report.score),
                report.threat_level,
                str(report.confidence or ""),
                len(report.triggered()),
                1 if deep else 0,
                json.dumps(payload),
            ),
        )
        conn.commit()
        row_id = cursor.lastrowid
        assert row_id is not None
        return int(row_id)
    finally:
        conn.close()


def list_audits(limit: int = 50, *, db_path: str | Path | None = None) -> list[dict]:
    """Newest-first audit summaries (no full report payloads)."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, created_at, target, resolved_ip, score, threat_level,"
            " confidence, triggered_count, deep"
            " FROM audits ORDER BY id DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_audit(audit_id: int, *, db_path: str | Path | None = None) -> dict | None:
    """One full audit (summary + parsed report payload), or None."""
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT * FROM audits WHERE id = ?", (int(audit_id),)).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["report"] = json.loads(record.pop("report_json"))
        return record
    finally:
        conn.close()


def delete_audit(audit_id: int, *, db_path: str | Path | None = None) -> bool:
    conn = _connect(db_path)
    try:
        cursor = conn.execute("DELETE FROM audits WHERE id = ?", (int(audit_id),))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()
