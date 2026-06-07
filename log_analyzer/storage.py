from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from log_analyzer.core import Report


class SQLiteStore:

    def __init__(self, db_path: Path = Path("reports.db")):
        self.db_path = db_path
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    file        TEXT    NOT NULL,
                    run_at      TEXT    NOT NULL,
                    total_lines INTEGER,
                    failed      INTEGER,
                    accepted    INTEGER,
                    alerts      TEXT
                )
            """)

    def save(self, report: Report) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                """INSERT INTO runs
                   (file, run_at, total_lines, failed, accepted, alerts)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    report.file,
                    datetime.now(timezone.utc).isoformat(),
                    report.total_lines,
                    report.failed_total,
                    report.accepted_total,
                    json.dumps(report.alerts),
                ),
            )
            return cur.lastrowid  # type: ignore

    def history(self, limit: int = 10) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY run_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]