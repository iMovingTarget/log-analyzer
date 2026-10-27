"""Run history storage: SQLite by default, MySQL/MariaDB optionally."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from log_analyzer.core import Report


class SQLiteStore:
    def __init__(self, db_path: Path = Path("reports.db")):
        self.db_path = Path(db_path)
        self._init()

    def _connect(self) -> closing[sqlite3.Connection]:
        # sqlite3's own context manager only commits; closing() also releases
        # the file, which matters on Windows where an open handle locks it.
        return closing(sqlite3.connect(self.db_path))

    def _init(self) -> None:
        with self._connect() as conn, conn:
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
        with self._connect() as conn, conn:
            cur = conn.execute(
                """INSERT INTO runs (file, run_at, total_lines, failed, accepted, alerts)
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
            return int(cur.lastrowid or 0)

    def history(self, limit: int = 10) -> list[dict]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY run_at DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


class MySQLStore:
    """MySQL/MariaDB backend with the same interface as SQLiteStore."""

    def __init__(self, host: str, user: str, password: str, database: str):
        try:
            import mysql.connector
        except ImportError:
            raise RuntimeError(
                "mysql-connector-python is not installed. "
                "Install it with: pip install 'log-analyzer[mysql]'"
            ) from None
        self._mysql = mysql.connector
        self.config = {"host": host, "user": user, "password": password, "database": database}
        self._init()

    def _init(self) -> None:
        with self._mysql.connect(**self.config) as conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id          INT AUTO_INCREMENT PRIMARY KEY,
                    file        VARCHAR(500),
                    run_at      DATETIME,
                    total_lines INT,
                    failed      INT,
                    accepted    INT,
                    alerts      JSON
                )
            """)
            conn.commit()

    def save(self, report: Report) -> int:
        with self._mysql.connect(**self.config) as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO runs (file, run_at, total_lines, failed, accepted, alerts)
                   VALUES (%s, UTC_TIMESTAMP(), %s, %s, %s, %s)""",
                (
                    report.file,
                    report.total_lines,
                    report.failed_total,
                    report.accepted_total,
                    json.dumps(report.alerts),
                ),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def history(self, limit: int = 10) -> list[dict]:
        with self._mysql.connect(**self.config) as conn, conn.cursor(dictionary=True) as cur:
            cur.execute("SELECT * FROM runs ORDER BY run_at DESC, id DESC LIMIT %s", (limit,))
            return cur.fetchall()
