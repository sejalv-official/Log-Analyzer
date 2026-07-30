import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).parent / "incidents.db"


def get_connection() -> sqlite3.Connection:
    """Open a connection to the local incident database."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    """Create the incidents table if it does not already exist."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                error_count INTEGER NOT NULL,
                log_reference TEXT,
                report TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open'
            )
            """
        )


def save_incident(
    source: str,
    severity: str,
    error_count: int,
    report: str,
    log_reference: str = "",
) -> int:
    """Save one AI-generated incident and return its database ID."""
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO incidents (
                created_at,
                source,
                severity,
                error_count,
                log_reference,
                report,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().isoformat(timespec="seconds"),
                source,
                severity,
                error_count,
                log_reference,
                report,
                "Open",
            ),
        )
        return int(cursor.lastrowid)


def list_incidents(limit: int = 100) -> list[dict[str, Any]]:
    """Return the newest incidents first."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                created_at,
                source,
                severity,
                error_count,
                log_reference,
                status,
                report
            FROM incidents
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]