"""
db.py

SQLite database manager for the central log collector.
Stores all incoming events and mitigation actions for forensic analysis.

Schema:
  - events: all raw events received from victim VMs
  - mitigations: record of every mitigation action taken
"""

import sqlite3
import json
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional


DB_PATH = "lab_logs.db"


class Database:
    """
    Thread-safe SQLite wrapper for storing events and mitigations.
    Uses a threading.Lock so multiple handler threads can write safely.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        """Create tables if they don't exist"""
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS events (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        received_at     TEXT    NOT NULL,
                        alert_type      TEXT    NOT NULL,
                        severity        TEXT    NOT NULL,
                        source_vm       TEXT    NOT NULL,
                        timestamp       TEXT,
                        description     TEXT,
                        raw_json        TEXT    NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS mitigations (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        executed_at     TEXT    NOT NULL,
                        alert_type      TEXT    NOT NULL,
                        source_vm       TEXT    NOT NULL,
                        action          TEXT    NOT NULL,
                        result          TEXT,
                        event_id        INTEGER,
                        FOREIGN KEY (event_id) REFERENCES events(id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_events_alert_type
                        ON events(alert_type);
                    CREATE INDEX IF NOT EXISTS idx_events_source_vm
                        ON events(source_vm);
                    CREATE INDEX IF NOT EXISTS idx_events_severity
                        ON events(severity);
                """)
                conn.commit()
            finally:
                conn.close()

    def insert_event(self, event: Dict[str, Any]) -> int:
        """
        Insert a single event into the events table.
        Returns the new row ID.
        """
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO events
                        (received_at, alert_type, severity, source_vm,
                         timestamp, description, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        datetime.utcnow().isoformat() + "Z",
                        event.get("alert_type", "unknown"),
                        event.get("severity", "unknown"),
                        event.get("source_vm", "unknown"),
                        event.get("timestamp"),
                        event.get("description"),
                        json.dumps(event),
                    )
                )
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def insert_mitigation(
        self,
        alert_type: str,
        source_vm: str,
        action: str,
        result: str,
        event_id: Optional[int] = None,
    ):
        """Record a mitigation action that was taken"""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO mitigations
                        (executed_at, alert_type, source_vm, action, result, event_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        datetime.utcnow().isoformat() + "Z",
                        alert_type,
                        source_vm,
                        action,
                        result,
                        event_id,
                    )
                )
                conn.commit()
            finally:
                conn.close()

    def get_recent_events(
        self,
        limit: int = 50,
        alert_type: Optional[str] = None,
        source_vm: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query recent events with optional filters"""
        with self._lock:
            conn = self._connect()
            try:
                query = "SELECT * FROM events"
                params = []
                conditions = []

                if alert_type:
                    conditions.append("alert_type = ?")
                    params.append(alert_type)
                if source_vm:
                    conditions.append("source_vm = ?")
                    params.append(source_vm)

                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

                query += " ORDER BY id DESC LIMIT ?"
                params.append(limit)

                rows = conn.execute(query, params).fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()

    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics"""
        with self._lock:
            conn = self._connect()
            try:
                total_events = conn.execute(
                    "SELECT COUNT(*) FROM events"
                ).fetchone()[0]

                total_mitigations = conn.execute(
                    "SELECT COUNT(*) FROM mitigations"
                ).fetchone()[0]

                by_type = conn.execute(
                    "SELECT alert_type, COUNT(*) as count FROM events GROUP BY alert_type"
                ).fetchall()

                by_severity = conn.execute(
                    "SELECT severity, COUNT(*) as count FROM events GROUP BY severity"
                ).fetchall()

                return {
                    "total_events": total_events,
                    "total_mitigations": total_mitigations,
                    "by_type": {row["alert_type"]: row["count"] for row in by_type},
                    "by_severity": {row["severity"]: row["count"] for row in by_severity},
                }
            finally:
                conn.close()
