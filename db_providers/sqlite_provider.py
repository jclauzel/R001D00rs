"""SQLite connection-history provider.

Uses only the Python standard-library ``sqlite3`` module — no extra
dependencies are required.
"""

import datetime
import json
import logging
import os
import sqlite3
from typing import Dict, List, Optional

from . import ConnectionDatabaseProvider

DB_FILENAME = "connection_history.db"


class SqliteProvider(ConnectionDatabaseProvider):
    name = "SQLite"

    def __init__(self):
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def connect(self, **kwargs) -> None:
        db_path = kwargs.get("db_path", DB_FILENAME)
        # Ensure directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._ensure_schema()

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def is_connected(self) -> bool:
        if self._conn is None:
            return False
        try:
            self._conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #
    def _ensure_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS connection_snapshots (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT    NOT NULL,
                connections_json TEXT NOT NULL,
                agent_data_json  TEXT
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_snapshots_ts
            ON connection_snapshots (timestamp)
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ipanalyze_alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_json  TEXT NOT NULL
            )
        """)
        self._conn.commit()

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #
    def save_snapshot(self, timestamp: datetime.datetime,
                      connections: List[Dict],
                      agent_data: Optional[Dict] = None) -> None:
        if self._conn is None:
            return
        ts_str = timestamp.isoformat()
        conn_json = json.dumps(connections, default=str)
        agent_json = json.dumps(agent_data, default=str) if agent_data else None
        try:
            self._conn.execute(
                "INSERT INTO connection_snapshots (timestamp, connections_json, agent_data_json) "
                "VALUES (?, ?, ?)",
                (ts_str, conn_json, agent_json),
            )
            self._conn.commit()
        except Exception as e:
            logging.error(f"SQLite save_snapshot error: {e}")

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #
    def load_snapshots(self, limit: int) -> List[Dict]:
        if self._conn is None:
            return []
        try:
            cur = self._conn.execute(
                "SELECT timestamp, connections_json, agent_data_json "
                "FROM connection_snapshots ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
            rows.reverse()  # oldest first
            result = []
            for ts_str, conn_json, agent_json in rows:
                try:
                    dt = datetime.datetime.fromisoformat(ts_str)
                except Exception:
                    dt = datetime.datetime.now()
                result.append({
                    "datetime": dt,
                    "connection_list": json.loads(conn_json),
                    "agent_data": json.loads(agent_json) if agent_json else None,
                })
            return result
        except Exception as e:
            logging.error(f"SQLite load_snapshots error: {e}")
            return []

    def count_snapshots(self) -> int:
        if self._conn is None:
            return 0
        try:
            cur = self._conn.execute("SELECT COUNT(*) FROM connection_snapshots")
            return cur.fetchone()[0]
        except Exception:
            return 0

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #
    def save_alerts(self, alerts: List[Dict]) -> None:
        if self._conn is None:
            return
        try:
            self._conn.execute("DELETE FROM ipanalyze_alerts")
            for alert in alerts:
                self._conn.execute(
                    "INSERT INTO ipanalyze_alerts (alert_json) VALUES (?)",
                    (json.dumps(alert, default=str),),
                )
            self._conn.commit()
        except Exception as e:
            logging.error(f"SQLite save_alerts error: {e}")

    def load_alerts(self) -> List[Dict]:
        if self._conn is None:
            return []
        try:
            cur = self._conn.execute(
                "SELECT alert_json FROM ipanalyze_alerts ORDER BY id ASC"
            )
            return [json.loads(row[0]) for row in cur.fetchall()]
        except Exception as e:
            logging.error(f"SQLite load_alerts error: {e}")
            return []

    def purge_alerts(self) -> int:
        if self._conn is None:
            return 0
        try:
            cur = self._conn.execute("SELECT COUNT(*) FROM ipanalyze_alerts")
            count = cur.fetchone()[0]
            self._conn.execute("DELETE FROM ipanalyze_alerts")
            self._conn.commit()
            return count
        except Exception as e:
            logging.error(f"SQLite purge_alerts error: {e}")
            return 0

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #
    def purge_oldest(self, keep: int) -> int:
        if self._conn is None:
            return 0
        try:
            cur = self._conn.execute("SELECT COUNT(*) FROM connection_snapshots")
            total = cur.fetchone()[0]
            if total <= keep:
                return 0
            to_delete = total - keep
            self._conn.execute(
                "DELETE FROM connection_snapshots WHERE id IN "
                "(SELECT id FROM connection_snapshots ORDER BY id ASC LIMIT ?)",
                (to_delete,),
            )
            self._conn.commit()
            return to_delete
        except Exception as e:
            logging.error(f"SQLite purge_oldest error: {e}")
            return 0
