"""SQL Server connection-history provider.

Requires the ``pyodbc`` package (``pip install pyodbc``) and an appropriate
ODBC driver for SQL Server (e.g. "ODBC Driver 18 for SQL Server").
The import is deferred so the rest of the application never needs pyodbc
unless this provider is actually selected.
"""

import datetime
import json
import logging
from typing import Dict, List, Optional

from . import ConnectionDatabaseProvider

try:
    import pyodbc  # type: ignore
except ImportError:
    pyodbc = None  # type: ignore

DEFAULT_CONN_STR = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=localhost;"
    "DATABASE=r001d00rs;"
    "Trusted_Connection=yes;"
    "TrustServerCertificate=yes;"
)


class SqlserverProvider(ConnectionDatabaseProvider):
    name = "SQL Server"

    def __init__(self):
        self._conn = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def connect(self, **kwargs) -> None:
        if pyodbc is None:
            raise RuntimeError(
                "pyodbc is not installed.  Run:  pip install pyodbc"
            )
        conn_str = kwargs.get("connection_string", DEFAULT_CONN_STR)
        self._conn = pyodbc.connect(conn_str, autocommit=True)
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
            IF NOT EXISTS (
                SELECT * FROM sys.tables WHERE name = 'connection_snapshots'
            )
            CREATE TABLE connection_snapshots (
                id               INT IDENTITY(1,1) PRIMARY KEY,
                timestamp        DATETIME2       NOT NULL,
                connections_json NVARCHAR(MAX)   NOT NULL,
                agent_data_json  NVARCHAR(MAX)   NULL
            )
        """)
        cur.execute("""
            IF NOT EXISTS (
                SELECT * FROM sys.indexes
                WHERE name = 'idx_snapshots_ts'
                  AND object_id = OBJECT_ID('connection_snapshots')
            )
            CREATE INDEX idx_snapshots_ts
            ON connection_snapshots (timestamp)
        """)
        cur.execute("""
            IF NOT EXISTS (
                SELECT * FROM sys.tables WHERE name = 'ipanalyze_alerts'
            )
            CREATE TABLE ipanalyze_alerts (
                id         INT IDENTITY(1,1) PRIMARY KEY,
                alert_json NVARCHAR(MAX) NOT NULL
            )
        """)
        cur.close()

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #
    def save_snapshot(self, timestamp: datetime.datetime,
                      connections: List[Dict],
                      agent_data: Optional[Dict] = None) -> None:
        if self._conn is None:
            return
        conn_json = json.dumps(connections, default=str)
        agent_json = json.dumps(agent_data, default=str) if agent_data else None
        try:
            self._conn.execute(
                "INSERT INTO connection_snapshots (timestamp, connections_json, agent_data_json) "
                "VALUES (?, ?, ?)",
                timestamp, conn_json, agent_json,
            )
        except Exception as e:
            logging.error(f"SQL Server save_snapshot error: {e}")

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #
    def load_snapshots(self, limit: int) -> List[Dict]:
        if self._conn is None:
            return []
        try:
            cur = self._conn.execute(
                "SELECT TOP (?) timestamp, connections_json, agent_data_json "
                "FROM connection_snapshots ORDER BY id DESC",
                limit,
            )
            rows = cur.fetchall()
            rows.reverse()
            result = []
            for ts, conn_json, agent_json in rows:
                if not isinstance(ts, datetime.datetime):
                    ts = datetime.datetime.now()
                result.append({
                    "datetime": ts,
                    "connection_list": json.loads(conn_json),
                    "agent_data": json.loads(agent_json) if agent_json else None,
                })
            return result
        except Exception as e:
            logging.error(f"SQL Server load_snapshots error: {e}")
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
                    json.dumps(alert, default=str),
                )
        except Exception as e:
            logging.error(f"SQL Server save_alerts error: {e}")

    def load_alerts(self) -> List[Dict]:
        if self._conn is None:
            return []
        try:
            cur = self._conn.execute(
                "SELECT alert_json FROM ipanalyze_alerts ORDER BY id ASC"
            )
            return [json.loads(row[0]) for row in cur.fetchall()]
        except Exception as e:
            logging.error(f"SQL Server load_alerts error: {e}")
            return []

    def purge_alerts(self) -> int:
        if self._conn is None:
            return 0
        try:
            cur = self._conn.execute("SELECT COUNT(*) FROM ipanalyze_alerts")
            count = cur.fetchone()[0]
            self._conn.execute("DELETE FROM ipanalyze_alerts")
            return count
        except Exception as e:
            logging.error(f"SQL Server purge_alerts error: {e}")
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
                "(SELECT TOP (?) id FROM connection_snapshots ORDER BY id ASC)",
                to_delete,
            )
            return to_delete
        except Exception as e:
            logging.error(f"SQL Server purge_oldest error: {e}")
            return 0
