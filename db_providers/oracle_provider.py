"""Oracle Database connection-history provider.

Requires the ``oracledb`` package (``pip install oracledb``).
The thin-mode driver works without a separate Oracle Client installation.
The import is deferred so the rest of the application never needs oracledb
unless this provider is actually selected.
"""

import datetime
import json
import logging
from typing import Dict, List, Optional

from . import ConnectionDatabaseProvider

try:
    import oracledb  # type: ignore
except ImportError:
    oracledb = None  # type: ignore

DEFAULT_DSN = "localhost:1521/XEPDB1"
DEFAULT_USER = "r001d00rs"
DEFAULT_PASSWORD = "r001d00rs"


class OracleProvider(ConnectionDatabaseProvider):
    name = "Oracle"

    def __init__(self):
        self._conn = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def connect(self, **kwargs) -> None:
        if oracledb is None:
            raise RuntimeError(
                "oracledb is not installed.  Run:  pip install oracledb"
            )
        dsn = kwargs.get("dsn", DEFAULT_DSN)
        user = kwargs.get("user", DEFAULT_USER)
        password = kwargs.get("password", DEFAULT_PASSWORD)
        self._conn = oracledb.connect(user=user, password=password, dsn=dsn)
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
            self._conn.ping()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #
    def _ensure_schema(self) -> None:
        cur = self._conn.cursor()
        # Check if table exists
        cur.execute(
            "SELECT COUNT(*) FROM user_tables WHERE table_name = 'CONNECTION_SNAPSHOTS'"
        )
        if cur.fetchone()[0] == 0:
            cur.execute("""
                CREATE TABLE connection_snapshots (
                    id               NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    timestamp        TIMESTAMP       NOT NULL,
                    connections_json CLOB            NOT NULL,
                    agent_data_json  CLOB
                )
            """)
            cur.execute("""
                CREATE INDEX idx_snapshots_ts ON connection_snapshots (timestamp)
            """)
            self._conn.commit()
        # Alerts table
        cur.execute(
            "SELECT COUNT(*) FROM user_tables WHERE table_name = 'IPANALYZE_ALERTS'"
        )
        if cur.fetchone()[0] == 0:
            cur.execute("""
                CREATE TABLE ipanalyze_alerts (
                    id         NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    alert_json CLOB NOT NULL
                )
            """)
            self._conn.commit()
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
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO connection_snapshots (timestamp, connections_json, agent_data_json) "
                "VALUES (:1, :2, :3)",
                (timestamp, conn_json, agent_json),
            )
            self._conn.commit()
            cur.close()
        except Exception as e:
            logging.error(f"Oracle save_snapshot error: {e}")

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #
    def load_snapshots(self, limit: int) -> List[Dict]:
        if self._conn is None:
            return []
        try:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT timestamp, connections_json, agent_data_json "
                "FROM connection_snapshots ORDER BY id DESC FETCH FIRST :1 ROWS ONLY",
                (limit,),
            )
            rows = cur.fetchall()
            cur.close()
            rows.reverse()
            result = []
            for ts, conn_json, agent_json in rows:
                if not isinstance(ts, datetime.datetime):
                    ts = datetime.datetime.now()
                # Oracle CLOB objects may need explicit read
                if hasattr(conn_json, 'read'):
                    conn_json = conn_json.read()
                if agent_json is not None and hasattr(agent_json, 'read'):
                    agent_json = agent_json.read()
                result.append({
                    "datetime": ts,
                    "connection_list": json.loads(conn_json),
                    "agent_data": json.loads(agent_json) if agent_json else None,
                })
            return result
        except Exception as e:
            logging.error(f"Oracle load_snapshots error: {e}")
            return []

    def count_snapshots(self) -> int:
        if self._conn is None:
            return 0
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM connection_snapshots")
            val = cur.fetchone()[0]
            cur.close()
            return val
        except Exception:
            return 0

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #
    def save_alerts(self, alerts: List[Dict]) -> None:
        if self._conn is None:
            return
        try:
            cur = self._conn.cursor()
            cur.execute("DELETE FROM ipanalyze_alerts")
            for alert in alerts:
                cur.execute(
                    "INSERT INTO ipanalyze_alerts (alert_json) VALUES (:1)",
                    (json.dumps(alert, default=str),),
                )
            self._conn.commit()
            cur.close()
        except Exception as e:
            logging.error(f"Oracle save_alerts error: {e}")

    def load_alerts(self) -> List[Dict]:
        if self._conn is None:
            return []
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT alert_json FROM ipanalyze_alerts ORDER BY id ASC")
            rows = cur.fetchall()
            cur.close()
            result = []
            for (alert_json,) in rows:
                if hasattr(alert_json, 'read'):
                    alert_json = alert_json.read()
                result.append(json.loads(alert_json))
            return result
        except Exception as e:
            logging.error(f"Oracle load_alerts error: {e}")
            return []

    def purge_alerts(self) -> int:
        if self._conn is None:
            return 0
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM ipanalyze_alerts")
            count = cur.fetchone()[0]
            cur.execute("DELETE FROM ipanalyze_alerts")
            self._conn.commit()
            cur.close()
            return count
        except Exception as e:
            logging.error(f"Oracle purge_alerts error: {e}")
            return 0

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #
    def purge_oldest(self, keep: int) -> int:
        if self._conn is None:
            return 0
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM connection_snapshots")
            total = cur.fetchone()[0]
            if total <= keep:
                cur.close()
                return 0
            to_delete = total - keep
            cur.execute(
                "DELETE FROM connection_snapshots WHERE id IN "
                "(SELECT id FROM connection_snapshots ORDER BY id ASC FETCH FIRST :1 ROWS ONLY)",
                (to_delete,),
            )
            self._conn.commit()
            cur.close()
            return to_delete
        except Exception as e:
            logging.error(f"Oracle purge_oldest error: {e}")
            return 0
