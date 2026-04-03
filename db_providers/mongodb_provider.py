"""MongoDB connection-history provider.

Requires the ``pymongo`` package (``pip install pymongo``).
The import is deferred to this file so the rest of the application never
needs pymongo unless MongoDB is actually selected.
"""

import datetime
import json
import logging
from typing import Dict, List, Optional

from . import ConnectionDatabaseProvider

# Deferred import — only fails if someone actually selects this provider
# without having pymongo installed.
try:
    import pymongo  # type: ignore
except ImportError:
    pymongo = None  # type: ignore

DB_NAME = "r001d00rs"
COLLECTION_NAME = "connection_snapshots"


class MongodbProvider(ConnectionDatabaseProvider):
    name = "MongoDB"

    def __init__(self):
        self._client = None
        self._db = None
        self._col = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def connect(self, **kwargs) -> None:
        if pymongo is None:
            raise RuntimeError(
                "pymongo is not installed.  Run:  pip install pymongo"
            )
        uri = kwargs.get("uri", "mongodb://localhost:27017")
        self._client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        # Force a round-trip to verify connectivity
        self._client.admin.command("ping")
        self._db = self._client[DB_NAME]
        self._col = self._db[COLLECTION_NAME]
        self._ensure_schema()

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            self._db = None
            self._col = None

    def is_connected(self) -> bool:
        if self._client is None:
            return False
        try:
            self._client.admin.command("ping")
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #
    def _ensure_schema(self) -> None:
        self._col.create_index([("timestamp", pymongo.ASCENDING)])

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #
    def save_snapshot(self, timestamp: datetime.datetime,
                      connections: List[Dict],
                      agent_data: Optional[Dict] = None) -> None:
        if self._col is None:
            return
        doc = {
            "timestamp": timestamp,
            "connections": json.loads(json.dumps(connections, default=str)),
            "agent_data": json.loads(json.dumps(agent_data, default=str)) if agent_data else None,
        }
        try:
            self._col.insert_one(doc)
        except Exception as e:
            logging.error(f"MongoDB save_snapshot error: {e}")

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #
    def load_snapshots(self, limit: int) -> List[Dict]:
        if self._col is None:
            return []
        try:
            cursor = self._col.find().sort("timestamp", pymongo.DESCENDING).limit(limit)
            rows = list(cursor)
            rows.reverse()  # oldest first
            result = []
            for doc in rows:
                ts = doc.get("timestamp")
                if not isinstance(ts, datetime.datetime):
                    ts = datetime.datetime.now()
                result.append({
                    "datetime": ts,
                    "connection_list": doc.get("connections", []),
                    "agent_data": doc.get("agent_data"),
                })
            return result
        except Exception as e:
            logging.error(f"MongoDB load_snapshots error: {e}")
            return []

    def count_snapshots(self) -> int:
        if self._col is None:
            return 0
        try:
            return self._col.count_documents({})
        except Exception:
            return 0

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #
    def purge_oldest(self, keep: int) -> int:
        if self._col is None:
            return 0
        try:
            total = self._col.count_documents({})
            if total <= keep:
                return 0
            to_delete = total - keep
            oldest_ids = [
                doc["_id"]
                for doc in self._col.find().sort("timestamp", pymongo.ASCENDING).limit(to_delete)
            ]
            if oldest_ids:
                self._col.delete_many({"_id": {"$in": oldest_ids}})
            return len(oldest_ids)
        except Exception as e:
            logging.error(f"MongoDB purge_oldest error: {e}")
            return 0
