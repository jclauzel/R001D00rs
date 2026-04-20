# R001D00rs database abstraction layer
#
# Each provider subclasses ConnectionDatabaseProvider and lives in its own
# .py file inside this package.  Only the chosen provider's module is imported
# at runtime, so database-specific dependencies (pymongo, pyodbc, cx_Oracle…)
# are never required unless the provider is actually selected.

import abc
import datetime
from typing import Dict, List, Optional


class ConnectionDatabaseProvider(abc.ABC):
    """Abstract interface that every database back-end must implement.

    The high-level application interacts exclusively through this interface
    and never knows which concrete database engine is in use.
    """

    # Human-readable name shown in the Settings combo box.
    name: str = ""

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def connect(self, **kwargs) -> None:
        """Open / create the database and ensure the schema exists."""

    @abc.abstractmethod
    def close(self) -> None:
        """Cleanly shut down the database connection."""

    @abc.abstractmethod
    def is_connected(self) -> bool:
        """Return True if the database connection is alive."""

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def save_snapshot(self, timestamp: datetime.datetime,
                      connections: List[Dict],
                      agent_data: Optional[Dict] = None) -> None:
        """Persist one connection-cycle snapshot.

        Parameters
        ----------
        timestamp   : when this snapshot was captured
        connections : list of connection dicts (same schema as connection_list entries)
        agent_data  : optional server-mode agent payload
        """

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def load_snapshots(self, limit: int) -> List[Dict]:
        """Return up to *limit* most-recent snapshots, oldest first.

        Each returned dict must have the keys:
            ``datetime``        – datetime.datetime
            ``connection_list`` – list[dict]
            ``agent_data``      – dict | None
        """

    @abc.abstractmethod
    def count_snapshots(self) -> int:
        """Return the total number of stored snapshots."""

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def purge_oldest(self, keep: int) -> int:
        """Delete the oldest snapshots so that at most *keep* remain.

        Returns the number of rows actually deleted.
        """

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def save_alerts(self, alerts: List[Dict]) -> None:
        """Persist the full list of IPAnalyze alerts, replacing any
        previously stored alerts."""

    @abc.abstractmethod
    def load_alerts(self) -> List[Dict]:
        """Return all previously persisted IPAnalyze alerts."""


# --------------------------------------------------------------------- #
# Provider registry – discovers concrete providers in this package.
# --------------------------------------------------------------------- #
_PROVIDERS: Dict[str, type] = {}


def _discover_providers():
    """Import every sibling module and register its provider class."""
    import importlib
    import os
    import logging

    pkg_dir = os.path.dirname(__file__)
    for fname in sorted(os.listdir(pkg_dir)):
        if fname.startswith("_") or not fname.endswith("_provider.py"):
            continue
        module_name = fname[:-3]  # strip .py
        try:
            mod = importlib.import_module(f".{module_name}", package=__name__)
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if (isinstance(obj, type)
                        and issubclass(obj, ConnectionDatabaseProvider)
                        and obj is not ConnectionDatabaseProvider
                        and getattr(obj, 'name', '')):
                    _PROVIDERS[obj.name] = obj
        except Exception as exc:
            # Provider's dependency is missing — skip silently.
            logging.debug(f"Skipping db provider module {module_name}: {exc}")


_discover_providers()


def get_available_providers() -> Dict[str, type]:
    """Return ``{display_name: provider_class}`` for every importable provider."""
    return dict(_PROVIDERS)


def create_provider(name: str) -> Optional[ConnectionDatabaseProvider]:
    """Instantiate a provider by its display name, or return None."""
    cls = _PROVIDERS.get(name)
    if cls is None:
        return None
    return cls()
