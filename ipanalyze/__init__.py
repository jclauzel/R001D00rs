"""
IPAnalyze — extensible IP threat-intelligence plugin framework.

Each plugin lives in the ``ipanalyze/`` package directory and derives from
:class:`IPAnalyzePlugin`.  Plugins are registered by adding one line per
plugin module name (without ``.py``) to ``ipanalyze.json`` in the
application root.

Every plugin stores its own configuration in a JSON file named
``<module_name>.json`` inside the ``ipanalyze/`` directory.

Public API used by the main application:
    load_registry()          — read ipanalyze.json, import & instantiate plugins
    IPAnalyzePlugin          — abstract base class
    IPAnalyzeResult          — per-plugin result dataclass
"""

from __future__ import annotations

import abc
import importlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class IPAnalyzeResult:
    """Returned by each plugin after checking an IP address."""
    found: bool = False
    plugin_name: str = ""
    additional_information: str = ""


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------

class IPAnalyzePlugin(abc.ABC):
    """Interface that every IPAnalyze plugin must implement."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable plugin name (shown in the Settings UI)."""
        ...

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Short description of what this plugin does."""
        ...

    @abc.abstractmethod
    def check_ip(self, ip_address: str) -> IPAnalyzeResult:
        """Check whether *ip_address* is suspicious.

        Must be safe to call from any thread (the main application invokes
        this from a ``QThreadPool`` worker).

        Returns an :class:`IPAnalyzeResult`.
        """
        ...

    def show_settings_dialog(self, parent) -> None:
        """Build and show a PySide6 dialog for editing this plugin's settings.

        Each plugin owns its UI — the main application simply calls this
        method when the user clicks the *Settings* button in the IPAnalyze
        plugin table.  ``parent`` is the main :class:`QMainWindow` instance.

        The default implementation does nothing (plugins that have no
        configurable settings may leave it as-is).  Plugins with settings
        **must** override this to import PySide6 widgets *inside* the method
        and build the dialog themselves.
        """
        pass

    # --- configuration helpers (shared) ------------------------------------

    def _config_path(self) -> str:
        """Return the path to this plugin's JSON config file."""
        module_file = os.path.abspath(
            getattr(self.__class__, '_source_file', __file__)
        )
        module_dir = os.path.dirname(module_file)
        module_name = os.path.splitext(os.path.basename(module_file))[0]
        return os.path.join(module_dir, f"{module_name}.json")

    def load_config(self) -> dict:
        """Load and return the plugin's JSON config, or ``{}`` if missing."""
        path = self._config_path()
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logging.warning("IPAnalyze: failed to load config %s: %s", path, exc)
            return {}

    def save_config(self, cfg: dict) -> None:
        """Persist *cfg* to the plugin's JSON config file."""
        path = self._config_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            logging.error("IPAnalyze: failed to save config %s: %s", path, exc)

    def get_settings(self) -> Dict[str, dict]:
        """Return an ordered dict of ``{key: {value, type, description}}``
        entries that the Settings UI will display in an editable table.

        Subclasses should override this.  The default implementation
        exposes every top-level key in the config JSON.
        """
        cfg = self.load_config()
        out: Dict[str, dict] = {}
        for k, v in cfg.items():
            out[k] = {
                "value": v,
                "type": type(v).__name__,
                "description": k,
            }
        return out


# ---------------------------------------------------------------------------
# Registry loader
# ---------------------------------------------------------------------------

_REGISTRY_FILE = "ipanalyze.json"
_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))


def _registry_path() -> str:
    """Return the absolute path of the registry file (application root)."""
    return os.path.join(os.path.dirname(_PACKAGE_DIR), _REGISTRY_FILE)


def load_registry() -> List[IPAnalyzePlugin]:
    """Read ``ipanalyze.json`` and import + instantiate every listed plugin.

    The registry file contains a JSON array of objects::

        [
            {"module": "http_text_csv_plugin", "enabled": true},
            {"module": "pihole_plugin",        "enabled": false}
        ]

    Returns a list of :class:`IPAnalyzePlugin` instances (one per entry).
    Plugins that fail to import are logged and skipped.
    """
    reg_path = _registry_path()
    if not os.path.exists(reg_path):
        logging.info("IPAnalyze: registry file %s not found — no plugins loaded", reg_path)
        return []

    try:
        with open(reg_path, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except Exception as exc:
        logging.error("IPAnalyze: failed to read registry %s: %s", reg_path, exc)
        return []

    plugins: List[IPAnalyzePlugin] = []
    for entry in entries:
        module_name = entry if isinstance(entry, str) else entry.get("module", "")
        if not module_name:
            continue
        fqn = f"ipanalyze.{module_name}"
        try:
            mod = importlib.import_module(fqn)
            # Find the first IPAnalyzePlugin subclass defined in the module
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if (isinstance(obj, type)
                        and issubclass(obj, IPAnalyzePlugin)
                        and obj is not IPAnalyzePlugin):
                    inst = obj()
                    inst._source_module = module_name
                    inst.__class__._source_file = mod.__file__
                    inst._enabled = entry.get("enabled", False) if isinstance(entry, dict) else False
                    plugins.append(inst)
                    logging.info("IPAnalyze: loaded plugin '%s' from %s (enabled=%s)",
                                 inst.name, fqn, inst._enabled)
                    break
            else:
                logging.warning("IPAnalyze: no IPAnalyzePlugin subclass found in %s", fqn)
        except Exception as exc:
            logging.error("IPAnalyze: failed to import %s: %s", fqn, exc)

    return plugins


def save_registry(plugins: List[IPAnalyzePlugin]) -> None:
    """Persist the current plugin list and enabled states to ``ipanalyze.json``."""
    entries = []
    for p in plugins:
        entries.append({
            "module": getattr(p, '_source_module', ''),
            "enabled": getattr(p, '_enabled', False),
        })
    reg_path = _registry_path()
    try:
        with open(reg_path, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        logging.error("IPAnalyze: failed to save registry %s: %s", reg_path, exc)
