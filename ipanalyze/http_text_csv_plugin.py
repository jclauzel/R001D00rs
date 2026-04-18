"""
Http text/CSV IPAnalyze plugin.

Downloads one or more text/CSV files from configurable HTTP URLs, caches
them on disk with a per-source TTL, and checks whether an IP address
appears in any of them.

Configuration (``http_text_csv_plugin.json`` in the ``ipanalyze/`` dir)::

    {
      "sources": [
        {
          "url": "https://example.com/blocklist.txt",
          "description": "Example blocklist",
          "ttl_seconds": 86400,
          "format": "text",
          "csv_ip_column": 0,
          "enabled": true
        }
      ]
    }

Supported formats:
    - ``text`` (default): one IP per line, comments (#, //) are stripped.
    - ``csv``: the IP is extracted from the column index given by
      ``csv_ip_column`` (0-based, default 0).

Each source file is downloaded into ``ipanalyze/cache/`` and refreshed
when its TTL expires.  Multiple sources are checked in parallel using
``concurrent.futures.ThreadPoolExecutor``.

Parsed IP sets are kept in an in-memory cache keyed by content-hash and
protected by ``functools.lru_cache`` for fast repeat lookups within
the same download cycle.
"""

from __future__ import annotations

import csv as _csv_mod
import functools
import hashlib
import io
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, FrozenSet, List, Tuple

from ipanalyze import IPAnalyzePlugin, IPAnalyzeResult

_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")

_DEFAULT_CONFIG = {
    "sources": [
        {
            "url": "",
            "description": "Add a URL to a text/CSV IP blocklist",
            "ttl_seconds": 86400,
            "format": "text",
            "csv_ip_column": 0,
            "enabled": False,
        }
    ]
}


# ---------------------------------------------------------------------------
# Module-level LRU-cached parser keyed by (content_hash, fmt, col)
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=64)
def _parse_ip_set_cached(content_hash: str, raw_text: str,
                         fmt: str, csv_ip_column: int) -> FrozenSet[str]:
    """Parse *raw_text* into a frozenset of IP address strings.

    The result is memoised by *content_hash* (SHA-256 of the downloaded
    text).  When the TTL expires and the file is re-downloaded, a new hash
    invalidates the cache entry automatically.
    """
    ip_set: set = set()

    if fmt == "csv":
        reader = _csv_mod.reader(io.StringIO(raw_text))
        for row in reader:
            if not row:
                continue
            first_char = row[0].lstrip()
            if first_char.startswith("#") or first_char.startswith("//"):
                continue
            if csv_ip_column < len(row):
                token = row[csv_ip_column].strip()
                if "." in token or ":" in token:
                    ip_set.add(token)
    else:
        # text format: one IP per line
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            token = line.split()[0].strip()
            if "." in token or ":" in token:
                ip_set.add(token)

    return frozenset(ip_set)


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class HttpTextCsvPlugin(IPAnalyzePlugin):
    """Check IPs against one or more HTTP-hosted text/CSV blocklists."""

    # --- plugin metadata ---------------------------------------------------

    @property
    def name(self) -> str:
        return "Http text/CSV"

    @property
    def description(self) -> str:
        return (
            "Download text or CSV IP lists from HTTP URLs and check "
            "if a given IP address appears in any of them."
        )

    # --- internal state ----------------------------------------------------

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        # {url: {"text": str, "hash": str, "last_download": float, "ttl": int}}
        self._source_cache: Dict[str, dict] = {}
        self._ensure_config()

    def _ensure_config(self):
        """Create the default config file if it does not exist."""
        if not os.path.exists(self._config_path()):
            self.save_config(_DEFAULT_CONFIG)

    # --- IPAnalyzePlugin interface -----------------------------------------

    def check_ip(self, ip_address: str) -> IPAnalyzeResult:
        """Return *found=True* if *ip_address* is in any enabled source.

        Enabled sources are checked in parallel via ThreadPoolExecutor.
        """
        try:
            cfg = self.load_config()
            sources = cfg.get("sources", [])
            enabled_sources = [
                s for s in sources
                if s.get("enabled", False) and s.get("url", "").strip()
            ]
            if not enabled_sources:
                return IPAnalyzeResult(found=False, plugin_name=self.name)

            found_sources: List[str] = []
            source_errors: List[str] = []

            def _check_source(src):
                url = src["url"].strip()
                ttl = int(src.get("ttl_seconds", 86400))
                fmt = src.get("format", "text").lower()
                col = int(src.get("csv_ip_column", 0))
                desc = src.get("description", url) or url
                ip_set = self._get_ip_set(url, ttl, fmt, col)
                if ip_address in ip_set:
                    return desc
                return None

            workers = min(len(enabled_sources), 8)
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(_check_source, s): s
                    for s in enabled_sources
                }
                for future in as_completed(futures):
                    try:
                        result = future.result(timeout=60)
                        if result:
                            found_sources.append(result)
                    except Exception as exc:
                        src = futures[future]
                        source_errors.append(
                            f"{src.get('url', '?')}: {exc}"
                        )
                        logging.debug(
                            "HttpTextCsvPlugin: source check failed for %s: %s",
                            src.get("url", "?"), exc,
                        )

            if source_errors:
                return IPAnalyzeResult(
                    found=bool(found_sources),
                    plugin_name=self.name,
                    additional_information="; ".join(source_errors),
                    status=False,
                )

            if found_sources:
                return IPAnalyzeResult(
                    found=True,
                    plugin_name=self.name,
                    additional_information="; ".join(found_sources),
                )
            return IPAnalyzeResult(found=False, plugin_name=self.name)
        except Exception as exc:
            logging.error(
                "HttpTextCsvPlugin: executor error for %s: %s",
                ip_address, exc,
            )
            return IPAnalyzeResult(
                found=False,
                plugin_name=self.name,
                additional_information=f"Plugin failed: {exc}",
                status=False,
            )

    # --- settings (programmatic accessor) ----------------------------------

    def get_settings(self) -> Dict[str, dict]:
        """Return a flat dict of settings for non-UI consumers."""
        cfg = self.load_config()
        out: Dict[str, dict] = {}
        for i, src in enumerate(cfg.get("sources", [])):
            prefix = f"source_{i}"
            out[f"{prefix}_url"] = {
                "value": src.get("url", ""), "type": "str",
                "description": f"Source {i} URL",
            }
            out[f"{prefix}_description"] = {
                "value": src.get("description", ""), "type": "str",
                "description": f"Source {i} description",
            }
            out[f"{prefix}_ttl_seconds"] = {
                "value": src.get("ttl_seconds", 86400), "type": "int",
                "description": f"Source {i} cache TTL (seconds)",
            }
            out[f"{prefix}_format"] = {
                "value": src.get("format", "text"), "type": "str",
                "description": f"Source {i} format (text/csv)",
            }
            out[f"{prefix}_csv_ip_column"] = {
                "value": src.get("csv_ip_column", 0), "type": "int",
                "description": f"Source {i} CSV column index for IP",
            }
            out[f"{prefix}_enabled"] = {
                "value": src.get("enabled", False), "type": "bool",
                "description": f"Source {i} enabled",
            }
        return out

    # --- settings dialog (plugin-owned UI) ---------------------------------

    def show_settings_dialog(self, parent) -> None:
        """Build and display the Http text/CSV plugin settings dialog.

        PySide6 widgets are imported locally so the plugin module has no
        hard Qt dependency at import time.
        """
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import (
            QCheckBox, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout,
            QHeaderView, QLabel, QPushButton, QSpinBox, QTableWidget,
            QTableWidgetItem, QVBoxLayout, QWidget,
        )

        cfg = self.load_config()
        sources: list = list(cfg.get("sources", []))

        dialog = QDialog(parent)
        dialog.setWindowTitle(f"{self.name} \u2014 Settings")
        dialog.setMinimumWidth(780)
        dialog.setMinimumHeight(350)
        root_layout = QVBoxLayout(dialog)
        root_layout.addWidget(
            QLabel("Configure HTTP text/CSV blocklist sources:")
        )

        # Column indices
        COL_URL = 0
        COL_DESC = 1
        COL_TTL = 2
        COL_FMT = 3
        COL_CSVCOL = 4
        COL_ENABLED = 5
        COL_REMOVE = 6
        HEADERS = ["URL", "Description", "TTL (s)", "Format",
                    "CSV Col", "Enabled", ""]

        tbl = QTableWidget(0, len(HEADERS))
        tbl.setHorizontalHeaderLabels(HEADERS)
        tbl.horizontalHeader().setStretchLastSection(False)
        tbl.horizontalHeader().setSectionResizeMode(
            COL_URL, QHeaderView.Stretch
        )
        tbl.horizontalHeader().setSectionResizeMode(
            COL_DESC, QHeaderView.Stretch
        )
        tbl.setSelectionBehavior(QTableWidget.SelectRows)

        def _rewire_remove_buttons():
            """Re-bind every minus button to the correct row index."""
            for r in range(tbl.rowCount()):
                btn = tbl.cellWidget(r, COL_REMOVE)
                if isinstance(btn, QPushButton):
                    if btn.receivers("2clicked()") > 0:
                        btn.clicked.disconnect()
                    btn.clicked.connect(
                        lambda checked=False, rr=r: _remove_row(rr)
                    )

        def _add_source_row(src=None):
            """Append one source row to the table."""
            if src is None:
                src = {
                    "url": "", "description": "", "ttl_seconds": 86400,
                    "format": "text", "csv_ip_column": 0, "enabled": False,
                }
            row = tbl.rowCount()
            tbl.insertRow(row)

            # URL
            tbl.setItem(row, COL_URL,
                        QTableWidgetItem(src.get("url", "")))
            # Description
            tbl.setItem(row, COL_DESC,
                        QTableWidgetItem(src.get("description", "")))
            # TTL spinbox
            ttl_spin = QSpinBox()
            ttl_spin.setRange(60, 999999999)
            ttl_spin.setValue(int(src.get("ttl_seconds", 86400)))
            ttl_spin.setSuffix(" s")
            tbl.setCellWidget(row, COL_TTL, ttl_spin)
            # Format combo
            fmt_combo = QComboBox()
            fmt_combo.addItems(["text", "csv"])
            fmt_combo.setCurrentText(
                src.get("format", "text").lower()
            )
            tbl.setCellWidget(row, COL_FMT, fmt_combo)
            # CSV column spinbox
            csv_col_spin = QSpinBox()
            csv_col_spin.setRange(0, 999)
            csv_col_spin.setValue(int(src.get("csv_ip_column", 0)))
            tbl.setCellWidget(row, COL_CSVCOL, csv_col_spin)
            # Enabled checkbox (centred in cell)
            chk = QCheckBox()
            chk.setChecked(bool(src.get("enabled", False)))
            chk_container = QWidget()
            chk_layout = QHBoxLayout(chk_container)
            chk_layout.addWidget(chk)
            chk_layout.setAlignment(Qt.AlignCenter)
            chk_layout.setContentsMargins(0, 0, 0, 0)
            tbl.setCellWidget(row, COL_ENABLED, chk_container)
            # Remove button
            remove_btn = QPushButton("\u2212")
            remove_btn.setFixedWidth(28)
            remove_btn.setToolTip("Remove this source")
            tbl.setCellWidget(row, COL_REMOVE, remove_btn)

            _rewire_remove_buttons()

        def _remove_row(row_idx: int):
            """Remove a source row and re-wire button indices."""
            tbl.removeRow(row_idx)
            _rewire_remove_buttons()

        # Populate existing sources
        for src in sources:
            _add_source_row(src)

        root_layout.addWidget(tbl)

        # "+ Add source" button
        add_btn = QPushButton("+ Add source")
        add_btn.clicked.connect(lambda: _add_source_row())
        root_layout.addWidget(add_btn)

        # Save / Cancel
        btn_box = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel
        )
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        root_layout.addWidget(btn_box)

        if dialog.exec() == QDialog.Accepted:
            new_sources = []
            for r in range(tbl.rowCount()):
                url_item = tbl.item(r, COL_URL)
                desc_item = tbl.item(r, COL_DESC)
                ttl_w = tbl.cellWidget(r, COL_TTL)
                fmt_w = tbl.cellWidget(r, COL_FMT)
                csv_w = tbl.cellWidget(r, COL_CSVCOL)
                chk_cont = tbl.cellWidget(r, COL_ENABLED)

                url_val = url_item.text().strip() if url_item else ""
                desc_val = desc_item.text().strip() if desc_item else ""
                ttl_val = (ttl_w.value()
                           if isinstance(ttl_w, QSpinBox) else 86400)
                fmt_val = (fmt_w.currentText()
                           if isinstance(fmt_w, QComboBox) else "text")
                csv_col_val = (csv_w.value()
                               if isinstance(csv_w, QSpinBox) else 0)
                enabled_val = False
                if chk_cont is not None:
                    chk_widget = chk_cont.findChild(QCheckBox)
                    if chk_widget is not None:
                        enabled_val = chk_widget.isChecked()

                new_sources.append({
                    "url": url_val,
                    "description": desc_val,
                    "ttl_seconds": ttl_val,
                    "format": fmt_val,
                    "csv_ip_column": csv_col_val,
                    "enabled": enabled_val,
                })
            cfg["sources"] = new_sources
            self.save_config(cfg)
            # Invalidate memory caches so new config takes effect
            self._source_cache.clear()
            _parse_ip_set_cached.cache_clear()

    # --- download / cache --------------------------------------------------

    def _url_hash(self, url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()[:16]

    def _cache_path(self, url: str) -> str:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        return os.path.join(_CACHE_DIR, f"{self._url_hash(url)}.txt")

    def _get_ip_set(self, url: str, ttl: int,
                    fmt: str, csv_ip_column: int) -> FrozenSet[str]:
        """Return the cached IP set for *url*, downloading if stale."""
        with self._lock:
            cached = self._source_cache.get(url)
            now = time.time()
            if cached and (now - cached["last_download"]) < ttl:
                return _parse_ip_set_cached(
                    cached["hash"], cached["text"], fmt, csv_ip_column,
                )

        # Outside lock: download can be slow
        raw_text, content_hash = self._download(url)

        with self._lock:
            self._source_cache[url] = {
                "text": raw_text,
                "hash": content_hash,
                "last_download": time.time(),
                "ttl": ttl,
            }

        return _parse_ip_set_cached(
            content_hash, raw_text, fmt, csv_ip_column,
        )

    def _download(self, url: str) -> Tuple[str, str]:
        """Download *url* and return ``(raw_text, sha256_hex[:32])``."""
        cache_file = self._cache_path(url)
        raw_text = ""

        try:
            import requests
            logging.info("HttpTextCsvPlugin: downloading %s", url)
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            raw_text = resp.text

            # Persist to disk cache
            with open(cache_file, "w", encoding="utf-8") as f:
                f.write(raw_text)

        except Exception as exc:
            logging.warning(
                "HttpTextCsvPlugin: download failed for %s: %s", url, exc,
            )
            if os.path.exists(cache_file):
                logging.info(
                    "HttpTextCsvPlugin: using on-disk cache for %s", url,
                )
                with open(cache_file, "r", encoding="utf-8") as f:
                    raw_text = f.read()

        content_hash = hashlib.sha256(raw_text.encode()).hexdigest()[:32]
        return raw_text, content_hash
