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
_CUSTOM_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "custom_files")

_DEFAULT_CONFIG = {
    "sources": [
        {
            "source_type": "http",
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
                source_type = src.get("source_type", "http")
                if source_type == "file":
                    ip_set = self._get_file_ip_set(url, fmt, col)
                else:
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
            QHeaderView, QLabel, QMessageBox, QPushButton, QSpinBox,
            QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
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
        COL_SOURCE = 0
        COL_LOCATION = 1
        COL_DESC = 2
        COL_TTL = 3
        COL_FMT = 4
        COL_CSVCOL = 5
        COL_ENABLED = 6
        COL_REACHABLE = 7
        COL_REMOVE = 8
        HEADERS = ["Source", "Location", "Description", "TTL (s)", "Format",
                    "CSV Col", "Enabled", "Reachable", ""]

        tbl = QTableWidget(0, len(HEADERS))
        tbl.setHorizontalHeaderLabels(HEADERS)
        tbl.horizontalHeader().setStretchLastSection(False)
        tbl.horizontalHeader().setSectionResizeMode(
            COL_LOCATION, QHeaderView.Stretch
        )
        tbl.horizontalHeader().setSectionResizeMode(
            COL_DESC, QHeaderView.Stretch
        )
        tbl.setSelectionBehavior(QTableWidget.SelectRows)

        # Ensure custom_files directory exists
        os.makedirs(_CUSTOM_FILES_DIR, exist_ok=True)

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

        def _validate_location(row: int):
            """Validate the location for the given row based on source type."""
            source_combo = tbl.cellWidget(row, COL_SOURCE)
            loc_item = tbl.item(row, COL_LOCATION)
            if source_combo is None or loc_item is None:
                return
            location = loc_item.text().strip()
            if not location:
                _set_reachable(row, None)
                return
            source_type = source_combo.currentText()
            if source_type == "Http download":
                _try_download_url(location, row)
            else:
                _try_check_file(location, row)

        def _try_download_url(url: str, row: int):
            """Attempt to download *url* and update the Reachable column."""
            try:
                import requests
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                # Cache on disk
                cache_file = self._cache_path(url)
                os.makedirs(_CACHE_DIR, exist_ok=True)
                with open(cache_file, "w", encoding="utf-8") as f:
                    f.write(resp.text)
                _set_reachable(row, True)
            except Exception as exc:
                _set_reachable(row, False)
                QMessageBox.warning(
                    dialog,
                    "Download failed",
                    f"Could not download:\n{url}\n\n"
                    f"Error: {exc}\n\n"
                    "Please check the URL and try again.",
                )

        def _try_check_file(filename: str, row: int):
            """Check if the file exists under custom_files."""
            filepath = os.path.join(_CUSTOM_FILES_DIR, filename)
            if os.path.isfile(filepath):
                _set_reachable(row, True)
            else:
                _set_reachable(row, False)
                QMessageBox.warning(
                    dialog,
                    "File not found",
                    f"Could not find file:\n{filepath}\n\n"
                    f"Please place the file in the 'ipanalyze/custom_files/' folder.",
                )

        def _set_reachable(row: int, reachable):
            """Update the Reachable cell for *row*."""
            if reachable is None:
                item = QTableWidgetItem("")
            elif reachable:
                item = QTableWidgetItem("\u2714 Reachable")
            else:
                item = QTableWidgetItem("\u2716 Unreachable")
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            tbl.setItem(row, COL_REACHABLE, item)

        def _update_csv_col_state(row: int, fmt_combo: QComboBox):
            """Enable/disable the CSV col spinbox based on format."""
            csv_spin = tbl.cellWidget(row, COL_CSVCOL)
            if isinstance(csv_spin, QSpinBox):
                csv_spin.setEnabled(fmt_combo.currentText() == "csv")

        def _on_location_changed(item):
            """When the Location cell is edited, validate it."""
            if item is None:
                return
            if item.column() == COL_LOCATION:
                _validate_location(item.row())

        tbl.itemChanged.connect(_on_location_changed)

        def _on_source_type_changed(row: int):
            """Reset reachable when source type changes and re-validate."""
            _set_reachable(row, None)
            loc_item = tbl.item(row, COL_LOCATION)
            if loc_item and loc_item.text().strip():
                _validate_location(row)

        def _add_source_row(src=None):
            """Append one source row to the table."""
            if src is None:
                src = {
                    "source_type": "http", "url": "",
                    "description": "", "ttl_seconds": 86400,
                    "format": "text", "csv_ip_column": 0, "enabled": False,
                }
            row = tbl.rowCount()
            tbl.insertRow(row)

            # Source type combo
            source_combo = QComboBox()
            source_combo.addItems(["Http download", "File"])
            src_type = src.get("source_type", "http")
            source_combo.setCurrentText(
                "File" if src_type == "file" else "Http download"
            )
            tbl.setCellWidget(row, COL_SOURCE, source_combo)
            source_combo.currentTextChanged.connect(
                lambda _txt, r=row: _on_source_type_changed(r)
            )
            # Location (URL or filename)
            tbl.setItem(row, COL_LOCATION,
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
            csv_col_spin.setEnabled(fmt_combo.currentText() == "csv")
            tbl.setCellWidget(row, COL_CSVCOL, csv_col_spin)
            # Wire format combo to toggle CSV col
            fmt_combo.currentTextChanged.connect(
                lambda _txt, r=row, fc=fmt_combo: _update_csv_col_state(r, fc)
            )
            # Enabled checkbox (centred in cell)
            chk = QCheckBox()
            chk.setChecked(bool(src.get("enabled", False)))
            chk_container = QWidget()
            chk_layout = QHBoxLayout(chk_container)
            chk_layout.addWidget(chk)
            chk_layout.setAlignment(Qt.AlignCenter)
            chk_layout.setContentsMargins(0, 0, 0, 0)
            tbl.setCellWidget(row, COL_ENABLED, chk_container)
            # Reachable indicator (read-only)
            loc_val = src.get("url", "").strip()
            if loc_val:
                _set_reachable(row, True)  # assume previously saved are reachable
            else:
                _set_reachable(row, None)
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

        def _on_save():
            """Validate reachability before accepting."""
            for r in range(tbl.rowCount()):
                loc_item = tbl.item(r, COL_LOCATION)
                loc_val = loc_item.text().strip() if loc_item else ""
                if not loc_val:
                    continue
                reach_item = tbl.item(r, COL_REACHABLE)
                reach_text = reach_item.text() if reach_item else ""
                if "\u2714" not in reach_text:
                    QMessageBox.warning(
                        dialog,
                        "Cannot save",
                        f"Row {r + 1} source is not reachable.\n"
                        "Please fix or remove unreachable sources before saving.",
                    )
                    return
            dialog.accept()

        btn_box.accepted.connect(_on_save)
        btn_box.rejected.connect(dialog.reject)
        root_layout.addWidget(btn_box)

        if dialog.exec() == QDialog.Accepted:
            new_sources = []
            for r in range(tbl.rowCount()):
                source_w = tbl.cellWidget(r, COL_SOURCE)
                loc_item = tbl.item(r, COL_LOCATION)
                desc_item = tbl.item(r, COL_DESC)
                ttl_w = tbl.cellWidget(r, COL_TTL)
                fmt_w = tbl.cellWidget(r, COL_FMT)
                csv_w = tbl.cellWidget(r, COL_CSVCOL)
                chk_cont = tbl.cellWidget(r, COL_ENABLED)

                source_type_val = "http"
                if isinstance(source_w, QComboBox):
                    source_type_val = (
                        "file" if source_w.currentText() == "File"
                        else "http"
                    )
                loc_val = loc_item.text().strip() if loc_item else ""
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
                    "source_type": source_type_val,
                    "url": loc_val,
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
        """Download *url* with up to 3 retries.

        Returns ``(raw_text, sha256_hex[:32])``.
        Raises ``RuntimeError`` if all retries fail and no disk cache exists.
        """
        import requests

        cache_file = self._cache_path(url)
        last_exc = None

        for attempt in range(1, 4):
            try:
                logging.info(
                    "HttpTextCsvPlugin: downloading %s (attempt %d/3)",
                    url, attempt,
                )
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                raw_text = resp.text

                # Persist to disk cache
                with open(cache_file, "w", encoding="utf-8") as f:
                    f.write(raw_text)

                content_hash = hashlib.sha256(
                    raw_text.encode()
                ).hexdigest()[:32]
                return raw_text, content_hash
            except Exception as exc:
                last_exc = exc
                logging.warning(
                    "HttpTextCsvPlugin: download attempt %d failed for %s: %s",
                    attempt, url, exc,
                )
                if attempt < 3:
                    time.sleep(2 * attempt)

        # All 3 retries failed — try disk cache as last resort
        if os.path.exists(cache_file):
            logging.info(
                "HttpTextCsvPlugin: using on-disk cache for %s after 3 failures",
                url,
            )
            with open(cache_file, "r", encoding="utf-8") as f:
                raw_text = f.read()
            content_hash = hashlib.sha256(raw_text.encode()).hexdigest()[:32]
            return raw_text, content_hash

        # No cache, no successful download — raise to signal plugin failure
        raise RuntimeError(
            f"Failed to download {url} after 3 retries: {last_exc}"
        )

    def _get_file_ip_set(self, filename: str,
                         fmt: str, csv_ip_column: int) -> FrozenSet[str]:
        """Return the IP set parsed from a local file in custom_files/.

        Always re-reads the file (no TTL caching) so edits are picked up
        immediately.  Raises ``FileNotFoundError`` if the file is missing.
        """
        filepath = os.path.join(_CUSTOM_FILES_DIR, filename)
        if not os.path.isfile(filepath):
            raise FileNotFoundError(
                f"Custom file not found: {filepath}"
            )

        with open(filepath, "r", encoding="utf-8") as f:
            raw_text = f.read()

        content_hash = hashlib.sha256(raw_text.encode()).hexdigest()[:32]
        return _parse_ip_set_cached(content_hash, raw_text, fmt, csv_ip_column)
