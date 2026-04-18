"""
Dev/Test IPAnalyze plugin.

A diagnostic plugin that simulates various IPAnalyze outcomes so the
application's alert pipeline and UI can be exercised without a live
threat-intelligence source.

Configuration (``dev_test_plugin.json`` in the ``ipanalyze/`` dir)::

    {
      "simulate_failure": "Disabled"
    }

**simulate_failure** options:

* ``Disabled``                  — returns not found, status ``True``.
* ``Return suspicious IP found`` — returns found, status ``True``.
* ``Return plugin Failed``     — returns status ``False`` with failure info.
* ``Loop through all modes``   — cycles through the three modes above on
  each successive ``check_ip`` call.
"""

from __future__ import annotations

import logging
import os
import random
import threading

from ipanalyze import IPAnalyzePlugin, IPAnalyzeResult

_MODES = [
    "Disabled",
    "Return suspicious IP found",
    "Return plugin Failed",
    "Loop through all modes",
    "Random",
]

_DEFAULT_CONFIG = {
    "simulate_failure": "Disabled",
    "failure_rate_percent": 1,
}


class DevTestPlugin(IPAnalyzePlugin):
    """Simulates various check_ip outcomes for testing."""

    def __init__(self):
        super().__init__()
        self._loop_index = 0
        self._loop_lock = threading.Lock()
        self._random_toggle = False  # alternates between suspicious and failed

    # ------------------------------------------------------------------
    # IPAnalyzePlugin interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "Dev Test Plugin"

    @property
    def description(self) -> str:
        return "Diagnostic plugin that simulates success, suspicious-IP, or failure outcomes."

    def check_ip(self, ip_address: str) -> IPAnalyzeResult:
        cfg = self.load_config()
        mode = cfg.get("simulate_failure", "Disabled")

        if mode == "Loop through all modes":
            with self._loop_lock:
                # Cycle through the first three modes (Disabled, Found, Failed)
                effective_mode = _MODES[self._loop_index % 3]
                self._loop_index += 1
        elif mode == "Random":
            rate = cfg.get("failure_rate_percent", 1)
            if random.randint(1, 100) <= rate:
                # Alternate between suspicious and failed each time
                with self._loop_lock:
                    if self._random_toggle:
                        effective_mode = "Return plugin Failed"
                    else:
                        effective_mode = "Return suspicious IP found"
                    self._random_toggle = not self._random_toggle
            else:
                effective_mode = "Disabled"
        else:
            effective_mode = mode

        return self._execute_mode(effective_mode, ip_address)

    # ------------------------------------------------------------------
    # Settings dialog
    # ------------------------------------------------------------------

    def show_settings_dialog(self, parent) -> None:
        from PySide6.QtWidgets import (
            QComboBox, QDialog, QDialogButtonBox, QFormLayout,
            QSpinBox,
        )

        cfg = self.load_config()
        if not cfg:
            cfg = dict(_DEFAULT_CONFIG)

        dialog = QDialog(parent)
        dialog.setWindowTitle(f"{self.name} \u2014 Settings")
        dialog.setMinimumWidth(400)

        layout = QFormLayout(dialog)

        combo = QComboBox()
        combo.addItems(_MODES)
        current = cfg.get("simulate_failure", "Disabled")
        idx = combo.findText(current)
        if idx >= 0:
            combo.setCurrentIndex(idx)
        layout.addRow("Simulate failure:", combo)

        # Failure-rate spinner (visible only when "Random" is selected)
        rate_spin = QSpinBox()
        rate_spin.setRange(1, 100)
        rate_spin.setSingleStep(1)
        rate_spin.setSuffix("%")
        rate_spin.setValue(int(cfg.get("failure_rate_percent", 1)))
        layout.addRow("Failure rate (%):", rate_spin)

        def _toggle_rate_visibility():
            visible = combo.currentText() == "Random"
            layout.setRowVisible(rate_spin, visible)

        combo.currentTextChanged.connect(lambda _: _toggle_rate_visibility())
        _toggle_rate_visibility()

        btn_box = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel
        )
        layout.addRow(btn_box)
        btn_box.rejected.connect(dialog.reject)

        def _on_save():
            dialog.accept()

        btn_box.accepted.connect(_on_save)

        if dialog.exec() == QDialog.Accepted:
            cfg["simulate_failure"] = combo.currentText()
            cfg["failure_rate_percent"] = rate_spin.value()
            self.save_config(cfg)
            logging.info("DevTestPlugin: saved simulate_failure = %s, failure_rate_percent = %d",
                         cfg["simulate_failure"], cfg["failure_rate_percent"])

    # ------------------------------------------------------------------
    # get_settings (for the generic settings table)
    # ------------------------------------------------------------------

    def get_settings(self):
        cfg = self.load_config()
        if not cfg:
            cfg = dict(_DEFAULT_CONFIG)
        return {
            "simulate_failure": {
                "value": cfg.get("simulate_failure", "Disabled"),
                "type": "str",
                "description": "Simulation mode: Disabled | Return suspicious IP found | Return plugin Failed | Loop through all modes | Random",
            },
            "failure_rate_percent": {
                "value": cfg.get("failure_rate_percent", 1),
                "type": "int",
                "description": "Failure rate (1-100%) used when mode is Random",
            },
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _execute_mode(mode: str, ip_address: str) -> IPAnalyzeResult:
        if mode == "Return suspicious IP found":
            return IPAnalyzeResult(
                found=True,
                plugin_name="Dev Test Plugin",
                additional_information=f"Simulated suspicious IP: {ip_address}",
                status=True,
            )
        elif mode == "Return plugin Failed":
            return IPAnalyzeResult(
                found=False,
                plugin_name="Dev Test Plugin",
                additional_information="Failed on purpose",
                status=False,
            )
        else:
            # Disabled — clean pass
            return IPAnalyzeResult(
                found=False,
                plugin_name="Dev Test Plugin",
                additional_information="",
                status=True,
            )
