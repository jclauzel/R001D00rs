"""
PiHole IPAnalyze plugin.

Queries a configured Pi-hole DNS server to determine whether an IP address
is blocked.  The check works by performing a reverse-DNS lookup (PTR) for
the IP through the Pi-hole DNS resolver using a lightweight UDP DNS query
built with the standard library (no third-party packages required).

If the query is refused, times out, or the connection is reset, the IP is
considered **found** (blocked by Pi-hole).

Configuration (``pihole_plugin.json`` in the ``ipanalyze/`` dir)::

    {
      "dns_server": "pi.hole",
      "dns_port": 53,
      "timeout_seconds": 3,
      "description": "Pi-hole DNS sinkhole check"
    }
"""

from __future__ import annotations

import functools
import logging
import os
import random
import socket
import struct
import time
from typing import Dict

from ipanalyze import IPAnalyzePlugin, IPAnalyzeResult

_DEFAULT_CONFIG = {
    "dns_server": "pi.hole",
    "dns_port": 53,
    "timeout_seconds": 3,
    "description": "Pi-hole DNS check",
}


def _build_a_query(hostname: str) -> bytes:
    """Build a raw DNS A-record query packet for *hostname*."""
    txn_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)
    qname = b""
    for label in hostname.rstrip(".").split("."):
        qname += struct.pack("B", len(label)) + label.encode("ascii")
    qname += b"\x00"
    qtype = 1   # A
    qclass = 1  # IN
    return header + qname + struct.pack("!HH", qtype, qclass)


def _test_dns_server(dns_server: str, dns_port: int,
                     timeout: float) -> tuple[bool, str]:
    """Test DNS server reachability by resolving ``dns.google`` (A record).

    Returns ``(reachable, error_msg)``.  On success *error_msg* is empty.
    """
    try:
        packet = _build_a_query("dns.google")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (dns_server, dns_port))
            data, _ = sock.recvfrom(1024)
        finally:
            sock.close()
        if len(data) < 12:
            return False, "Invalid DNS response (too short)"
        flags = struct.unpack("!H", data[2:4])[0]
        rcode = flags & 0x0F
        if rcode != 0:
            return False, f"DNS response code {rcode}"
        return True, ""
    except (socket.timeout, TimeoutError):
        return False, "Connection timed out"
    except socket.gaierror as exc:
        return False, f"Cannot resolve DNS server address: {exc}"
    except (ConnectionResetError, ConnectionRefusedError, OSError) as exc:
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)


def _build_ptr_query(ip_address: str) -> tuple[bytes, str]:
    """Build a raw DNS PTR query packet for *ip_address*.

    Returns ``(packet_bytes, ptr_name)`` where *ptr_name* is the
    ``x.x.x.x.in-addr.arpa`` name used in the query.
    """
    parts = ip_address.split(".")
    rev = ".".join(reversed(parts)) + ".in-addr.arpa"
    txn_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)
    qname = b""
    for label in rev.split("."):
        qname += struct.pack("B", len(label)) + label.encode("ascii")
    qname += b"\x00"
    qtype = 12  # PTR
    qclass = 1  # IN
    question = qname + struct.pack("!HH", qtype, qclass)
    return header + question, rev


def _parse_ptr_response(data: bytes) -> tuple[int, str | None]:
    """Parse a DNS response and return ``(rcode, ptr_name | None)``.

    *rcode* is the response code from the DNS header (0 = NOERROR,
    3 = NXDOMAIN, 5 = REFUSED, etc.).
    """
    if len(data) < 12:
        return -1, None
    _, flags, _, ancount = struct.unpack("!HHHH", data[:8])
    rcode = flags & 0x0F

    if ancount == 0 or rcode != 0:
        return rcode, None

    # Skip the question section
    offset = 12
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1 + 4  # null label + QTYPE(2) + QCLASS(2)
            break
        if (length & 0xC0) == 0xC0:
            offset += 2 + 4
            break
        offset += 1 + length
    else:
        return rcode, None

    # Read the first answer RR
    if offset + 12 > len(data):
        return rcode, None

    # Skip answer NAME (may be pointer)
    if (data[offset] & 0xC0) == 0xC0:
        offset += 2
    else:
        while offset < len(data) and data[offset] != 0:
            offset += 1 + data[offset]
        offset += 1

    if offset + 10 > len(data):
        return rcode, None

    rr_type, _, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10

    if rr_type != 12 or offset + rdlength > len(data):
        return rcode, None

    # Decode the PTR domain name from rdata
    labels: list[str] = []
    end = offset + rdlength
    while offset < end:
        length = data[offset]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            ptr_offset = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = ptr_offset
            end = len(data)
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    return rcode, ".".join(labels) if labels else None


# Module-level LRU cache for DNS results.
# Keyed by (dns_server, dns_port, ip_address, cache_epoch).
# cache_epoch is time.time() // 60 so entries auto-expire every 60 s.

def _perform_dns_query(dns_server: str, dns_port: int, timeout: float,
                       ip_address: str) -> tuple[int, str | None]:
    """Perform a single DNS PTR query. Returns (rcode, ptr_name | None).
    Raises socket.timeout, socket.gaierror, or OSError on failure."""
    packet, _rev = _build_ptr_query(ip_address)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (dns_server, dns_port))
        data, _ = sock.recvfrom(1024)
    finally:
        sock.close()
    return _parse_ptr_response(data)


@functools.lru_cache(maxsize=1024)
def _dns_check_cached(dns_server: str, dns_port: int, timeout: float,
                      ip_address: str, cache_epoch: int,
                      suspicious_flags: tuple = ("refused",),
                      timeout_strategy: str = "fail"):
    """Perform the actual DNS check.  Returns (found: bool, detail: str)."""
    # Determine retry parameters based on strategy
    if timeout_strategy == "retry_immediate":
        max_attempts = 3
        retry_pause = 0
    elif timeout_strategy == "retry_with_pause":
        max_attempts = 3
        retry_pause = 1.0
    else:  # "fail"
        max_attempts = 1
        retry_pause = 0

    last_exception = None
    for attempt in range(max_attempts):
        if attempt > 0 and retry_pause > 0:
            time.sleep(retry_pause)
        try:
            rcode, ptr_name = _perform_dns_query(dns_server, dns_port, timeout, ip_address)

            # NXDOMAIN (3) = normal "no PTR record", NOT a Pi-hole block
            if rcode == 3:
                return False, ""

            # REFUSED (5)
            if rcode == 5 and "refused" in suspicious_flags:
                return True, f"Pi-hole ({dns_server}): DNS rcode {rcode} (REFUSED)"

            # SERVFAIL (2)
            if rcode == 2 and "servfail" in suspicious_flags:
                return True, f"Pi-hole ({dns_server}): DNS rcode {rcode} (SERVFAIL)"

            # NOERROR with a PTR answer means the name resolved normally
            if rcode == 0 and ptr_name:
                return False, f"DNS resolved: {ptr_name}"

            # NOERROR but no answer data
            if "empty_response" in suspicious_flags:
                return True, f"Pi-hole ({dns_server}): empty DNS response"

            return False, ""

        except (socket.timeout, TimeoutError) as exc:
            last_exception = exc
            if attempt < max_attempts - 1:
                continue  # retry
            # final attempt — whether it is suspicious depends on the flag
            if "timeout" in suspicious_flags:
                return True, f"Pi-hole ({dns_server}): timeout (tried {max_attempts}x)"
            return False, f"Pi-hole ({dns_server}): timeout (not flagged)"
        except (ConnectionResetError, ConnectionRefusedError, OSError) as exc:
            return True, f"Pi-hole ({dns_server}): {type(exc).__name__}"
        except Exception as exc:
            logging.error("PiHolePlugin: unexpected error checking %s: %s",
                          ip_address, exc)
            return False, f"Error: {exc}"

    # Should not reach here — treat same as timeout flag
    if "timeout" in suspicious_flags:
        return True, f"Pi-hole ({dns_server}): timeout"
    return False, f"Pi-hole ({dns_server}): timeout (not flagged)"


class PiHolePlugin(IPAnalyzePlugin):
    """Check IPs against a Pi-hole DNS sinkhole."""

    # --- plugin metadata ---------------------------------------------------

    @property
    def name(self) -> str:
        return "PiHole"

    @property
    def description(self) -> str:
        return (
            "Query a Pi-hole DNS server and flag the IP if the DNS "
            "response is empty or the connection is refused/reset."
        )

    # --- init --------------------------------------------------------------

    def __init__(self):
        super().__init__()
        self._ensure_config()
        self._first_check_time: float | None = None  # set on first check_ip call

    def _ensure_config(self):
        if not os.path.exists(self._config_path()):
            self.save_config(_DEFAULT_CONFIG)

    # --- IPAnalyzePlugin interface -----------------------------------------

    def check_ip(self, ip_address: str) -> IPAnalyzeResult:
        """Perform a DNS lookup for *ip_address* via the configured Pi-hole."""
        try:
            cfg = self.load_config()
            dns_server = cfg.get("dns_server", "pi.hole").strip()
            dns_port = int(cfg.get("dns_port", 53))
            timeout = float(cfg.get("timeout_seconds", 3))

            if not dns_server:
                return IPAnalyzeResult(found=False, plugin_name=self.name,
                                       additional_information="No DNS server configured",
                                       status=False)

            # Migrate legacy string config to list format
            raw_sus = cfg.get("suspicious_flags", cfg.get("suspicious_rcodes", ["refused"]))
            if isinstance(raw_sus, str):
                # migrate old values
                if raw_sus == "refused_and_servfail":
                    raw_sus = ["refused", "servfail"]
                else:
                    raw_sus = ["refused"]
            suspicious_flags = tuple(sorted(raw_sus))

            timeout_strategy = cfg.get("timeout_strategy", "fail")

            # --- Progressive plugin start ------------------------------------
            warmup_str = cfg.get("progressive_start", "5")
            if warmup_str != "disabled":
                try:
                    warmup_minutes = int(warmup_str)
                except (ValueError, TypeError):
                    warmup_minutes = 5
                now = time.time()
                if self._first_check_time is None:
                    self._first_check_time = now
                elapsed = now - self._first_check_time
                warmup_seconds = warmup_minutes * 60
                if elapsed < warmup_seconds:
                    # fraction of queries to actually send: ramps 0 → 1 linearly
                    fraction = elapsed / warmup_seconds
                    if random.random() > fraction:
                        # Skip this query — return clean result so no alert is raised
                        return IPAnalyzeResult(
                            found=False, plugin_name=self.name,
                            additional_information="",
                        )
            # -----------------------------------------------------------------

            # cache_epoch flips every 60 s so stale entries expire automatically
            cache_epoch = int(time.time()) // 60
            found, detail = _dns_check_cached(
                dns_server, dns_port, timeout, ip_address, cache_epoch,
                suspicious_flags, timeout_strategy,
            )
            return IPAnalyzeResult(
                found=found, plugin_name=self.name,
                additional_information=detail,
            )
        except Exception as exc:
            logging.error("PiHolePlugin: failed for %s: %s", ip_address, exc)
            return IPAnalyzeResult(
                found=False, plugin_name=self.name,
                additional_information=f"Plugin failed: {exc}",
                status=False,
            )

    # --- settings (programmatic accessor) ----------------------------------

    def get_settings(self) -> Dict[str, dict]:
        cfg = self.load_config()
        return {
            "dns_server": {
                "value": cfg.get("dns_server", "pi.hole"),
                "type": "str",
                "description": "Pi-hole DNS server IP address",
            },
            "dns_port": {
                "value": cfg.get("dns_port", 53),
                "type": "int",
                "description": "DNS server port",
            },
            "timeout_seconds": {
                "value": cfg.get("timeout_seconds", 3),
                "type": "int",
                "description": "DNS query timeout (seconds)",
            },
            "description": {
                "value": cfg.get("description", "Pi-hole DNS check"),
                "type": "str",
                "description": "Plugin description",
            },
            "suspicious_flags": {
                "value": cfg.get("suspicious_flags", ["refused"]),
                "type": "multi_check",
                "options": [
                    {"key": "refused",        "label": "REFUSED (5)"},
                    {"key": "servfail",       "label": "SERVFAIL (2)"},
                    {"key": "empty_response", "label": "Empty DNS response"},
                    {"key": "timeout",        "label": "Timeout"},
                ],
                "description": "Consider suspicious",
            },
            "timeout_strategy": {
                "value": cfg.get("timeout_strategy", "fail"),
                "type": "choice",
                "choices": ["fail", "retry_immediate", "retry_with_pause"],
                "labels": ["Fail", "Retry immediately 3 times", "Retry immediately 3 times with a pause of one second"],
                "description": "On DNS timeout",
            },
            "progressive_start": {
                "value": cfg.get("progressive_start", "5"),
                "type": "choice",
                "choices": ["5", "10", "30", "disabled"],
                "labels": ["5 minutes", "10 minutes", "30 minutes", "Disabled"],
                "description": "Progressive plugin start",
            },
        }

    # --- settings dialog (plugin-owned UI) ---------------------------------

    def show_settings_dialog(self, parent) -> None:
        """Build and display the PiHole plugin settings dialog.

        PySide6 widgets are imported locally so the plugin module has no
        hard Qt dependency at import time.
        """
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import (
            QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QHeaderView,
            QLabel, QMessageBox, QPushButton, QTableWidget,
            QTableWidgetItem, QVBoxLayout,
        )

        settings = self.get_settings()
        if not settings:
            return

        dialog = QDialog(parent)
        dialog.setWindowTitle(f"{self.name} \u2014 Settings")
        dialog.setMinimumWidth(500)
        root_layout = QVBoxLayout(dialog)

        keys = [k for k in settings.keys() if settings[k].get("type") not in ("choice", "multi_check")]
        tbl = QTableWidget(len(keys), 3)
        tbl.setHorizontalHeaderLabels(["Setting", "Value", "Description"])
        tbl.setToolTip(
            "dns_server: hostname or IP of your Pi-hole DNS server.\n"
            "dns_port: UDP port to query (default 53).\n"
            "timeout_seconds: how long to wait for a DNS reply before timing out.\n"
            "description: a label shown in the IPAnalyze plugin table."
        )
        tbl.horizontalHeader().setStretchLastSection(True)
        tbl.setEditTriggers(QTableWidget.AllEditTriggers)

        for i, key in enumerate(keys):
            entry = settings[key]
            name_item = QTableWidgetItem(key)
            name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
            tbl.setItem(i, 0, name_item)
            tbl.setItem(i, 1, QTableWidgetItem(str(entry.get("value", ""))))
            desc_item = QTableWidgetItem(entry.get("description", ""))
            desc_item.setFlags(desc_item.flags() & ~Qt.ItemIsEditable)
            tbl.setItem(i, 2, desc_item)

        root_layout.addWidget(tbl)

        # --- "Consider suspicious" checkboxes --------------------------------
        from PySide6.QtWidgets import QCheckBox, QGroupBox
        sus_group = QGroupBox("Consider suspicious:")
        sus_group.setToolTip(
            "Select which DNS response conditions should be treated as evidence\n"
            "that an IP address is blocked or flagged by Pi-hole."
        )
        sus_layout = QVBoxLayout(sus_group)
        _sus_options = [
            ("refused",        "REFUSED (5)"),
            ("servfail",       "SERVFAIL (2)"),
            ("empty_response", "Empty DNS response"),
            ("timeout",        "Timeout"),
        ]
        _sus_tips = {
            "refused":        (
                "DNS REFUSED (rcode 5): Pi-hole actively refused the PTR query.\n"
                "This is the strongest indicator that the IP is blocked by Pi-hole.\n"
                "Recommended: keep checked."
            ),
            "servfail":       (
                "DNS SERVFAIL (rcode 2): the server encountered an internal failure.\n"
                "May indicate blocking but can also be a transient DNS server error.\n"
                "Consider enabling only if your Pi-hole consistently returns SERVFAIL\n"
                "for blocked domains rather than REFUSED."
            ),
            "empty_response": (
                "NOERROR reply with no answer records — Pi-hole returned a sinkhole\n"
                "empty response (common pattern for some blocklist configurations).\n"
                "Enable if your Pi-hole is configured to return NOERROR with no data\n"
                "instead of REFUSED for blocked IPs."
            ),
            "timeout":        (
                "DNS query timed out — no reply received within timeout_seconds.\n\n"
                "By default this is NOT checked, so timeouts are silently ignored\n"
                "and never raise alerts. This is the safest setting for slow DNS\n"
                "servers or during startup warm-up (see Progressive plugin start below).\n\n"
                "Enable only if you want unanswered queries to be treated as suspicious\n"
                "(e.g. your Pi-hole drops queries to blocked IPs instead of replying).\n"
                "Combine with 'Retry' options above to avoid false positives from\n"
                "transient network glitches."
            ),
        }
        raw_sus = self.load_config().get("suspicious_flags",
                      self.load_config().get("suspicious_rcodes", ["refused"]))
        if isinstance(raw_sus, str):
            raw_sus = ["refused", "servfail"] if raw_sus == "refused_and_servfail" else ["refused"]
        current_flags = set(raw_sus)
        sus_checks: list[tuple[str, QCheckBox]] = []
        for key, label in _sus_options:
            cb = QCheckBox(label)
            cb.setChecked(key in current_flags)
            cb.setToolTip(_sus_tips.get(key, ""))
            sus_layout.addWidget(cb)
            sus_checks.append((key, cb))
        root_layout.addWidget(sus_group)

        # --- "On DNS timeout" dropdown ----------------------------------------
        from PySide6.QtWidgets import QComboBox
        timeout_row = QHBoxLayout()
        timeout_label = QLabel("On DNS timeout:")
        timeout_label.setToolTip(
            "What to do when the Pi-hole DNS server does not reply within\n"
            "the configured timeout_seconds window."
        )
        timeout_row.addWidget(timeout_label)
        timeout_combo = QComboBox()
        timeout_combo.setToolTip(
            "Fail: report a timeout alert immediately after a single unanswered query.\n"
            "Retry immediately 3 times: repeat the query up to 3 times before reporting a timeout.\n"
            "Retry 3 times with pause: same as above but waits 1 second between each attempt."
        )
        timeout_combo.addItem("Fail", "fail")
        timeout_combo.addItem("Retry immediately 3 times", "retry_immediate")
        timeout_combo.addItem("Retry immediately 3 times with a pause of one second", "retry_with_pause")
        current_timeout = self.load_config().get("timeout_strategy", "fail")
        idx = timeout_combo.findData(current_timeout)
        if idx >= 0:
            timeout_combo.setCurrentIndex(idx)
        timeout_row.addWidget(timeout_combo)
        timeout_row.addStretch()
        root_layout.addLayout(timeout_row)

        # --- "Progressive plugin start" combo ---------------------------------
        progressive_row = QHBoxLayout()
        progressive_label = QLabel("Progressive plugin start:")
        progressive_label.setToolTip(
            "Gradually ramp up the number of DNS queries sent to Pi-hole after startup,\n"
            "allowing the DNS server to build its cache smoothly without being overwhelmed.\n\n"
            "During the warmup period, only a small fraction of queries are actually sent\n"
            "(starting near 0% and reaching 100% at the end of the selected time).\n"
            "Queries that are skipped return a clean 'not found' result so no false alerts\n"
            "are raised. Once the warmup period ends, all queries are sent normally.\n\n"
            "Set to 'Disabled' to always send every query from the moment the plugin starts."
        )
        progressive_row.addWidget(progressive_label)
        progressive_combo = QComboBox()
        progressive_combo.setToolTip(
            "5 minutes: ramp from 0% to 100% queries over 5 minutes after startup.\n"
            "10 minutes: ramp over 10 minutes.\n"
            "30 minutes: ramp over 30 minutes (recommended for large networks).\n"
            "Disabled: send all queries immediately from startup."
        )
        progressive_combo.addItem("5 minutes",  "5")
        progressive_combo.addItem("10 minutes", "10")
        progressive_combo.addItem("30 minutes", "30")
        progressive_combo.addItem("Disabled",   "disabled")
        current_progressive = self.load_config().get("progressive_start", "5")
        p_idx = progressive_combo.findData(current_progressive)
        if p_idx >= 0:
            progressive_combo.setCurrentIndex(p_idx)
        progressive_row.addWidget(progressive_combo)
        progressive_row.addStretch()
        root_layout.addLayout(progressive_row)

        # --- Test connection row -------------------------------------------
        test_btn = QPushButton("Test dns/PiHole server connection")
        test_btn.setToolTip(
            "Send a test DNS A-record query for 'dns.google' to the configured\n"
            "Pi-hole server to verify it is reachable and responding correctly.\n"
            "A green ✔ Reachable result is required before saving."
        )
        root_layout.addWidget(test_btn)

        test_label = QLabel("")
        test_label.setWordWrap(True)
        root_layout.addWidget(test_label)

        def _read_dialog_values():
            """Read dns_server, dns_port, timeout from the current table."""
            vals = {}
            for idx, key in enumerate(keys):
                vals[key] = tbl.item(idx, 1).text()
            server = vals.get("dns_server", "").strip()
            try:
                port = int(vals.get("dns_port", "53"))
            except ValueError:
                port = 53
            try:
                timeout = float(vals.get("timeout_seconds", "3"))
            except ValueError:
                timeout = 3.0
            return server, port, timeout

        def _on_test_clicked():
            server, port, timeout = _read_dialog_values()
            if not server:
                test_label.setText("Unreachable, error: No DNS server configured")
                return
            reachable, error_msg = _test_dns_server(server, port, timeout)
            if reachable:
                test_label.setText("\u2714 Reachable")
            else:
                test_label.setText(f"Unreachable, error: {error_msg}")

        test_btn.clicked.connect(_on_test_clicked)

        # --- Save / Cancel -------------------------------------------------
        btn_box = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel
        )
        root_layout.addWidget(btn_box)
        btn_box.rejected.connect(dialog.reject)

        def _on_save():
            server, port, timeout = _read_dialog_values()
            if not server:
                QMessageBox.warning(
                    dialog, "DNS Server Unreachable",
                    "The dns server field is empty.",
                )
                return
            reachable, error_msg = _test_dns_server(server, port, timeout)
            if not reachable:
                QMessageBox.warning(
                    dialog, "DNS Server Unreachable",
                    f"The dns server \"{server}\" is unreachable, "
                    f"error: {error_msg}",
                )
                test_label.setText(f"Unreachable, error: {error_msg}")
                return
            dialog.accept()

        btn_box.accepted.connect(_on_save)

        if dialog.exec() == QDialog.Accepted:
            cfg = self.load_config()
            for i, key in enumerate(keys):
                entry = settings[key]
                if entry.get("type") in ("choice", "multi_check"):
                    continue  # handled separately below
                raw_value = tbl.item(i, 1).text()
                val_type = entry.get("type", "str")
                try:
                    if val_type == "bool":
                        parsed = raw_value.strip().lower() in ("true", "1", "yes")
                    elif val_type == "int":
                        parsed = int(raw_value)
                    elif val_type == "float":
                        parsed = float(raw_value)
                    else:
                        parsed = raw_value
                except Exception:
                    parsed = raw_value
                cfg[key] = parsed
            # Save the suspicious flags checkboxes
            cfg.pop("suspicious_rcodes", None)  # remove legacy key
            cfg["suspicious_flags"] = [k for k, cb in sus_checks if cb.isChecked()]
            # Save the timeout strategy dropdown
            cfg["timeout_strategy"] = timeout_combo.currentData()
            # Save the progressive start dropdown
            cfg["progressive_start"] = progressive_combo.currentData()
            self.save_config(cfg)
            # Clear DNS cache so new server config takes effect immediately
            _dns_check_cached.cache_clear()
