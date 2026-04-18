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
@functools.lru_cache(maxsize=1024)
def _dns_check_cached(dns_server: str, dns_port: int, timeout: float,
                      ip_address: str, cache_epoch: int):
    """Perform the actual DNS check.  Returns (found: bool, detail: str)."""
    try:
        packet, _rev = _build_ptr_query(ip_address)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (dns_server, dns_port))
            data, _ = sock.recvfrom(1024)
        finally:
            sock.close()

        rcode, ptr_name = _parse_ptr_response(data)

        # NXDOMAIN (3) = normal "no PTR record", NOT a Pi-hole block
        if rcode == 3:
            return False, ""

        # REFUSED (5) or SERVFAIL (2) typically mean Pi-hole is blocking
        if rcode in (2, 5):
            return True, f"Pi-hole ({dns_server}): DNS rcode {rcode}"

        # NOERROR with a PTR answer means the name resolved normally
        if rcode == 0 and ptr_name:
            return False, f"DNS resolved: {ptr_name}"

        # NOERROR but no answer data – treat as blocked
        return True, f"Pi-hole ({dns_server}): empty DNS response"

    except (socket.timeout, TimeoutError):
        return True, f"Pi-hole ({dns_server}): timeout"
    except (ConnectionResetError, ConnectionRefusedError, OSError) as exc:
        return True, f"Pi-hole ({dns_server}): {type(exc).__name__}"
    except Exception as exc:
        logging.error("PiHolePlugin: unexpected error checking %s: %s",
                      ip_address, exc)
        return False, f"Error: {exc}"


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

    def _ensure_config(self):
        if not os.path.exists(self._config_path()):
            self.save_config(_DEFAULT_CONFIG)

    # --- IPAnalyzePlugin interface -----------------------------------------

    def check_ip(self, ip_address: str) -> IPAnalyzeResult:
        """Perform a DNS lookup for *ip_address* via the configured Pi-hole."""
        cfg = self.load_config()
        dns_server = cfg.get("dns_server", "pi.hole").strip()
        dns_port = int(cfg.get("dns_port", 53))
        timeout = float(cfg.get("timeout_seconds", 3))

        if not dns_server:
            return IPAnalyzeResult(found=False, plugin_name=self.name,
                                   additional_information="No DNS server configured")

        # cache_epoch flips every 60 s so stale entries expire automatically
        cache_epoch = int(time.time()) // 60
        found, detail = _dns_check_cached(
            dns_server, dns_port, timeout, ip_address, cache_epoch,
        )
        return IPAnalyzeResult(
            found=found, plugin_name=self.name,
            additional_information=detail,
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
        }

    # --- settings dialog (plugin-owned UI) ---------------------------------

    def show_settings_dialog(self, parent) -> None:
        """Build and display the PiHole plugin settings dialog.

        PySide6 widgets are imported locally so the plugin module has no
        hard Qt dependency at import time.
        """
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import (
            QDialog, QDialogButtonBox, QHBoxLayout, QHeaderView, QLabel,
            QMessageBox, QPushButton, QTableWidget, QTableWidgetItem,
            QVBoxLayout,
        )

        settings = self.get_settings()
        if not settings:
            return

        dialog = QDialog(parent)
        dialog.setWindowTitle(f"{self.name} \u2014 Settings")
        dialog.setMinimumWidth(500)
        root_layout = QVBoxLayout(dialog)

        keys = list(settings.keys())
        tbl = QTableWidget(len(keys), 3)
        tbl.setHorizontalHeaderLabels(["Setting", "Value", "Description"])
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

        # --- Test connection row -------------------------------------------
        test_btn = QPushButton("Test dns/PiHole server connection")
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
                raw_value = tbl.item(i, 1).text()
                entry = settings[key]
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
            self.save_config(cfg)
            # Clear DNS cache so new server config takes effect immediately
            _dns_check_cached.cache_clear()
