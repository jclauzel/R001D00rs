"""
Connection collector plugin that reads connections from a pcap file.

Architecture (OS-table-first):
    Every call to ``collect_raw_connections()`` starts from the **live OS
    connection table** (via ``netstat``/``ss``), exactly like the built-in
    psutil collector.  Traffic byte counters parsed from the pcap file are
    overlaid on matching OS-table entries.

    Connections that exist in the OS table but have no matching pcap
    traffic are still returned — with ``bytes_sent`` / ``bytes_recv`` = 0.

Requires the ``scapy`` library (``pip install scapy``).

To use it:
  1. ``pip install scapy``
  2. Place this file in the ``plugins/`` directory next to ``tcp_geo_map.py``.
  3. Launch the application → Settings tab → Connection Collector → select
     "PCAP File Collector".
  4. Set the pcap file path in the Settings tab (saved to settings.json).
"""

import json
import logging
import os
import platform as _platform

from connection_collector_plugin import ConnectionCollectorPlugin
from plugins.os_conn_table import get_os_connections as _get_os_table

# Path to the global settings file (one directory above this plugin)
_SETTINGS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'settings.json'
)


def _read_pcap_path() -> str:
    """Return the pcap_file_path stored in settings.json, or '' if not set."""
    try:
        with open(_SETTINGS_FILE, 'r') as f:
            return json.load(f).get('pcap_file_path', '')
    except Exception:
        return ''


class PcapCollector(ConnectionCollectorPlugin):
    """Read TCP/UDP connections from a pcap capture file, overlaid on the live OS table."""

    @property
    def name(self) -> str:
        return "PCAP File Collector"

    @property
    def description(self) -> str:
        return (
            "OS connection table (netstat/ss) supplemented with traffic "
            "bytes from a pcap/pcapng file (requires: pip install scapy)"
        )

    def collect_raw_connections(self) -> list:
        """Return the live OS connection table supplemented with pcap traffic.

        The connection *list* is always driven by the OS table.  Traffic
        bytes parsed from the pcap file are overlaid on matching entries.
        Connections with no pcap traffic still appear with 0 bytes.
        """
        hostname = _platform.node()

        # 1. Authoritative connection list from the OS table
        os_conns, _os_alive = _get_os_table(hostname)

        # 2. Parse traffic bytes from the pcap (if configured)
        traffic = self._parse_pcap_traffic()

        # 3. Overlay traffic on OS-table entries
        for key, conn in os_conns.items():
            t = traffic.get(key)
            if not t:
                # Try reverse key
                src, sp, dst, dp, proto = key
                t = traffic.get((dst, dp, src, sp, proto))
                if t:
                    # Swap sent/recv for reverse direction
                    t = {'bytes_sent': t.get('bytes_recv', 0),
                         'bytes_recv': t.get('bytes_sent', 0)}
            if t:
                conn['bytes_sent'] = t.get('bytes_sent', 0)
                conn['bytes_recv'] = t.get('bytes_recv', 0)

        return list(os_conns.values())

    # ---- pcap parsing -------------------------------------------------------

    @staticmethod
    def _parse_pcap_traffic() -> dict:
        """Parse the pcap file and return traffic byte counters.

        Returns ``{(src, sport, dst, dport, proto): {bytes_sent, bytes_recv}}``
        keyed on the first-seen direction.
        """
        pcap_file_path = _read_pcap_path()
        if not pcap_file_path:
            return {}

        try:
            from scapy.all import rdpcap, IP, IPv6, TCP, UDP
        except ImportError:
            return {}

        try:
            packets = rdpcap(pcap_file_path)
        except Exception as e:
            logging.debug(f"PcapCollector: failed to read pcap: {e}")
            return {}

        traffic: dict = {}
        seen_keys: dict = {}   # maps both orientations to the canonical key

        for pkt in packets:
            ip_layer = None
            if IP in pkt:
                ip_layer = pkt[IP]
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
            else:
                continue

            protocol = ""
            sport = ""
            dport = ""
            if TCP in pkt:
                protocol = "TCP"
                sport = str(pkt[TCP].sport)
                dport = str(pkt[TCP].dport)
            elif UDP in pkt:
                protocol = "UDP"
                sport = str(pkt[UDP].sport)
                dport = str(pkt[UDP].dport)
            else:
                continue

            src = ip_layer.src
            dst = ip_layer.dst

            try:
                pkt_bytes = int(ip_layer.len)
            except Exception:
                pkt_bytes = len(pkt)

            fwd_key = (src, sport, dst, dport, protocol)
            rev_key = (dst, dport, src, sport, protocol)

            if fwd_key in seen_keys:
                canon = seen_keys[fwd_key]
                if canon == fwd_key:
                    traffic[canon]['bytes_sent'] += pkt_bytes
                else:
                    traffic[canon]['bytes_recv'] += pkt_bytes
            elif rev_key in seen_keys:
                canon = seen_keys[rev_key]
                if canon == fwd_key:
                    traffic[canon]['bytes_sent'] += pkt_bytes
                else:
                    traffic[canon]['bytes_recv'] += pkt_bytes
            else:
                # First time seeing this flow — canonical key is fwd
                seen_keys[fwd_key] = fwd_key
                seen_keys[rev_key] = fwd_key
                traffic[fwd_key] = {
                    'bytes_sent': pkt_bytes,
                    'bytes_recv': 0,
                }

        return traffic
