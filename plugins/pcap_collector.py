"""
Connection collector plugin that reads connections from a pcap file.

Requires the ``scapy`` library (``pip install scapy``).

To use it:
  1. ``pip install scapy``
  2. Place this file in the ``plugins/`` directory next to ``tcp_geo_map.py``.
  3. Launch the application → Settings tab → Connection Collector → select
     "PCAP File Collector".
  4. Set the pcap file path in the Settings tab (saved to settings.json).
"""

import json
import os

from connection_collector_plugin import ConnectionCollectorPlugin

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
    """Read TCP/UDP connections from a pcap capture file instead of live psutil."""

    @property
    def name(self) -> str:
        return "PCAP File Collector"

    @property
    def description(self) -> str:
        return "Reads connections from a pcap/pcapng file using Scapy (requires: pip install scapy)"

    def collect_raw_connections(self) -> list:
        """Parse the pcap and return a list of connection dicts.

        Each dict must contain at minimum:
            process, pid, protocol, local, localport, remote, remoteport,
            ip_type, hostname
        """
        pcap_file_path = _read_pcap_path()
        if not pcap_file_path:
            return []

        try:
            from scapy.all import rdpcap, IP, IPv6, TCP, UDP
        except ImportError:
            return []

        connections = []
        conn_map = {}   # key -> index in connections list (for byte accumulation)

        try:
            packets = rdpcap(pcap_file_path)
        except Exception:
            return []

        import platform as _platform
        local_hostname = _platform.node()

        for pkt in packets:
            ip_layer = None
            ip_type = ""
            if IP in pkt:
                ip_layer = pkt[IP]
                ip_type = "IPv4"
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
                ip_type = "IPv6"
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

            # Packet byte size (IP total length or raw length)
            try:
                pkt_bytes = int(ip_layer.len)
            except Exception:
                pkt_bytes = len(pkt)

            key = (src, sport, dst, dport, protocol)
            rev_key = (dst, dport, src, sport, protocol)

            if key in conn_map:
                # Same direction as the first packet — accumulate as sent
                connections[conn_map[key]]['bytes_sent'] = connections[conn_map[key]].get('bytes_sent', 0) + pkt_bytes
            elif rev_key in conn_map:
                # Reverse direction — accumulate as received on the original entry
                connections[conn_map[rev_key]]['bytes_recv'] = connections[conn_map[rev_key]].get('bytes_recv', 0) + pkt_bytes
            else:
                conn_map[key] = len(connections)
                connections.append({
                    'process': 'pcap',
                    'pid': '',
                    'protocol': protocol,
                    'local': src,
                    'localport': sport,
                    'remote': dst,
                    'remoteport': dport,
                    'ip_type': ip_type,
                    'hostname': local_hostname,
                    'bytes_sent': pkt_bytes,
                    'bytes_recv': 0,
                })

        return connections
