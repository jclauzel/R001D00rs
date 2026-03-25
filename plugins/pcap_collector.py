"""
Example connection collector plugin that reads connections from a pcap file.

This is a *template* — it requires the ``scapy`` library to be installed
(``pip install scapy``) and a pcap file path to be configured.

To use it:
  1. ``pip install scapy``
  2. Place this file in the ``plugins/`` directory next to ``tcp_geo_map.py``.
  3. Launch the application → Settings tab → Connection Collector → select
     "PCAP File Collector".
  4. Set ``PCAP_FILE_PATH`` below (or extend the plugin to accept a UI path).
"""

from connection_collector_plugin import ConnectionCollectorPlugin

# --- Configuration -----------------------------------------------------------
PCAP_FILE_PATH = ""  # Set to the full path of your .pcap / .pcapng file
# -----------------------------------------------------------------------------


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
        if not PCAP_FILE_PATH:
            return []

        try:
            from scapy.all import rdpcap, IP, IPv6, TCP, UDP
        except ImportError:
            return []

        connections = []
        seen = set()

        try:
            packets = rdpcap(PCAP_FILE_PATH)
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

            # De-duplicate
            key = (src, sport, dst, dport, protocol)
            if key in seen:
                continue
            seen.add(key)

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
            })

        return connections
