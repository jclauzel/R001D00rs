"""
Live packet capture connection collector plugin using Scapy's ``sniff()``.

Cross-platform: works on Windows (with or without Npcap), macOS, and Linux.

This plugin runs a background sniffer thread that captures TCP and UDP
packets in real time.  Each call to ``collect_raw_connections()`` (fired
every refresh cycle by the main app) returns the unique connections
observed since the *previous* call — i.e. a rolling live view.

Windows without Npcap:
    Scapy automatically falls back to its Layer 3 socket (conf.L3socket)
    which works without any additional driver.  This covers all TCP/UDP
    traffic at the IP layer.  Install Npcap (https://npcap.com/) for full
    Layer 2 access (required to see traffic that doesn't originate from or
    terminate at this host, e.g. bridged/mirrored traffic).

Requirements:
    pip install scapy

To use:
    1. Place this file in the ``plugins/`` directory next to ``tcp_geo_map.py``.
    2. Launch the application → Settings → Connection Collector →
       select **"Scapy Live Capture"**.
"""

import threading
import platform as _platform
import logging

from connection_collector_plugin import ConnectionCollectorPlugin


class ScapyLiveCollector(ConnectionCollectorPlugin):
    """Capture live TCP/UDP connections from the wire using Scapy."""

    # ---- plugin metadata ----------------------------------------------------

    @property
    def name(self) -> str:
        return "Scapy Live Capture"

    @property
    def description(self) -> str:
        return (
            "Live packet capture via Scapy sniff() — "
            "cross-platform; on Windows works without Npcap (install Npcap for full L2 access)"
        )

    # ---- internal state -----------------------------------------------------

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        # Accumulated connections: key=(src, sport, dst, dport, proto) -> dict
        self._connections: dict = {}
        self._sniffer_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._started = False
        self._hostname = _platform.node()

    # ---- public API ---------------------------------------------------------

    def collect_raw_connections(self) -> list:
        """Return connections observed since the last call, then reset.

        On the very first call the background sniffer is started; subsequent
        calls simply drain the accumulated buffer.
        """
        if not self._started:
            self._start_sniffer()

        with self._lock:
            snapshot = list(self._connections.values())
            self._connections.clear()
        return snapshot

    # ---- background sniffer -------------------------------------------------

    def _start_sniffer(self):
        """Spin up the background packet-capture thread."""
        self._stop_event.clear()
        self._sniffer_thread = threading.Thread(
            target=self._sniffer_loop, daemon=True, name="ScapyLiveSniffer"
        )
        self._sniffer_thread.start()
        self._started = True
        logging.info("Scapy live sniffer started")

    def _sniffer_loop(self):
        """Run ``scapy.sniff()`` in a background thread.

        Tries Layer 2 first (requires Npcap on Windows); if that raises the
        "winpcap is not installed" / layer-2-unavailable error, retries
        transparently using Scapy's Layer 3 socket (``conf.L3socket``), which
        works on all platforms without any extra drivers.
        """
        try:
            from scapy.all import sniff, IP, IPv6, TCP, UDP, conf
        except ImportError:
            logging.error(
                "Scapy is not installed — live capture unavailable "
                "(pip install scapy)"
            )
            return

        def _process_packet(pkt):
            """Callback invoked for every captured packet."""
            if self._stop_event.is_set():
                return

            # --- IP layer ----------------------------------------------------
            ip_layer = None
            ip_type = ""
            if IP in pkt:
                ip_layer = pkt[IP]
                ip_type = "IPv4"
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
                ip_type = "IPv6"
            else:
                return

            src = ip_layer.src
            dst = ip_layer.dst

            # --- Transport layer ---------------------------------------------
            protocol = ""
            sport = ""
            dport = ""

            if TCP in pkt:
                tcp = pkt[TCP]
                flags = tcp.flags
                # Only track established flows (ACK bit set).
                # Ignore pure SYN, FIN, RST to avoid half-open / teardown noise.
                if not (flags & 0x10):   # ACK bit must be set
                    return
                if flags & 0x04:         # skip RST+ACK (connection refused)
                    return
                protocol = "TCP"
                sport = str(tcp.sport)
                dport = str(tcp.dport)

            elif UDP in pkt:
                udp = pkt[UDP]
                protocol = "UDP"
                sport = str(udp.sport)
                dport = str(udp.dport)
            else:
                return

            key = (src, sport, dst, dport, protocol)
            conn = {
                'process': 'capture',
                'pid': '',
                'protocol': protocol,
                'local': src,
                'localport': sport,
                'remote': dst,
                'remoteport': dport,
                'ip_type': ip_type,
                'hostname': self._hostname,
            }
            with self._lock:
                self._connections[key] = conn

        # BPF filter: only TCP and UDP (ignore ARP, ICMP, etc.)
        bpf_filter = "tcp or udp"
        stop_fn = lambda _pkt: self._stop_event.is_set()

        def _run_sniff(l2socket=None):
            kwargs = dict(
                prn=_process_packet,
                filter=bpf_filter,
                store=0,
                stop_filter=stop_fn,
            )
            if l2socket is not None:
                kwargs['L2socket'] = l2socket
            sniff(**kwargs)

        try:
            # --- Attempt 1: default (Layer 2, requires Npcap on Windows) ----
            _run_sniff()

        except (OSError, ImportError) as e:
            msg = str(e).lower()
            if "winpcap" in msg or "layer 2" in msg or "not available" in msg or "npcap" in msg:
                # --- Attempt 2: Layer 3 fallback (no Npcap needed) -----------
                logging.warning(
                    "Scapy Layer 2 unavailable (Npcap not installed). "
                    "Falling back to Layer 3 socket — install Npcap for full capture."
                )
                try:
                    _run_sniff(l2socket=conf.L3socket)
                except PermissionError:
                    logging.error(
                        "Scapy live capture requires elevated privileges "
                        "(run as Administrator / root)"
                    )
                except Exception as e2:
                    logging.error(f"Scapy L3 fallback sniffer error: {e2}")
            else:
                logging.error(f"Scapy live sniffer error: {e}")

        except PermissionError:
            logging.error(
                "Scapy live capture requires elevated privileges "
                "(run as Administrator / root)"
            )
        except Exception as e:
            msg = str(e).lower()
            if "winpcap" in msg or "layer 2" in msg or "not available" in msg or "npcap" in msg:
                logging.warning(
                    "Scapy Layer 2 unavailable (Npcap not installed). "
                    "Falling back to Layer 3 socket — install Npcap for full capture."
                )
                try:
                    _run_sniff(l2socket=conf.L3socket)
                except PermissionError:
                    logging.error(
                        "Scapy live capture requires elevated privileges "
                        "(run as Administrator / root)"
                    )
                except Exception as e2:
                    logging.error(f"Scapy L3 fallback sniffer error: {e2}")
            else:
                logging.error(f"Scapy live sniffer error: {e}")
        finally:
            self._started = False
            logging.info("Scapy live sniffer stopped")

    # ---- cleanup ------------------------------------------------------------

    def stop(self):
        """Signal the sniffer to stop (called when switching plugins)."""
        self._stop_event.set()
        self._started = False

