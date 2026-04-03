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
import time
import socket as _socket
import platform as _platform
import logging

try:
    import psutil as _psutil
except ImportError:
    _psutil = None

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
        # Now each value is a dict with connection info + 'last_seen'
        self._connections: dict = {}
        self._sniffer_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._started = False
        self._hostname = _platform.node()
        self._pid_cache: dict = {}
        self._pid_cache_time: float = 0.0
        self._pid_cache_lock = threading.Lock()
        self._CONN_TIMEOUT = 30  # seconds before checking OS table for liveness
        self._local_addrs: set = set()  # populated once at start
        self._local_addrs_time: float = 0.0

    _PID_CACHE_TTL = 2.0  # seconds between psutil connection-table refreshes

    # ---- public API ---------------------------------------------------------

    def collect_raw_connections(self) -> list:
        """Return all connections captured by Scapy that are still alive.

        A connection is kept as long as it still appears in the OS connection
        table (via psutil).  Connections that have timed out *and* are no
        longer in the OS table are evicted.  This prevents the aggressive
        packet-timeout from hiding idle-but-established connections that
        psutil would show (e.g. keep-alive HTTP/2, database pools, SSH).
        """
        if not self._started:
            self._start_sniffer()

        # Build a set of currently active OS connections for liveness checks
        os_alive = self._get_os_connection_set()

        now = time.monotonic()
        with self._lock:
            to_remove = []
            for key, conn in self._connections.items():
                if now - conn.get('last_seen', 0) > self._CONN_TIMEOUT:
                    # Timed out — only evict if also gone from OS table
                    if not self._is_alive_in_os(key, os_alive):
                        to_remove.append(key)
            for key in to_remove:
                del self._connections[key]
            snapshot = [dict(conn) for conn in self._connections.values()]
        return snapshot

    # ---- OS connection table helpers ----------------------------------------

    def _refresh_local_addrs(self):
        """Cache the set of local IP addresses for direction detection."""
        if _psutil is None:
            return
        now = time.monotonic()
        if now - self._local_addrs_time < 30.0 and self._local_addrs:
            return  # still fresh
        addrs = set()
        try:
            for _iface, snics in _psutil.net_if_addrs().items():
                for snic in snics:
                    if snic.address:
                        addrs.add(snic.address)
        except Exception:
            pass
        addrs.update(('127.0.0.1', '::1', '0.0.0.0', '::'))
        self._local_addrs = addrs
        self._local_addrs_time = now

    def _get_os_connection_set(self) -> set:
        """Return a set of ``(local_ip, local_port, remote_ip, remote_port, proto)``
        tuples for all active OS connections (TCP ESTABLISHED + UDP with remote)."""
        if _psutil is None:
            return set()
        result = set()
        try:
            for c in _psutil.net_connections(kind='inet'):
                if c.type == _socket.SOCK_STREAM:
                    if c.status != 'ESTABLISHED':
                        continue
                    proto = 'TCP'
                elif c.type == _socket.SOCK_DGRAM:
                    proto = 'UDP'
                else:
                    continue
                if not c.laddr:
                    continue
                laddr_ip = c.laddr.ip
                laddr_port = str(c.laddr.port)
                if c.raddr and c.raddr.ip and c.raddr.ip not in ('0.0.0.0', '::', '*', ''):
                    raddr_ip = c.raddr.ip
                    raddr_port = str(c.raddr.port)
                else:
                    continue  # no remote — skip
                result.add((laddr_ip, laddr_port, raddr_ip, raddr_port, proto))
        except Exception as e:
            logging.debug(f"ScapyLiveCollector: OS connection set error: {e}")
        return result

    def _is_alive_in_os(self, key: tuple, os_alive: set) -> bool:
        """Check whether the Scapy-tracked connection *key* still appears in
        the OS connection table.

        The Scapy key is ``(src, sport, dst, dport, proto)`` based on packet
        direction, so we must check both orientations against the OS table
        (which always uses local-first ordering).
        """
        src, sport, dst, dport, proto = key
        # Forward: src is local
        if (src, sport, dst, dport, proto) in os_alive:
            return True
        # Reverse: dst is local (inbound packet created the key)
        if (dst, dport, src, sport, proto) in os_alive:
            return True
        return False

    # ---- PID / process correlation ------------------------------------------

    def _refresh_pid_cache(self):
        """Rebuild the port-based PID lookup table from the live OS connection table.

        Keyed on ``(lport_str, proto)`` rather than ``(laddr, lport, proto)``
        because psutil may report wildcard bind addresses (``"0.0.0.0"``,
        ``"::"``) which never match the real source/destination IP seen in a
        captured packet.  Port numbers are unique enough in practice for
        correlating a captured flow back to its owning process.

        Guarded by ``_PID_CACHE_TTL`` so psutil is called at most once per
        refresh cycle regardless of packet rate.
        """
        if _psutil is None:
            return
        new_cache: dict = {}
        try:
            for c in _psutil.net_connections(kind='inet'):
                if not c.laddr or not c.pid:
                    continue
                if c.type == _socket.SOCK_STREAM:
                    proto = 'TCP'
                elif c.type == _socket.SOCK_DGRAM:
                    proto = 'UDP'
                else:
                    continue
                key = (str(c.laddr.port), proto)
                # Don't overwrite an entry that already has a real process name
                if key in new_cache:
                    continue
                try:
                    proc_name = _psutil.Process(c.pid).name()
                except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                    proc_name = ''
                new_cache[key] = (c.pid, proc_name)
        except Exception as e:
            logging.debug(f"ScapyLiveCollector: PID cache refresh error: {e}")
        with self._pid_cache_lock:
            self._pid_cache = new_cache
            self._pid_cache_time = time.monotonic()

    def _lookup_pid(self, port: str, proto: str):
        """Return ``(pid_str, process_name)`` for *port*/*proto*, or ``('', '')``.

        Refreshes the cache when stale before the lookup.
        """
        if _psutil is None:
            return '', ''
        now = time.monotonic()
        with self._pid_cache_lock:
            stale = (now - self._pid_cache_time) >= self._PID_CACHE_TTL
        if stale:
            self._refresh_pid_cache()
        with self._pid_cache_lock:
            entry = self._pid_cache.get((port, proto))
        if entry is not None:
            pid, name = entry
            return str(pid), name or str(pid)
        return '', ''

    # ---- background sniffer -------------------------------------------------

    def _start_sniffer(self):
        """Spin up the background packet-capture thread."""
        self._stop_event.clear()
        self._refresh_local_addrs()
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

            # --- Direction detection -----------------------------------------
            # Determine which side is local so we always store the connection
            # as (local_ip, local_port, remote_ip, remote_port) — the same
            # orientation psutil uses.  This prevents a single TCP connection
            # from creating two entries (one per packet direction).
            self._refresh_local_addrs()
            src_is_local = src in self._local_addrs
            dst_is_local = dst in self._local_addrs

            if src_is_local and not dst_is_local:
                # Outbound packet: src is local
                local_ip, local_port, remote_ip, remote_port = src, sport, dst, dport
                is_outbound = True
            elif dst_is_local and not src_is_local:
                # Inbound packet: dst is local
                local_ip, local_port, remote_ip, remote_port = dst, dport, src, sport
                is_outbound = False
            else:
                # Both local (loopback) or both non-local (forwarded):
                # fall back to PID-cache heuristic
                _, _src_proc = self._lookup_pid(sport, protocol)
                if _src_proc:
                    local_ip, local_port, remote_ip, remote_port = src, sport, dst, dport
                    is_outbound = True
                else:
                    local_ip, local_port, remote_ip, remote_port = dst, dport, src, sport
                    is_outbound = False

            # Canonical key: always (local, lport, remote, rport, proto)
            key = (local_ip, local_port, remote_ip, remote_port, protocol)

            # Correlate with the OS connection table via psutil.
            pid_str, proc_name = self._lookup_pid(local_port, protocol)
            if not pid_str:
                pid_str, proc_name = self._lookup_pid(remote_port, protocol)
            if not proc_name:
                proc_name = 'capture'

            # --- Byte accounting ---------------------------------------------
            try:
                pkt_bytes = int(ip_layer.len)
            except Exception:
                pkt_bytes = len(pkt)

            with self._lock:
                existing = self._connections.get(key)
                now = time.monotonic()
                if existing:
                    if is_outbound:
                        existing['bytes_sent'] = existing.get('bytes_sent', 0) + pkt_bytes
                    else:
                        existing['bytes_recv'] = existing.get('bytes_recv', 0) + pkt_bytes
                    existing['last_seen'] = now
                    # Update PID/process if we got a better match
                    if pid_str and not existing.get('pid'):
                        existing['pid'] = pid_str
                        existing['process'] = proc_name
                else:
                    conn = {
                        'process': proc_name,
                        'pid': pid_str,
                        'protocol': protocol,
                        'local': local_ip,
                        'localport': local_port,
                        'remote': remote_ip,
                        'remoteport': remote_port,
                        'ip_type': ip_type,
                        'hostname': self._hostname,
                        'bytes_sent': pkt_bytes if is_outbound else 0,
                        'bytes_recv': pkt_bytes if not is_outbound else 0,
                        'last_seen': now,
                    }
                    self._connections[key] = conn

        stop_fn = lambda _pkt: self._stop_event.is_set()

        def _run_sniff(l2socket=None):
            kwargs = dict(
                prn=_process_packet,
                store=0,
                stop_filter=stop_fn,
            )
            kwargs.pop('type', None)   # ignore if present

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

