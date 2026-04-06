"""
Live packet capture connection collector plugin using Scapy's ``sniff()``.

Cross-platform: works on Windows (with or without Npcap), macOS, and Linux.

Architecture (OS-table-first):
    Every call to ``collect_raw_connections()`` starts from the **live OS
    connection table** (via ``netstat``/``ss``), exactly like the built-in
    psutil collector.  A background Scapy sniffer thread accumulates
    per-connection byte counters (sent/recv) which are overlaid on the
    OS-table entries when a match is found.

    Connections that exist in the OS table but have had no captured traffic
    are still returned — with ``bytes_sent`` / ``bytes_recv`` = 0.  This
    guarantees the Scapy collector shows *at least* as many connections as
    the psutil collector while adding real-time traffic accounting.

    The traffic cache (``_traffic``) only holds byte counters and a
    ``last_seen`` timestamp.  ``_CONN_TIMEOUT`` controls how long byte
    counters are retained after a connection disappears from the OS table;
    set to 0 to disable the cache entirely (connections get fresh zero
    counters every refresh cycle).

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
from plugins.os_conn_table import get_os_connections as _get_os_table


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
        # Traffic cache: key → {bytes_sent, bytes_recv, last_seen}
        # Only holds byte counters — the *connection list* comes from the
        # OS table on every call.  Set _CONN_TIMEOUT = 0 to disable
        # caching entirely (counters are discarded every cycle).
        self._traffic: dict = {}
        self._sniffer_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._started = False
        self._hostname = _platform.node()
        self._pid_cache: dict = {}
        self._pid_cache_time: float = 0.0
        self._pid_cache_lock = threading.Lock()
        self._CONN_TIMEOUT = 10  # seconds to retain byte counters after a connection leaves the OS table
        self._local_addrs: set = set()
        self._local_addrs_time: float = 0.0
        self._LOCAL_ADDRS_TTL = 2.0  # seconds – detect VPN/NIC changes quickly

    _PID_CACHE_TTL = 2.0  # seconds between psutil connection-table refreshes

    # ---- public API ---------------------------------------------------------

    def collect_raw_connections(self) -> list:
        """Return the live OS connection table supplemented with traffic bytes.

        The connection *list* is always driven by the OS table (``netstat``
        / ``ss``).  The background Scapy sniffer provides byte-level
        sent/recv counters that are overlaid on matching entries.

        Connections with no captured traffic still appear — with
        ``bytes_sent`` / ``bytes_recv`` = 0 — exactly like the psutil
        collector but with traffic accounting when available.
        """
        if not self._started:
            self._start_sniffer()

        # 1. Authoritative connection list from the OS table
        os_conns, os_alive = _get_os_table(self._hostname)

        # 2. Overlay traffic byte counters from the sniffer cache
        now = time.monotonic()
        matched = 0
        with self._lock:
            traffic_count = len(self._traffic)

            for key, conn in os_conns.items():
                traffic = self._traffic.get(key)
                if not traffic:
                    # Try reverse key (sniffer might have stored it flipped)
                    src, sp, dst, dp, proto = key
                    traffic = self._traffic.get((dst, dp, src, sp, proto))
                if traffic:
                    conn['bytes_sent'] = traffic.get('bytes_sent', 0)
                    conn['bytes_recv'] = traffic.get('bytes_recv', 0)
                    matched += 1

            # 3. Evict traffic entries for connections no longer in the OS table.
            #    _CONN_TIMEOUT controls how long dead entries linger.
            #    Live connections always keep their byte counters.
            to_remove = [
                k for k, t in self._traffic.items()
                if not self._is_alive_in_os(k, os_alive)
                and (now - t.get('last_seen', 0)) > self._CONN_TIMEOUT
            ]
            for k in to_remove:
                del self._traffic[k]

        logging.debug(
            f"ScapyLiveCollector: os_conns={len(os_conns)}, "
            f"traffic={traffic_count}, matched={matched}"
        )

        return list(os_conns.values())

    # ---- OS table liveness check --------------------------------------------

    @staticmethod
    def _is_alive_in_os(key: tuple, os_alive: set) -> bool:
        """Check whether *key* (either orientation) is in *os_alive*."""
        src, sport, dst, dport, proto = key
        if (src, sport, dst, dport, proto) in os_alive:
            return True
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

    # ---- local address detection --------------------------------------------

    def _refresh_local_addrs(self):
        """Cache the set of local IP addresses for direction detection.

        When the address set changes (e.g. VPN on/off), the traffic cache
        is flushed because cached entries had direction (local vs remote)
        decided with the old address set and byte counters may be on the
        wrong side.
        """
        if _psutil is None:
            return
        now = time.monotonic()
        if now - self._local_addrs_time < self._LOCAL_ADDRS_TTL and self._local_addrs:
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
        old_addrs = self._local_addrs
        self._local_addrs = addrs
        self._local_addrs_time = now
        if old_addrs and addrs != old_addrs:
            logging.info(
                "ScapyLiveCollector: local addresses changed "
                "(VPN/NIC toggle detected) — flushing traffic cache"
            )
            with self._lock:
                self._traffic.clear()

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

        _pkt_count = [0]  # mutable counter for closure

        def _process_packet(pkt):
            """Callback invoked for every captured packet."""
            _pkt_count[0] += 1

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

            # --- Byte accounting ---------------------------------------------
            try:
                pkt_bytes = int(ip_layer.len)
            except Exception:
                pkt_bytes = len(pkt)

            with self._lock:
                existing = self._traffic.get(key)
                now = time.monotonic()
                if existing:
                    if is_outbound:
                        existing['bytes_sent'] = existing.get('bytes_sent', 0) + pkt_bytes
                    else:
                        existing['bytes_recv'] = existing.get('bytes_recv', 0) + pkt_bytes
                    existing['last_seen'] = now
                else:
                    self._traffic[key] = {
                        'bytes_sent': pkt_bytes if is_outbound else 0,
                        'bytes_recv': pkt_bytes if not is_outbound else 0,
                        'last_seen': now,
                    }

        stop_fn = lambda _pkt: self._stop_event.is_set()

        def _get_all_ifaces():
            """Return a list of all available Scapy interfaces.

            On Windows, Scapy's default ``conf.iface`` may point to a
            disconnected adapter (e.g. Wi-Fi with an APIPA address) while
            the real traffic flows over Ethernet or another NIC.  Passing
            ``iface=get_if_list()`` to ``sniff()`` makes it listen on
            **every** interface simultaneously, guaranteeing we capture
            traffic regardless of which adapter is active.
            """
            try:
                from scapy.all import get_if_list as _gif
                ifaces = _gif()
                if ifaces:
                    return ifaces
            except Exception:
                pass
            return None  # let sniff() use its default

        def _run_sniff(l2socket=None):
            ifaces = _get_all_ifaces()
            kwargs = dict(
                prn=_process_packet,
                store=0,
                stop_filter=stop_fn,
            )
            if ifaces is not None:
                kwargs['iface'] = ifaces
                logging.debug(
                    f"ScapyLiveCollector: sniffing on {len(ifaces)} interfaces"
                )

            if l2socket is not None:
                kwargs['L2socket'] = l2socket
            sniff(**kwargs)

        try:
            # --- Attempt 1: default (Layer 2, requires Npcap on Windows) ----
            logging.info("ScapyLiveCollector: attempting L2 sniff...")
            _run_sniff()
            logging.info(
                f"ScapyLiveCollector: L2 sniff() returned normally "
                f"(captured {_pkt_count[0]} packets)"
            )

        except (OSError, ImportError) as e:
            msg = str(e).lower()
            logging.warning(
                f"ScapyLiveCollector: L2 sniff raised {type(e).__name__}: {e}"
            )
            if "winpcap" in msg or "layer 2" in msg or "not available" in msg or "npcap" in msg:
                # --- Attempt 2: Layer 3 fallback (no Npcap needed) -----------
                logging.info(
                    "ScapyLiveCollector: falling back to L3 socket "
                    f"({conf.L3socket})..."
                )
                try:
                    _run_sniff(l2socket=conf.L3socket)
                    logging.info(
                        f"ScapyLiveCollector: L3 sniff() returned normally "
                        f"(captured {_pkt_count[0]} packets)"
                    )
                except PermissionError:
                    logging.error(
                        "Scapy live capture requires elevated privileges "
                        "(run as Administrator / root)"
                    )
                except Exception as e2:
                    logging.error(
                        f"ScapyLiveCollector: L3 fallback error: "
                        f"{type(e2).__name__}: {e2}"
                    )
            else:
                logging.error(f"ScapyLiveCollector: L2 sniffer error: {e}")

        except PermissionError:
            logging.error(
                "Scapy live capture requires elevated privileges "
                "(run as Administrator / root)"
            )
        except Exception as e:
            msg = str(e).lower()
            logging.warning(
                f"ScapyLiveCollector: L2 sniff raised {type(e).__name__}: {e}"
            )
            if "winpcap" in msg or "layer 2" in msg or "not available" in msg or "npcap" in msg:
                logging.info(
                    "ScapyLiveCollector: falling back to L3 socket "
                    f"({conf.L3socket})..."
                )
                try:
                    _run_sniff(l2socket=conf.L3socket)
                    logging.info(
                        f"ScapyLiveCollector: L3 sniff() returned normally "
                        f"(captured {_pkt_count[0]} packets)"
                    )
                except PermissionError:
                    logging.error(
                        "Scapy live capture requires elevated privileges "
                        "(run as Administrator / root)"
                    )
                except Exception as e2:
                    logging.error(
                        f"ScapyLiveCollector: L3 fallback error: "
                        f"{type(e2).__name__}: {e2}"
                    )
            else:
                logging.error(f"ScapyLiveCollector: sniffer error: {e}")
        finally:
            self._started = False
            logging.info(
                f"ScapyLiveCollector: sniffer stopped "
                f"(total packets processed: {_pkt_count[0]})"
            )

    # ---- cleanup ------------------------------------------------------------

    def stop(self):
        """Signal the sniffer to stop (called when switching plugins)."""
        self._stop_event.set()
        self._started = False

