"""
Cross-platform OS connection table helper.

Provides a single function ``get_os_connections()`` that returns the current
set of ESTABLISHED TCP (and optionally active UDP) connections by parsing
the output of a system command:

  * **Windows** — ``netstat -ano``
  * **Linux**   — ``ss -tunap`` (preferred) with fallback to
                  ``netstat -tulpent`` if *ss* is not available.
  * **macOS**   — ``netstat -anp tcp`` + ``netstat -anp udp``

Each connection is returned as a dict matching the
``ConnectionCollectorPlugin`` schema (process, pid, protocol, local,
localport, remote, remoteport, ip_type, hostname) with ``bytes_sent``
and ``bytes_recv`` set to **0**.

This module is used by both the Scapy live collector and the PCAP file
collector so that their connection list is always driven by the
authoritative OS table (like psutil) and the sniffer/pcap data only
supplements traffic byte counters.
"""

import logging
import platform as _platform
import re
import shutil
import socket as _socket
import subprocess

_HOSTNAME = _platform.node()

# Try to import psutil for PID → process name resolution.
try:
    import psutil as _psutil
except ImportError:
    _psutil = None

# TCP states considered "active" — connections in these states have a known
# remote endpoint and are worth displaying.  ESTABLISHED is the main one;
# SYN_SENT / SYN_RECV catch transient connections (e.g. VPN reconnects,
# proxy services) that would otherwise be missed because they never linger
# in ESTABLISHED long enough for a periodic OS-table snapshot to see them.
_ACTIVE_TCP_STATES_PSUTIL = frozenset()
if _psutil is not None:
    _ACTIVE_TCP_STATES_PSUTIL = frozenset({
        _psutil.CONN_ESTABLISHED,
        _psutil.CONN_SYN_SENT,
        _psutil.CONN_SYN_RECV,
    })

# Equivalent state names used by platform CLI tools (netstat / ss).
_ACTIVE_TCP_STATES_NETSTAT = frozenset({
    'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'SYN_RECEIVED',
})
_ACTIVE_TCP_STATES_SS = frozenset({
    'ESTAB', 'SYN-SENT', 'SYN-RECV',
})

# When True, psutil results are always supplemented with the platform netstat
# parser so that connections visible to netstat but missed by psutil are included.
_supplement_psutil_with_netstat: bool = True

# Last netstat-derived (lport, proto) -> (pid_str, proc_name) mapping.
# Populated during get_os_connections() when supplement mode is active so that
# callers (e.g. ScapyLiveCollector._refresh_pid_cache) can enrich their own
# PID caches with process names that netstat reported but psutil missed.
_netstat_pid_supplement: dict = {}


def set_supplement_psutil_with_netstat(enabled: bool) -> None:
    """Configure whether the netstat supplement is applied on top of psutil."""
    global _supplement_psutil_with_netstat
    _supplement_psutil_with_netstat = bool(enabled)


def get_netstat_pid_supplement() -> dict:
    """Return the most recent ``(lport_str, proto) -> (pid_str, proc_name)``
    mapping extracted from the netstat collection pass.

    Only populated when supplement mode is active.  The dict is replaced
    atomically on every ``get_os_connections()`` call so callers always see
    a consistent snapshot.
    """
    return _netstat_pid_supplement


def flush_all_caches() -> None:
    """Clear every module-level process/PID cache.

    Call this after a system sleep/resume cycle so that stale PID→name
    mappings (where the PID may have been recycled by a different process)
    are discarded and rebuilt from scratch on the next collection pass.
    """
    import time as _time
    global _proc_cache, _tasklist_cache, _tasklist_cache_time
    global _proc_negative_cache, _proc_negative_cache_time
    _proc_cache.clear()
    _tasklist_cache.clear()
    _tasklist_cache_time = 0.0
    _proc_negative_cache = set()
    _proc_negative_cache_time = 0.0
    logging.debug("os_conn_table: all caches flushed (sleep/resume)")


def get_tasklist_snapshot() -> dict[str, str]:
    """Return the current ``tasklist`` PID→name cache (Windows only).

    Calls ``_refresh_tasklist_cache()`` to ensure the data is fresh (respects
    the 2-second TTL) and returns the module-level ``_tasklist_cache`` dict
    mapping PID strings to process names.

    On non-Windows platforms the returned dict is always empty.
    """
    if _platform.system() == 'Windows':
        _refresh_tasklist_cache()
    return _tasklist_cache


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_os_connections(hostname: str | None = None) -> tuple[dict, set]:
    """Return ``(os_conns_dict, os_alive_set)`` from the live OS table.

    ``os_conns_dict`` maps canonical keys
    ``(local_ip, local_port, remote_ip, remote_port, proto)`` to full
    connection dicts (``bytes_sent`` / ``bytes_recv`` = 0).

    ``os_alive_set`` is the flat set of those keys for fast membership
    tests.

    *hostname* defaults to ``platform.node()`` if not supplied.

    When **psutil** is available it is used as the primary data source on
    every platform because the Win32 / procfs / sysctl API is faster and
    more complete than parsing ``netstat``/``ss`` text output.  In
    particular, on Windows the ``netstat -ano`` parser silently drops
    bound-but-unconnected UDP sockets (remote ``*:*``) that psutil
    correctly reports.  The subprocess-based parsers are kept as a
    fallback for environments where psutil is not installed.
    """
    hn = hostname or _HOSTNAME

    # --- Prefer psutil (fast, complete, no subprocess) -------------------
    if _psutil is not None:
        psutil_conns, psutil_alive = _parse_psutil(hn)
        if psutil_conns and not _supplement_psutil_with_netstat:
            return psutil_conns, psutil_alive
        # Either psutil returned nothing (possible permission issue) or
        # supplementing is enabled — run the platform netstat parser too.
        system = _platform.system()
        if system == 'Windows':
            ns_conns, ns_alive = _parse_netstat_windows(hn)
        elif system == 'Linux':
            ns_conns, ns_alive = _parse_linux(hn)
        elif system == 'Darwin':
            ns_conns, ns_alive = _parse_netstat_macos(hn)
        else:
            ns_conns, ns_alive = _parse_netstat_generic(hn)
        # Build a (lport, proto) -> (pid_str, proc_name) map from netstat
        # entries that carry a real process name.  This lets callers such as
        # ScapyLiveCollector._refresh_pid_cache enrich their PID caches with
        # names that netstat reported but psutil may have missed.
        global _netstat_pid_supplement
        supplement: dict = {}
        for conn in ns_conns.values():
            lport = conn.get('localport', '')
            proto = conn.get('protocol', '')
            pid_str = conn.get('pid', '')
            proc_name = conn.get('process', '')
            if lport and proto and proc_name and proc_name != 'Unknown':
                key = (lport, proto)
                if key not in supplement:
                    supplement[key] = (pid_str, proc_name)
        _netstat_pid_supplement = supplement

        # Merge: psutil entries take precedence (richer process info); netstat
        # entries fill in any keys that psutil did not report.
        # Exception: if the psutil entry has "Unknown" as the process name but
        # the netstat entry has a real name, keep the netstat name/pid.
        merged_conns = dict(ns_conns)
        for key, ps_conn in psutil_conns.items():
            ns_conn = merged_conns.get(key)
            if ns_conn is not None:
                ps_proc = ps_conn.get('process', '')
                ns_proc = ns_conn.get('process', '')
                if ps_proc in ('Unknown', '') and ns_proc and ns_proc != 'Unknown':
                    # Keep the netstat entry's process/pid but take everything
                    # else from psutil (it has richer metadata overall).
                    ps_conn = dict(ps_conn)
                    ps_conn['process'] = ns_proc
                    if ns_conn.get('pid'):
                        ps_conn['pid'] = ns_conn['pid']
            merged_conns[key] = ps_conn
        merged_alive = ns_alive | psutil_alive
        return merged_conns, merged_alive

    system = _platform.system()

    if system == 'Windows':
        return _parse_netstat_windows(hn)
    elif system == 'Linux':
        return _parse_linux(hn)
    elif system == 'Darwin':
        return _parse_netstat_macos(hn)
    else:
        # Generic fallback — try netstat
        return _parse_netstat_generic(hn)


# ---------------------------------------------------------------------------
# Process name cache (light — keyed on PID string)
# ---------------------------------------------------------------------------

_proc_cache: dict[str, str] = {}

# Windows tasklist fallback — maps PID string to process name.
# Used when psutil.Process(pid).name() throws AccessDenied for
# protected/system processes.  tasklist does not require elevation.
_tasklist_cache: dict[str, str] = {}
_tasklist_cache_time: float = 0.0
_TASKLIST_CACHE_TTL: float = 2.0  # seconds

# Negative cache — PIDs that failed all resolution attempts.
# Cleared every _NEGATIVE_CACHE_TTL seconds so transient failures are retried.
_proc_negative_cache: set = set()
_proc_negative_cache_time: float = 0.0
_NEGATIVE_CACHE_TTL: float = 5.0  # seconds


def _refresh_tasklist_cache() -> None:
    """Rebuild ``_tasklist_cache`` from ``tasklist /fo csv /nh`` (Windows).

    Non-elevated — lists every process visible to the current user,
    including System (PID 4) and services that psutil may not be able to
    query by PID due to access restrictions.
    """
    global _tasklist_cache, _tasklist_cache_time
    import time as _time
    now = _time.monotonic()
    if now - _tasklist_cache_time < _TASKLIST_CACHE_TTL and _tasklist_cache:
        return  # still fresh
    new_cache: dict[str, str] = {}
    try:
        import csv as _csv
        import io as _io
        output = subprocess.check_output(
            ['tasklist', '/fo', 'csv', '/nh'], timeout=10,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        ).decode('utf-8', errors='replace')
        for row in _csv.reader(_io.StringIO(output)):
            if len(row) >= 2:
                name = row[0].strip()
                pid = row[1].strip()
                if pid.isdigit() and name:
                    new_cache[pid] = name
    except Exception:
        pass
    _tasklist_cache = new_cache
    _tasklist_cache_time = now


def _resolve_process(pid_str: str) -> str:
    """Return process name for *pid_str*, or ``''``.

    Resolution order:
    1. Positive cache hit.
    2. ``psutil.Process(pid).name()``.
    3. Windows ``tasklist`` cache (handles AccessDenied PIDs).
    4. Negative-cache the PID for ``_NEGATIVE_CACHE_TTL`` seconds.
    """
    import time as _time
    global _proc_negative_cache, _proc_negative_cache_time

    if not pid_str or pid_str == '-' or pid_str == '0':
        return ''

    # 1. Positive cache
    cached = _proc_cache.get(pid_str)
    if cached:
        return cached

    # Clear stale negative cache
    now = _time.monotonic()
    if now - _proc_negative_cache_time >= _NEGATIVE_CACHE_TTL:
        _proc_negative_cache = set()
        _proc_negative_cache_time = now

    if pid_str in _proc_negative_cache:
        return ''

    # 2. psutil
    if _psutil is not None:
        try:
            name = _psutil.Process(int(pid_str)).name()
            if name:
                _proc_cache[pid_str] = name
                return name
        except Exception:
            pass

    # 3. Windows tasklist fallback
    if _platform.system() == 'Windows':
        _refresh_tasklist_cache()
        name = _tasklist_cache.get(pid_str, '')
        if name:
            _proc_cache[pid_str] = name
            return name

    # 4. Negative-cache — will be retried after TTL expires
    _proc_negative_cache.add(pid_str)
    return ''


def _make_conn(proto: str, local_ip: str, local_port: str,
               remote_ip: str, remote_port: str, ip_type: str,
               pid_str: str, proc_name: str, hostname: str) -> dict:
    """Build a connection dict matching the plugin schema."""
    name = proc_name or _resolve_process(pid_str)
    if not name and remote_port == '53':
        name = 'DNS (System)'
    return {
        'process': name or 'Unknown',
        'pid': pid_str,
        'protocol': proto,
        'local': local_ip,
        'localport': local_port,
        'remote': remote_ip,
        'remoteport': remote_port,
        'ip_type': ip_type,
        'hostname': hostname,
        'bytes_sent': 0,
        'bytes_recv': 0,
    }


def _normalize_ipv6(ip: str) -> tuple[str, str]:
    """If *ip* is an IPv4-mapped IPv6 address, return ``(ipv4, 'IPv4')``.
    Otherwise return ``(ip, 'IPv6')``."""
    if ip.startswith('::ffff:'):
        return ip[7:], 'IPv4'
    return ip, 'IPv6'


def _split_addr(addr: str) -> tuple[str, str, str]:
    """Split ``ip:port`` or ``[ip]:port`` into ``(ip, port, ip_type)``.

    Returns ``('', '', '')`` on failure.
    """
    if not addr:
        return '', '', ''
    # IPv6 bracket notation  [::1]:443
    if addr.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+)', addr)
        if m:
            ip, port = m.group(1), m.group(2)
            ip, ip_type = _normalize_ipv6(ip)
            return ip, port, ip_type
        return '', '', ''
    # IPv6 without brackets — multiple colons
    # e.g. "::1:443" — ambiguous, try rsplit on last colon
    if addr.count(':') > 1:
        # Last colon separates port
        last = addr.rfind(':')
        ip_part = addr[:last]
        port_part = addr[last + 1:]
        if port_part.isdigit():
            ip, ip_type = _normalize_ipv6(ip_part)
            return ip, port_part, ip_type
        return '', '', ''
    # Simple IPv4:port
    parts = addr.rsplit(':', 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], parts[1], 'IPv4'
    return '', '', ''


# ---------------------------------------------------------------------------
# psutil-based parser (preferred when psutil is installed)
# ---------------------------------------------------------------------------

def _netstat_udp_remotes_windows() -> dict:
    """Parse ``netstat -ano`` for UDP remote addresses (Windows only).

    On Windows, psutil's ``GetExtendedUdpTable`` does not report remote
    addresses for connected UDP sockets.  This helper supplements them by
    parsing the ``netstat -ano`` text output.

    Returns ``{(local_ip, local_port, pid_str): (remote_ip, remote_port)}``.
    """
    lookup: dict = {}
    try:
        output = subprocess.check_output(
            ['netstat', '-ano'], timeout=10,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        ).decode('utf-8', errors='replace')
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith('UDP'):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            local_part = parts[1]
            remote_part = parts[2]
            pid_str = parts[3]
            if remote_part in ('*:*', '0.0.0.0:0', '[::]:0'):
                continue
            l_ip, l_port, _ = _split_addr(local_part)
            r_ip, r_port, _ = _split_addr(remote_part)
            if l_ip and l_port and r_ip and r_port:
                lookup[(l_ip, l_port, pid_str)] = (r_ip, r_port)
    except Exception:
        pass
    return lookup


def _parse_psutil(hostname: str) -> tuple[dict, set]:
    """Build the connection table from **psutil** (cross-platform).

    Uses the same logic as the built-in ``PsutilCollector`` in
    *tcp_geo_map.py*: TCP ``ESTABLISHED`` + **all** UDP sockets.  On
    Windows, UDP remote addresses are supplemented with ``netstat -ano``
    because psutil's ``GetExtendedUdpTable`` does not report them.

    This produces an identical connection set to the psutil collector,
    eliminating the 20-40 % gap that the old ``netstat -ano`` text parser
    had (it silently dropped bound-but-unconnected UDP entries).
    """
    conns: dict = {}
    alive: set = set()

    # Snapshot PID → process name mapping *before* iterating connections.
    # This eliminates the race condition where a short-lived process exits
    # between psutil.net_connections() and psutil.Process(pid).name(),
    # which would otherwise leave the connection as "Unknown".
    pid_name_snapshot: dict[int, str] = {}
    try:
        for proc in _psutil.process_iter(['pid', 'name']):
            try:
                info = proc.info
                if info['pid'] and info['name']:
                    pid_name_snapshot[info['pid']] = info['name']
            except Exception:
                pass
    except Exception:
        pass

    try:
        all_connections = _psutil.net_connections(kind='inet')
    except Exception as e:
        logging.debug(f"os_conn_table: psutil.net_connections failed: {e}")
        return conns, alive

    # On Windows, supplement UDP with netstat for remote addresses
    udp_remote_lookup: dict = {}
    if _platform.system() == 'Windows':
        try:
            udp_remote_lookup = _netstat_udp_remotes_windows()
        except Exception:
            pass

    for conn in all_connections:
        is_tcp = (conn.type == _socket.SOCK_STREAM)
        is_udp = (conn.type == _socket.SOCK_DGRAM)

        if is_tcp:
            proto = 'TCP'
            if conn.status not in _ACTIVE_TCP_STATES_PSUTIL:
                continue
        elif is_udp:
            proto = 'UDP'
        else:
            continue

        laddr = getattr(conn, 'laddr', None)
        raddr = getattr(conn, 'raddr', None)
        if not laddr:
            continue

        l_ip = laddr.ip
        l_port = str(laddr.port)

        # --- determine remote address ------------------------------------
        has_real_raddr = False
        r_ip = ''
        r_port = ''
        if raddr:
            _rip = getattr(raddr, 'ip', None)
            _rport = getattr(raddr, 'port', None)
            if _rip and _rip not in ('0.0.0.0', '::', '*', '') and _rport:
                r_ip = _rip
                r_port = str(_rport)
                has_real_raddr = True

        if not has_real_raddr:
            # Try the Windows netstat UDP supplement
            if is_udp and udp_remote_lookup:
                pid_str = str(conn.pid) if conn.pid else ''
                ns_remote = udp_remote_lookup.get((l_ip, l_port, pid_str))
                if ns_remote:
                    r_ip, r_port = ns_remote
                    has_real_raddr = True

            if not has_real_raddr:
                if is_udp:
                    r_ip = '*'
                    r_port = '*'
                else:
                    # TCP without a real remote — skip
                    continue

        # Skip unroutable remotes (but keep '*' — it is the marker for
        # bound-but-unconnected UDP sockets, matching PsutilCollector).
        if r_ip in ('0.0.0.0', '::', ''):
            continue

        # --- IP type & IPv4-mapped normalisation -------------------------
        family = getattr(conn, 'family', None)
        if family == _socket.AF_INET6:
            ip_type = 'IPv6'
            if l_ip.startswith('::ffff:'):
                l_ip = l_ip[7:]
                ip_type = 'IPv4'
            if r_ip.startswith('::ffff:'):
                r_ip = r_ip[7:]
                ip_type = 'IPv4'
        else:
            ip_type = 'IPv4'

        # --- PID / process -----------------------------------------------
        pid_str = str(conn.pid) if conn.pid else ''
        proc_name = ''
        if conn.pid:
            # 1. Pre-snapshotted name (immune to race conditions)
            proc_name = pid_name_snapshot.get(conn.pid, '')
            # 2. Live psutil lookup (may succeed for long-lived processes)
            if not proc_name:
                try:
                    proc_name = _psutil.Process(conn.pid).name()
                except Exception:
                    pass
            # 3. Multi-tier fallback (tasklist, negative-cache with TTL)
            if not proc_name:
                proc_name = _resolve_process(pid_str)

        key = (l_ip, l_port, r_ip, r_port, proto)
        alive.add(key)
        if key not in conns:
            conns[key] = _make_conn(
                proto, l_ip, l_port, r_ip, r_port, ip_type,
                pid_str, proc_name, hostname,
            )

    return conns, alive


# ---------------------------------------------------------------------------
# Windows: netstat -ano  (fallback when psutil is unavailable)
# ---------------------------------------------------------------------------

def _parse_netstat_windows(hostname: str) -> tuple[dict, set]:
    """Parse ``netstat -ano`` on Windows."""
    conns: dict = {}
    alive: set = set()
    try:
        output = subprocess.check_output(
            ['netstat', '-ano'], timeout=10,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        ).decode('utf-8', errors='replace')
    except Exception as e:
        logging.debug(f"os_conn_table: netstat -ano failed: {e}")
        return conns, alive

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        # Expected: Proto  LocalAddress  ForeignAddress  State  PID
        # TCP lines have 5 cols, UDP lines have 4 cols (no State)
        if parts[0] == 'TCP':
            if len(parts) < 5:
                continue
            state = parts[3]
            if state in ('TIME_WAIT', 'TIME_WAIT2'):
                continue
            if state not in _ACTIVE_TCP_STATES_NETSTAT:
                continue
            proto = 'TCP'
            local_addr = parts[1]
            remote_addr = parts[2]
            pid_str = parts[4]
        elif parts[0] == 'UDP':
            if len(parts) < 4:
                continue
            proto = 'UDP'
            local_addr = parts[1]
            remote_addr = parts[2]
            pid_str = parts[3]
        else:
            continue

        # Skip wildcard / no remote
        if remote_addr in ('*:*', '0.0.0.0:0', '[::]:0', '*'):
            continue

        l_ip, l_port, l_type = _split_addr(local_addr)
        r_ip, r_port, r_type = _split_addr(remote_addr)
        if not l_ip or not r_ip or not l_port or not r_port:
            continue
        # Skip if remote is 0.0.0.0 or ::
        if r_ip in ('0.0.0.0', '::', '*', ''):
            continue

        ip_type = l_type or r_type or 'IPv4'
        key = (l_ip, l_port, r_ip, r_port, proto)
        alive.add(key)
        if key not in conns:
            conns[key] = _make_conn(
                proto, l_ip, l_port, r_ip, r_port, ip_type,
                pid_str, '', hostname,
            )

    return conns, alive


# ---------------------------------------------------------------------------
# Linux: ss -tunap  (preferred)  /  netstat -tulpent  (fallback)
# ---------------------------------------------------------------------------

def _parse_linux(hostname: str) -> tuple[dict, set]:
    """Try ``ss -tunap``, fall back to ``netstat -tulpent`` on Linux."""
    if shutil.which('ss'):
        result = _parse_ss(hostname)
        if result[0] or result[1]:
            return result
        # ss returned nothing — maybe permissions; try netstat
    return _parse_netstat_linux(hostname)


_SS_PID_RE = re.compile(r'pid=(\d+)')
_SS_PROC_RE = re.compile(r'"([^"]+)"')


def _parse_ss(hostname: str) -> tuple[dict, set]:
    """Parse ``ss -tunap`` output."""
    conns: dict = {}
    alive: set = set()
    try:
        output = subprocess.check_output(
            ['ss', '-tunap'], timeout=10,
            stderr=subprocess.DEVNULL,
        ).decode('utf-8', errors='replace')
    except Exception as e:
        logging.debug(f"os_conn_table: ss -tunap failed: {e}")
        return conns, alive

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        state_or_proto = parts[0].lower()

        # Header line
        if state_or_proto in ('netid', 'state'):
            continue

        # ss output format:
        #   Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process
        # or when --no-header:
        #   tcp   ESTAB  0      0       10.0.0.5:22         10.0.0.1:54321     users:(("sshd",pid=1234,fd=3))
        proto_raw = parts[0].lower()
        if proto_raw in ('tcp', 'tcp6'):
            proto = 'TCP'
        elif proto_raw in ('udp', 'udp6'):
            proto = 'UDP'
        else:
            continue

        state = parts[1]
        if proto == 'TCP' and state not in _ACTIVE_TCP_STATES_SS:
            continue

        local_addr = parts[4]
        remote_addr = parts[5] if len(parts) > 5 else ''
        proc_info = parts[6] if len(parts) > 6 else ''

        # Parse local and remote
        l_ip, l_port, l_type = _split_addr_ss(local_addr)
        r_ip, r_port, r_type = _split_addr_ss(remote_addr)
        if not l_ip or not r_ip or not l_port or not r_port:
            continue
        if r_ip in ('0.0.0.0', '::', '*', ''):
            continue

        ip_type = l_type or r_type or 'IPv4'

        # Extract PID and process from the process info column
        pid_str = ''
        proc_name = ''
        if proc_info:
            m = _SS_PID_RE.search(proc_info)
            if m:
                pid_str = m.group(1)
            m2 = _SS_PROC_RE.search(proc_info)
            if m2:
                proc_name = m2.group(1)

        key = (l_ip, l_port, r_ip, r_port, proto)
        alive.add(key)
        if key not in conns:
            conns[key] = _make_conn(
                proto, l_ip, l_port, r_ip, r_port, ip_type,
                pid_str, proc_name, hostname,
            )

    return conns, alive


def _split_addr_ss(addr: str) -> tuple[str, str, str]:
    """Split ``ss`` address format (``ip:port`` or ``[ip]:port`` or
    ``*:port``) into ``(ip, port, ip_type)``.

    ``ss`` sometimes uses ``%iface`` suffixes on link-local IPv6 — strip
    those.
    """
    if not addr or addr == '*':
        return '', '', ''

    # Strip interface suffix (e.g. fe80::1%eth0:443)
    addr = re.sub(r'%[^:\]]+', '', addr)

    # Bracket notation [::1]:443
    if addr.startswith('['):
        m = re.match(r'\[([^\]]+)\]:(\d+|\*)', addr)
        if m:
            ip, port = m.group(1), m.group(2)
            if port == '*':
                return '', '', ''
            ip, ip_type = _normalize_ipv6(ip)
            return ip, port, ip_type
        return '', '', ''

    # ss uses "*" for wildcard
    if addr.startswith('*:'):
        return '', '', ''

    # IPv6 without brackets: last ":" separates port
    if addr.count(':') > 1:
        last = addr.rfind(':')
        ip_part = addr[:last]
        port_part = addr[last + 1:]
        if port_part == '*':
            return '', '', ''
        if port_part.isdigit():
            ip, ip_type = _normalize_ipv6(ip_part)
            return ip, port_part, ip_type
        return '', '', ''

    # IPv4:port
    parts = addr.rsplit(':', 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], parts[1], 'IPv4'
    return '', '', ''


def _parse_netstat_linux(hostname: str) -> tuple[dict, set]:
    """Parse ``netstat -tunape`` output on Linux (fallback when ss absent).

    Flags: ``-t`` TCP, ``-u`` UDP, ``-n`` numeric, ``-a`` all states,
    ``-p`` show PID/program, ``-e`` extended info.
    Note: ``-l`` is deliberately omitted — it restricts output to
    LISTEN-only sockets.  We need ESTABLISHED connections.
    """
    conns: dict = {}
    alive: set = set()
    try:
        output = subprocess.check_output(
            ['netstat', '-tunape'], timeout=10,
            stderr=subprocess.DEVNULL,
        ).decode('utf-8', errors='replace')
    except Exception as e:
        logging.debug(f"os_conn_table: netstat -tunape failed: {e}")
        return conns, alive

    # Example lines:
    #   tcp   0  0  10.0.0.5:22  10.0.0.1:54321  ESTABLISHED  1000  123456  1234/sshd
    #   udp   0  0  0.0.0.0:53   0.0.0.0:*                    0     0       567/named
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        proto_raw = parts[0].lower()
        if proto_raw in ('tcp', 'tcp6'):
            proto = 'TCP'
        elif proto_raw in ('udp', 'udp6'):
            proto = 'UDP'
        else:
            continue

        local_addr = parts[3]
        remote_addr = parts[4]

        # TCP needs ESTABLISHED
        if proto == 'TCP':
            if len(parts) < 7:
                continue
            state = parts[5]
            if state not in _ACTIVE_TCP_STATES_NETSTAT:
                continue
            pid_proc = parts[8] if len(parts) > 8 else ''
        else:
            # UDP has no state column
            pid_proc = parts[7] if len(parts) > 7 else parts[6] if len(parts) > 6 else ''

        l_ip, l_port, l_type = _split_addr(local_addr)
        r_ip, r_port, r_type = _split_addr(remote_addr)
        if not l_ip or not r_ip or not l_port or not r_port:
            continue
        if r_ip in ('0.0.0.0', '::', '*', ''):
            continue

        ip_type = l_type or r_type or 'IPv4'

        # pid_proc is like "1234/sshd" or "-"
        pid_str = ''
        proc_name = ''
        if pid_proc and '/' in pid_proc:
            pp = pid_proc.split('/', 1)
            pid_str = pp[0]
            proc_name = pp[1] if len(pp) > 1 else ''

        key = (l_ip, l_port, r_ip, r_port, proto)
        alive.add(key)
        if key not in conns:
            conns[key] = _make_conn(
                proto, l_ip, l_port, r_ip, r_port, ip_type,
                pid_str, proc_name, hostname,
            )

    return conns, alive


# ---------------------------------------------------------------------------
# macOS: netstat -anp tcp / netstat -anp udp
# ---------------------------------------------------------------------------

def _parse_netstat_macos(hostname: str) -> tuple[dict, set]:
    """Parse ``netstat -an`` on macOS (no PID info without lsof)."""
    conns: dict = {}
    alive: set = set()
    for proto_flag, proto_name in [('tcp', 'TCP'), ('udp', 'UDP')]:
        try:
            output = subprocess.check_output(
                ['netstat', '-anp', proto_flag], timeout=10,
                stderr=subprocess.DEVNULL,
            ).decode('utf-8', errors='replace')
        except Exception:
            continue

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            if parts[0] not in ('tcp4', 'tcp6', 'tcp46', 'udp4', 'udp6', 'udp46'):
                continue

            local_addr = parts[3]
            remote_addr = parts[4]

            if proto_name == 'TCP':
                state = parts[5] if len(parts) > 5 else ''
                if state not in _ACTIVE_TCP_STATES_NETSTAT:
                    continue

            l_ip, l_port = _split_macos(local_addr)
            r_ip, r_port = _split_macos(remote_addr)
            if not l_ip or not r_ip or not l_port or not r_port:
                continue
            if r_ip in ('*', '0.0.0.0', '::'):
                continue

            ip_type = 'IPv6' if ':' in l_ip else 'IPv4'
            if l_ip.startswith('::ffff:'):
                l_ip = l_ip[7:]
                ip_type = 'IPv4'
            if r_ip.startswith('::ffff:'):
                r_ip = r_ip[7:]
                ip_type = 'IPv4'

            key = (l_ip, l_port, r_ip, r_port, proto_name)
            alive.add(key)
            if key not in conns:
                conns[key] = _make_conn(
                    proto_name, l_ip, l_port, r_ip, r_port, ip_type,
                    '', '', hostname,
                )

    return conns, alive


def _split_macos(addr: str) -> tuple[str, str]:
    """Split macOS netstat address like ``10.0.0.1.443`` or ``*.80`` or
    ``fe80::1.443`` into ``(ip, port)``."""
    if not addr or addr == '*.*':
        return '', ''
    # IPv6 addresses contain ":"  — last "." separates port
    # IPv4 also uses "." for port separator on macOS netstat
    dot = addr.rfind('.')
    if dot <= 0:
        return '', ''
    ip = addr[:dot]
    port = addr[dot + 1:]
    if port == '*':
        return '', ''
    return ip, port


# ---------------------------------------------------------------------------
# Generic fallback
# ---------------------------------------------------------------------------

def _parse_netstat_generic(hostname: str) -> tuple[dict, set]:
    """Best-effort ``netstat -an`` parsing."""
    conns: dict = {}
    alive: set = set()
    try:
        output = subprocess.check_output(
            ['netstat', '-an'], timeout=10,
            stderr=subprocess.DEVNULL,
        ).decode('utf-8', errors='replace')
    except Exception:
        return conns, alive

    for line in output.splitlines():
        line = line.strip()
        parts = line.split()
        if len(parts) < 4:
            continue
        proto_raw = parts[0].lower()
        if proto_raw.startswith('tcp'):
            proto = 'TCP'
        elif proto_raw.startswith('udp'):
            proto = 'UDP'
        else:
            continue

        local_addr = parts[3]
        remote_addr = parts[4] if len(parts) > 4 else ''

        l_ip, l_port, l_type = _split_addr(local_addr)
        r_ip, r_port, r_type = _split_addr(remote_addr)
        if not l_ip or not r_ip or not l_port or not r_port:
            continue
        if r_ip in ('0.0.0.0', '::', '*', ''):
            continue

        ip_type = l_type or r_type or 'IPv4'
        key = (l_ip, l_port, r_ip, r_port, proto)
        alive.add(key)
        if key not in conns:
            conns[key] = _make_conn(
                proto, l_ip, l_port, r_ip, r_port, ip_type,
                '', '', hostname,
            )

    return conns, alive
