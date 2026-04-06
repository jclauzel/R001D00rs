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
import subprocess

_HOSTNAME = _platform.node()

# Try to import psutil for PID → process name resolution.
try:
    import psutil as _psutil
except ImportError:
    _psutil = None

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
    """
    hn = hostname or _HOSTNAME
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


def _resolve_process(pid_str: str) -> str:
    """Return process name for *pid_str*, or ``''``."""
    if not pid_str or pid_str == '-' or pid_str == '0':
        return ''
    if pid_str in _proc_cache:
        return _proc_cache[pid_str]
    if _psutil is not None:
        try:
            name = _psutil.Process(int(pid_str)).name()
            _proc_cache[pid_str] = name
            return name
        except Exception:
            pass
    _proc_cache[pid_str] = ''
    return ''


def _make_conn(proto: str, local_ip: str, local_port: str,
               remote_ip: str, remote_port: str, ip_type: str,
               pid_str: str, proc_name: str, hostname: str) -> dict:
    """Build a connection dict matching the plugin schema."""
    return {
        'process': proc_name or _resolve_process(pid_str) or 'Unknown',
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
# Windows: netstat -ano
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
            if state != 'ESTABLISHED':
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
        if proto == 'TCP' and state != 'ESTAB':
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
            if state != 'ESTABLISHED':
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
                if state != 'ESTABLISHED':
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
