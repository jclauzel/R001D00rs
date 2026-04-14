#!/usr/bin/env python3

import psutil
import subprocess
import csv
import signal
import functools
from concurrent.futures import ThreadPoolExecutor, as_completed
# --- Constants that must be defined early ---
DATABASE_EXPIRE_AFTER_DAYS = 7
DATABASE_EXPIRE_TIME_CHECK_INTERVAL = 600000
import os
import sys
import platform
import socket
import json
import logging
import time
import datetime
import requests
import maxminddb
import ipaddress
from collections import deque

# --- PySide6 imports (for Qt integration) ---
from PySide6.QtCore import QObject, Slot, Signal, QRunnable, QTimer, QByteArray, QUrl, QPoint, QSize, Qt, QThreadPool
from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
    QWidget, QTableWidget, QTableWidgetItem, QLabel, QPushButton, QComboBox, QGroupBox, QFrame, QMessageBox, QCheckBox, QSlider, QToolButton, QSplitter, QHeaderView, QTextEdit, QTabWidget, QMenu, QScrollArea, QLineEdit, QDialog, QDialogButtonBox, QFileDialog, QStyle)
from PySide6.QtGui import QIcon, QAction, QPixmap, QColor, QFont, QFontMetrics
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineScript, QWebEngineProfile, QWebEngineUrlRequestInterceptor
from PySide6.QtWebChannel import QWebChannel

# Import ConnectionCollectorPlugin for plugin system
from connection_collector_plugin import ConnectionCollectorPlugin
from plugins.os_conn_table import set_supplement_psutil_with_netstat as _set_supplement_psutil
from plugins.os_conn_table import _resolve_process as _resolve_process_fallback
from plugins.os_conn_table import get_os_connections as _get_os_connections
from plugins.os_conn_table import flush_all_caches as _flush_os_caches

# --- Constants that must be defined early ---
DB_DIR = "databases"
CONNECTION_DATABASES_DIR = "connection_databases"  # Subfolder for connection-history database files
MAX_TRAFFIC_HISTOGRAM_BARS = 20  # Maximum number of bars in the traffic histogram overlay
VERSION = "3.7.8" # Current script version

# --- Standard library imports ---
import os
import sys
import platform
import socket
import json
import logging

# --- PySide6 imports (for Qt integration) ---
from PySide6.QtCore import QObject, Slot, Signal, QRunnable, QTimer, QByteArray, QUrl, QPoint, QSize
from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
    QWidget, QTableWidget, QTableWidgetItem, QLabel, QPushButton, QComboBox, QGroupBox, QFrame, QMessageBox, QCheckBox, QSlider, QToolButton, QSplitter, QHeaderView, QTextEdit, QTabWidget, QMenu, QScrollArea, QLineEdit, QDialog, QDialogButtonBox, QFileDialog, QStyle)
from PySide6.QtGui import QIcon, QAction, QPixmap, QColor, QFont, QFontMetrics
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineScript, QWebEngineProfile, QWebEngineUrlRequestInterceptor
from PySide6.QtWebChannel import QWebChannel

# R001D00rs tcp_geo_map

# pip install psutil, maxminddb PySide6 opencv-python procmon-parser flask scapy

# using https://github.com/pointhi/leaflet-color-markers for colored map markers
# using https://github.com/sapics/ip-location-db/tree/main/geolite2-city this script is using the MaxMind GeoLite2 database and is attributed accordingly for its usage.
# using OpenStreetMap and leaflet for map display and location data

# Summary
# R001D00rs tcp_geo_map is a cross-platform desktop network visibility and threat-hunting tool built with Python and PySide6.


# --- Async DNS Worker using asyncio and aiodns ---
import asyncio
import aiodns
import threading
import queue
import weakref

class AsyncDNSWorker:
    """
    Async DNS resolver using asyncio and aiodns, running in a background thread.
    Use enqueue(ip) to schedule lookups. Results are cached and callback is called on resolve.
    """
    def __init__(self, cache, lock, on_resolve=None, max_queue=10000):
        self.cache = cache
        self.lock = lock
        self.on_resolve = on_resolve
        self.queue = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="AsyncDNSWorker")

    def enqueue(self, ip):
        try:
            self.queue.put_nowait(ip)
        except queue.Full:
            pass

    def enqueue_many(self, ips):
        for ip in ips:
            self.enqueue(ip)

    def stop(self):
        self._stop.set()
        # Put a dummy item to unblock the queue if waiting
        try:
            self.queue.put_nowait(None)
        except Exception:
            pass

    def start(self):
        self._thread.start()

    def join(self, timeout=None):
        self._thread.join(timeout=timeout)

    def _run_loop(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._worker(loop))

    async def _worker(self, loop):
        resolver = aiodns.DNSResolver(loop=loop)
        while not self._stop.is_set():
            try:
                ip = await loop.run_in_executor(None, self.queue.get)
            except Exception:
                continue
            if self._stop.is_set() or not ip:
                break
            # skip if already in cache
            with self.lock:
                if ip in self.cache:
                    try:
                        self.queue.task_done()
                    except Exception:
                        pass
                    continue
            # perform async resolution
            hostname = None
            try:
                result = await resolver.gethostbyaddr(ip)
                hostname = result.name if result and hasattr(result, 'name') else None
            except Exception:
                hostname = None
            # update cache
            try:
                with self.lock:
                    self.cache[ip] = hostname
            except Exception:
                pass
            # notify caller (UI) if positive result
            if hostname and self.on_resolve:
                try:
                    self.on_resolve(ip, hostname)
                except Exception:
                    pass
            try:
                self.queue.task_done()
            except Exception:
                pass
SCREENSHOTS_DIR = "screen_captures"  # Screenshot directory for captured map images

IPV4_DB_PATH = os.path.join(DB_DIR, "geolite2-city-ipv4.mmdb")
IPV6_DB_PATH = os.path.join(DB_DIR, "geolite2-city-ipv6.mmdb")
C2_TRACKER_DB_PATH = os.path.join(DB_DIR, "all.txt")
SETTINGS_FILE_NAME = "settings.json"

# Default logging level — overridden at startup by loggingLevel in settings.json
logging_level = "WARNING"  # Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL

# Mapping of level name strings to logging module constants
_LOGGING_LEVEL_MAP = {
    "DEBUG":    logging.DEBUG,
    "INFO":     logging.INFO,
    "WARNING":  logging.WARNING,
    "ERROR":    logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

# Configure logging early with a sensible default.
# The level is refreshed from settings.json by _load_logging_level_from_settings()
# which is called immediately after its definition below.
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s',
)


def _load_logging_level_from_settings():
    """Read loggingLevel from settings.json and apply it to the root logger.

    Called once at module startup so the configured level takes effect before
    the UI or any background threads are created.
    """
    global logging_level
    try:
        if os.path.exists(SETTINGS_FILE_NAME):
            with open(SETTINGS_FILE_NAME, 'r') as _f:
                _s = json.load(_f)
            _level_str = str(_s.get('loggingLevel', 'WARNING')).upper()
            if _level_str in _LOGGING_LEVEL_MAP:
                logging_level = _level_str
                logging.getLogger().setLevel(_LOGGING_LEVEL_MAP[_level_str])
    except Exception:
        pass


# Apply logging level from settings.json as early as possible
_load_logging_level_from_settings()

""" 
    You can pass --accept_eula as a startup parametter to the script to automate download and refresh 
    the Geolite and c2 tracker databases howver this means you fully agree to their licensing terms
"""
# ---------------------------------------------------------------------------
# Help / usage — must be checked before any other sys.argv processing so that
# the app exits immediately without requiring a display or any other deps.
# ---------------------------------------------------------------------------
_HELP_FLAGS = {"-h", "-?", "/?", "--h", "--help"}
if _HELP_FLAGS.intersection(sys.argv):
    print("""
Usage: python tcp_geo_map.py [OPTIONS]

Options:
  --accept_eula
      Automatically accept the EULA for the GeoLite2 and C2-Tracker databases
      and allow them to be downloaded/refreshed on startup. By passing this
      flag you confirm that you have read and agree to their respective
      licensing terms.

  --enable_server_mode
      Start the application in server mode. A Flask endpoint is started to
      collect connection data submitted by one or more remote agents.
      The server accepts at most MAX_SERVER_AGENTS (default 100) distinct
      agents.  New agents beyond this limit receive HTTP 429 (Too Many
      Requests).  Adjust the constant in the script to raise the cap.

  --enable_agent_mode <host>
      Start the application in agent mode. The app periodically POSTs its
      live connection data to the server at <host>. <host> may be a bare
      hostname/IP (e.g. "myserver") or a legacy full URL
      (e.g. "http://myserver:5000").

  --no_ui
      Run as a headless background agent — no window is shown and no taskbar
      button is created. Only meaningful when combined with --enable_agent_mode.

  --no_ui_off
      Explicitly disable agent headless mode and persist that choice to settings.json
      so future launches without any flag also show the UI. Takes precedence
      over any saved "agent_no_ui" value in settings.json.

  --force_complete_database_load
      When the database persistence layer is enabled, temporarily overrides the
      in-memory buffer size (max_connection_list_filo_buffer_size) with the
      database limit (max_connection_list_database_size from settings.json) so
      the entire stored history can be loaded and replayed via the time slider.
      Agents discovered in the database are added to the Agent Management pane
      even if they originate from another machine.  This flag has no effect when
      the database layer is set to "Disabled".

  -h, -?, /?, --h, --help
      Show this help message and exit.
""")
    sys.exit(0)

ACCEPT_EULA = "--accept_eula" in sys.argv


PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK = False # set to True to turn on and speedup application start time, False to disable. However this will keep track on disk to what IP addresses machine was connected to.
IP_DNS_NAME_CACHE_FILE = "ip_cache.json" # if PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK is set to true the application will save and load to disk the IP DNS Name resolution made as name resolution is slow from the database sub folder. Next time the application start it will reload this cache to speed up startup time of the application

CONNECTION_TABLE_MIN_WIDTH = 700
CONNECTION_TABLE_MIN_HEIGHT = 300   
MAP_TABLE_MIN_WIDTH = 800
MAP_TABLE_MIN_HEIGHT = 500
GEOLITE2_IPV4_DOWNLOAD_URL = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv4.mmdb"
GEOLITE2_IPV6_DOWNLOAD_URL = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv6.mmdb"
C2_TRACKER_DB_DOWNLOAD_URL = "https://github.com//montysecurity/C2-Tracker/raw/refs/heads/main/data/all.txt"
C2_TRACKER_HEADER = "C2-TRACKER LIST: "
GEOLITE2_IPV4_DOWNLOAD_IPV4_ABOUT_TITLE = GEOLITE2_IPV6_DOWNLOAD_IPV4_ABOUT_TITLE = "About GeoLite2 IPv4 Database"
GEOLITE2_IPV4_DOWNLOAD_IPV4_ABOUT_TEXT = GEOLITE2_IPV6_DOWNLOAD_IPV4_ABOUT_TEXT= f"GeoLite2 is created by MaxMind. Please carefully read the GeoLite2 GEOLITE2_LICENSE and GEOLITE2_EULA license files available at https://github.com/sapics/ip-location-db/tree/main/geolite2-city if you use these database.\n\n This package comes with certain restrictions and obligations, most notably:\n\n- You cannot prevent the library from updating the databases..\n\n- You cannot use the GeoLite2 data: \n\n   * for FCRA purposes, \n\n   * to identify specific households or individuals."
C2_TRACKER_DB_DOWNLOAD_ABOUT_TITLE = "C2-TRACKER Database"
C2_TRACKER_DB_DOWNLOAD_ABOUT_TEXT = f"C2 Tracker is a free-to-use-community-driven IOC feed that uses Shodan and Censys searches to collect IP addresses of known malware/botnet/C2 infrastructure. Check out: https://github.com/montysecurity/C2-Tracker"

# OpenStreetMap tile server configuration
TILE_OPENSTREETMAP_SERVER = "tile.openstreetmap.org"

# Leaflet resources configuration
RESOURCES_DIR = "resources"
LEAFLET_DIR = os.path.join(RESOURCES_DIR, "leaflet")
LEAFLET_CSS_URL = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
LEAFLET_JS_URL = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
LEAFLET_MARKER_RED_URL    = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png"
LEAFLET_MARKER_GREEN_URL  = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png"
LEAFLET_MARKER_BLUE_URL   = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-blue.png"
LEAFLET_MARKER_YELLOW_URL = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-yellow.png"
LEAFLET_MARKER_ORANGE_URL = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-orange.png"
LEAFLET_MARKER_VIOLET_URL = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-violet.png"
LEAFLET_MARKER_BLACK_URL  = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-black.png"
LEAFLET_MARKER_GREY_URL   = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-grey.png"
LEAFLET_MARKER_GOLD_URL   = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-gold.png"

LEAFLET_CSS_PATH = os.path.join(LEAFLET_DIR, "leaflet.css")
LEAFLET_JS_PATH = os.path.join(LEAFLET_DIR, "leaflet.js")
LEAFLET_MARKER_RED_PATH    = os.path.join(LEAFLET_DIR, "marker-icon-2x-red.png")
LEAFLET_MARKER_GREEN_PATH  = os.path.join(LEAFLET_DIR, "marker-icon-2x-green.png")
LEAFLET_MARKER_BLUE_PATH   = os.path.join(LEAFLET_DIR, "marker-icon-2x-blue.png")
LEAFLET_MARKER_YELLOW_PATH = os.path.join(LEAFLET_DIR, "marker-icon-2x-yellow.png")
LEAFLET_MARKER_ORANGE_PATH = os.path.join(LEAFLET_DIR, "marker-icon-2x-orange.png")
LEAFLET_MARKER_VIOLET_PATH = os.path.join(LEAFLET_DIR, "marker-icon-2x-violet.png")
LEAFLET_MARKER_BLACK_PATH  = os.path.join(LEAFLET_DIR, "marker-icon-2x-black.png")
LEAFLET_MARKER_GREY_PATH   = os.path.join(LEAFLET_DIR, "marker-icon-2x-grey.png")
LEAFLET_MARKER_GOLD_PATH   = os.path.join(LEAFLET_DIR, "marker-icon-2x-gold.png")

LEAFLET_RESOURCES_ABOUT_TITLE = "About Leaflet Resources and pointhi marker icons"
LEAFLET_RESOURCES_ABOUT_TEXT = """Leaflet is an open-source JavaScript library for interactive maps.\n\nThis application uses:\n- Leaflet library (https://leafletjs.com/)\n- Colored map markers from https://github.com/pointhi/leaflet-color-markers\n\nDownloading these resources locally will:\n- Speed up application startup time\n- Enable offline map functionality\n- Reduce dependency on external CDN availability\n\nBy downloading, you agree to comply with the Leaflet license (BSD 2-Clause) and respective marker icon licenses."""

HOSTNAME_ROW_INDEX = 0    # Index of the 'Hostname' column in the table
PROCESS_ROW_INDEX = 1     # Index of the 'Process' column in the table
PID_ROW_INDEX = 2         # Index of the 'PID' column in the table
SUSPECT_ROW_INDEX = 3     # Index of the 'Suspect' column in the table
PROTOCOL_ROW_INDEX = 4    # Index of the 'Protocol' column in the table (TCP/UDP)
LOCAL_ADDRESS_ROW_INDEX = 5    # Index of the 'Local Address' column in the table
LOCAL_PORT_ROW_INDEX = 6      # Index of the 'Local Port' column in the table
REMOTE_ADDRESS_ROW_INDEX = 7  # Index of the 'Remote Address' column in the table
REMOTE_PORT_ROW_INDEX = 8     # Index of the 'Remote Port' column in the table
NAME_ROW_INDEX = 9        # Index of the 'Name' column in the table
IP_TYPE_ROW_INDEX = 10     # Index of the 'IP Type' column in the table
WAY_ROW_INDEX = 11         # Index of the 'Way' column in the table (IN/OUT)
LOCATION_LAT_ROW_INDEX = 12   # Index of the 'Location' column in the table
LOCATION_LON_ROW_INDEX = 13  # Index of the 'Location' column in the table
BYTES_SENT_ROW_INDEX = 14    # Index of the 'Sent' column in the table
BYTES_RECV_ROW_INDEX = 15    # Index of the 'Recv' column in the table
PID_COLUMN_SIZE = 60
SUSPECT_COLUMN_SIZE = 30
PROTOCOL_COLUMN_SIZE = 55
PORTS_COLUMN_SIZE = 70
IP_TYPE_COLUMN_SIZE = 20

TIME_SLIDER_TEXT = "Time slider position: "

START_CAPTURE_BUTTON_TEXT = "Start capturing live connections"
STOP_CAPTURE_BUTTON_TEXT = "Stop capturing live connections" 

max_connection_list_filo_buffer_size = 1000  # Maximum number of connection snapshots to keep in memory. The larger this value the more memory will be used. When the max size is reached the oldest connection snapshot will be removed from memory.
show_tooltip = False # Show tooltips on map markers
map_refresh_interval = 1000  # Map refresh time in milliseconds
show_only_new_active_connections = False # Show only new connections in the table
show_only_remote_connections = False # Hide local connections (ie 127.0.0.1 ::1)
table_column_sort_index = -1  # Default column index to sort the table by the index
table_column_sort_reverse = False  # Default sort order
summary_table_column_sort_index = -1  # Default column index to sort the summary table by the index
summary_table_column_sort_reverse = False  # Default sort order for summary table
do_reverse_dns = True  # Set to False to disable reverse DNS lookups
do_resolve_public_ip = True  # Set to True to resolve public IP addresses to hostnames (may slow down refresh)
do_pulse_exit_points = True  # Set to True to animate a pulsing ring on agent/server exit-point circles
do_drawlines_between_local_and_remote = True  # Set to True to draw lines between local and remote endpoints on the map
do_c2_check = False
do_always_supplement_psutil_with_netstat_when_available = True  # When True, psutil connection data is always supplemented with netstat to catch any connections psutil may miss
_set_supplement_psutil(do_always_supplement_psutil_with_netstat_when_available)
do_capture_screenshots = False  # Set to True to capture screenshots of the map to disk
do_pause_table_sorting = False  # Set to True to pause table sorting without stopping updates
do_show_traffic_gauge = True   # Set to True to show sent/recv traffic gauges next to markers (requires Scapy/PCAP collector)
do_show_traffic_histogram = True  # Set to True to show the network traffic histogram overlay on the map
do_collect_connections_asynchronously = True  # Set to True to collect connections on a background thread (prevents UI hangs)
do_show_listening_connections = False  # Set to True to include LISTEN sockets in the connection list
do_scapy_force_use_interface_name = ""  # When non-empty, passed as iface= to Scapy sniff() (overrides auto-detection)
conn_table_column_order: list = []        # Visual column order for the main connection table (logical indices)
summary_table_column_order: list = []     # Visual column order for the summary table (logical indices)
conn_table_column_widths: list = []       # Persisted per-column widths for the main connection table
summary_table_column_widths: list = []    # Persisted per-column widths for the summary table
# Default summary table column order: Count (logical 10) moved to the last visual position.
# Columns: Hostname(0) Process(1) PID(2) C2(3) Protocol(4) LocalAddr(5) RemoteAddr(6)
#          Type(7) Way(8) Name(9) Sent(11) Recv(12) Count(10)
SUMMARY_TABLE_DEFAULT_COLUMN_ORDER: list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 10]
USE_LOCAL_LEAFLET_FALLBACK = True  # allow using local resources when CDN fails

# Database persistence layer globals
db_provider_name = "Disabled"       # "Disabled" | "SQLite" | "MongoDB" | "SQL Server" | "Oracle"
max_connection_list_database_size = 100000  # max snapshots kept in database; oldest are purged beyond this

# Server / Agent mode globals
enable_server_mode = False  # When True the app runs a Flask endpoint to collect agent data
enable_agent_mode = False   # When True the app periodically POSTs its connections to a server
agent_server_host = ""      # Hostname/IP of the server in agent mode (no scheme, no port)
agent_no_ui = False         # When True in agent mode the window is never shown (headless agent)
MAX_SERVER_AGENTS = 100     # Max distinct agents the server will accept; new agents beyond this get HTTP 429
FLASK_SERVER_PORT = 5000    # Port the Flask server listens on (server mode)
FLASK_AGENT_PORT = 5000     # Port the agent POSTs to (agent mode)
LOCAL_HOSTNAME = platform.node() or socket.gethostname()  # This machine's hostname

# Parse --enable_server_mode and --enable_agent_mode from command line
if "--enable_server_mode" in sys.argv:
    enable_server_mode = True
_agent_idx = None
for _i, _a in enumerate(sys.argv):
    if _a == "--enable_agent_mode" and _i + 1 < len(sys.argv):
        _agent_idx = _i
        break
if _agent_idx is not None:
    enable_agent_mode = True
    # Accept either a bare hostname ("myserver") or a legacy full URL
    # ("http://myserver:5000") for backward-compatibility
    _raw = sys.argv[_agent_idx + 1]
    if _raw.startswith("http://") or _raw.startswith("https://"):
        import urllib.parse as _urlparse
        _parsed = _urlparse.urlparse(_raw)
        agent_server_host = _parsed.hostname or ""
        if _parsed.port:
            FLASK_AGENT_PORT = _parsed.port
    else:
        agent_server_host = _raw
# --no_ui: run as a headless background agent (no window shown, no taskbar button)
if "--no_ui" in sys.argv:
    agent_no_ui = True
# --no_ui_off: explicitly disable headless mode and persist that to settings.json
_no_ui_off_requested = "--no_ui_off" in sys.argv
if _no_ui_off_requested:
    agent_no_ui = False
    _settings_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'settings.json')
    try:
        _s = {}
        if os.path.exists(_settings_path):
            with open(_settings_path, 'r') as _f:
                _s = json.load(_f)
        _s['agent_no_ui'] = False
        with open(_settings_path, 'w') as _f:
            json.dump(_s, _f, indent=4)
    except Exception as _e:
        logging.warning(f"--no_ui_off: could not update settings.json: {_e}")
# Mutual exclusion: agent takes precedence if both are set
if enable_server_mode and enable_agent_mode:
    enable_server_mode = False

# --force_complete_database_load: override in-memory buffer with DB size
force_complete_database_load = "--force_complete_database_load" in sys.argv



# Global cache and lock for thread-safe IP lookups
ip_cache = {}
cache_lock = threading.Lock()

# Global cache to track attempted public IP DNS resolutions to avoid repeated failures
public_ip_dns_attempts = {}  # {ip: datetime} - tracks when we attempted resolution
public_ip_dns_attempts_lock = threading.Lock()

PUBLIC_IP_ENQUEUE_MAX_CACHE_SIZE = 10000 # maximum number of public IPs to keep in the enqueue cache to avoid unbounded growth
PUBLIC_IP_ENQUEUE_TIMER_INTERVAL = 10000 # timer scavanger in milliseconds

# Global geolocation cache for performance
geo_cache = {}  # {ip: (lat, lng)}
geo_cache_lock = threading.Lock()

# Global process name cache by PID
process_cache = {}  # {pid: process_name}
process_cache_lock = threading.Lock()

class MapBridge(QObject):
    """Bridge class to enable JavaScript-to-Python communication for map marker clicks"""

    def __init__(self, viewer):
        super().__init__()
        self.viewer = viewer

    @Slot(str, str, str, str)
    def selectConnection(self, process, pid, remote, local):
        """Called from JavaScript when a map marker is clicked"""
        try:
            self.viewer.select_table_row_by_connection(process, pid, remote, local)
        except Exception as e:
            logging.error(f"Error selecting connection from map: {e}")

    @Slot(str, str, str, str, str, str, str, str)
    def pinConnection(self, process, pid, protocol, local, localport, remote, remoteport, ip_type):
        """Called from JavaScript when a map marker is clicked — pins it as yellow."""
        try:
            self.viewer.pin_connection_from_map(process, pid, protocol, local, localport, remote, remoteport, ip_type)
        except Exception as e:
            logging.error(f"Error pinning connection from map: {e}")

    @Slot(int)
    def notifyPopupClosed(self, generation):
        """Called from JavaScript when the user manually closes the pinned popup.
        Only honoured when *generation* matches the current counter, so stale
        close events from old markers are silently ignored."""
        try:
            if generation == self.viewer._pinned_popup_generation:
                self.viewer._pinned_popup_open = False
                logging.debug("Pinned popup closed by user (gen %d)", generation)
            else:
                logging.debug("Ignored stale popupclose (got gen %d, current %d)",
                              generation, self.viewer._pinned_popup_generation)
        except Exception as e:
            logging.error(f"Error handling popup close notification: {e}")

    @Slot(str)
    def setForegroundHost(self, hostname):
        """Called from JavaScript when the user clicks an agent circle or marker.
        Promotes *hostname* to the foreground layer and triggers a map re-render."""
        try:
            self.viewer.bring_to_top_layer(hostname)
        except Exception as e:
            logging.error(f"Error in setForegroundHost: {e}")

class VideoGeneratorSignals(QObject):
    """Signals for video generation worker"""
    finished = Signal(bool, str, dict)  # success, message, stats
    error = Signal(str)  # error message
    progress = Signal(int, int)  # current frame, total frames

class VideoGeneratorWorker(QRunnable):
    """
    Worker thread for generating MP4 video from screenshots.
    Runs in QThreadPool to avoid blocking the UI.
    """
    def __init__(self, screenshots_dir):
        super().__init__()
        self.setAutoDelete(False)  # caller holds ref; signals object must outlive the pool thread
        self.screenshots_dir = screenshots_dir
        self.signals = VideoGeneratorSignals()

    def run(self):
        """Execute the video generation in a background thread"""
        try:
            # Import cv2 here to avoid import errors in main thread
            try:
                import cv2
            except ImportError:
                self.signals.error.emit(
                    "OpenCV (cv2) is required to generate videos.\n\n"
                    "Please install it using:\n"
                    "pip install opencv-python\n\n"
                    "Then restart the application."
                )
                return

            # Check if screenshots directory exists
            if not os.path.exists(self.screenshots_dir):
                self.signals.error.emit(
                    f"Screenshot directory '{self.screenshots_dir}' does not exist.\n\n"
                    "Enable screenshot capture and capture some connections first."
                )
                return

            # Get all screenshot files
            screenshot_files = []
            for filename in os.listdir(self.screenshots_dir):
                if filename.startswith("tcp_geo_map_") and filename.endswith(".jpg"):
                    filepath = os.path.join(self.screenshots_dir, filename)
                    try:
                        mtime = os.path.getmtime(filepath)
                        screenshot_files.append((mtime, filepath, filename))
                    except Exception:
                        continue

            if len(screenshot_files) < 2:
                self.signals.error.emit(
                    f"Found only {len(screenshot_files)} screenshot(s).\n\n"
                    "At least 2 screenshots are required to generate a video.\n"
                    "Capture more connections with screenshot capture enabled."
                )
                return

            # Sort by modification time (oldest first)
            screenshot_files.sort(key=lambda x: x[0])

            # Generate output filename with current timestamp
            timestamp = datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
            output_filename = f"tcp_geo_map_{timestamp}.mp4"
            output_path = os.path.join(self.screenshots_dir, output_filename)

            # Read first image to get dimensions
            first_frame = cv2.imread(screenshot_files[0][1])
            if first_frame is None:
                self.signals.error.emit("Failed to read first screenshot")
                return

            height, width, _ = first_frame.shape
            logging.info(f"Video dimensions: {width}x{height}")

            # Define codec and create VideoWriter object
            # Use mp4v codec for MP4 format (widely compatible)
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            fps = 1  # 1 frame per second (adjust as needed)

            video_writer = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

            if not video_writer.isOpened():
                self.signals.error.emit("Failed to create video writer")
                return

            # Write each frame to video
            frames_written = 0
            total_frames = len(screenshot_files)

            for idx, (mtime, filepath, filename) in enumerate(screenshot_files):
                try:
                    frame = cv2.imread(filepath)
                    if frame is not None:
                        # Ensure frame has same dimensions as first frame
                        if frame.shape[0] != height or frame.shape[1] != width:
                            frame = cv2.resize(frame, (width, height))

                        video_writer.write(frame)
                        frames_written += 1

                        # Emit progress signal
                        self.signals.progress.emit(frames_written, total_frames)

                        logging.debug(f"Added frame {frames_written}/{total_frames}: {filename}")
                    else:
                        logging.warning(f"Failed to read screenshot: {filename}")
                except Exception as e:
                    logging.warning(f"Error adding frame {filename}: {e}")
                    continue

            # Release the video writer
            video_writer.release()

            if frames_written > 0:
                stats = {
                    'output_path': output_path,
                    'frames_written': frames_written,
                    'total_files': len(screenshot_files),
                    'fps': fps,
                    'width': width,
                    'height': height
                }

                success_msg = (
                    f"Successfully generated video:\n{output_path}\n\n"
                    f"Frames: {frames_written}/{len(screenshot_files)}\n"
                    f"Duration: {frames_written} seconds @ {fps} FPS\n"
                    f"Resolution: {width}x{height}"
                )

                self.signals.finished.emit(True, success_msg, stats)
                logging.info(f"Video generated: {output_path} ({frames_written} frames)")
            else:
                self.signals.error.emit("No frames were written to video")

        except Exception as e:
            error_msg = f"Failed to generate video:\n{str(e)}\n\nCheck the logs for more details."
            self.signals.error.emit(error_msg)
            logging.error(f"Error generating video: {e}")

class ConnectionCollectorSignals(QObject):
    """Signals for the async connection collector worker."""
    finished = Signal(object, object)  # connections (list), slider_position (int | None)

class SummaryAggregationSignals(QObject):
    """Signals emitted by the background summary-table aggregation worker."""
    finished = Signal(object, int, int)  # sorted_stats (list), total_unique, total_connections

class SummaryAggregationWorker(QRunnable):
    """Aggregate connection_list into summary stats on a pool thread.

    The heavy loop (snapshot iteration, IP parsing, is_routable checks,
    dict accumulation) runs off the GUI thread.  Only the final table
    population happens on the UI thread via the *finished* signal.
    """

    def __init__(self, snapshot, filter_remote):
        super().__init__()
        self.setAutoDelete(False)
        self.snapshot = snapshot
        self.filter_remote = filter_remote
        self.signals = SummaryAggregationSignals()

    def run(self):
        try:
            connection_stats = {}
            for timeline_entry in self.snapshot:
                connection_list = timeline_entry.get('connection_list', [])
                for conn in connection_list:
                    process = conn.get('process', '')
                    pid = conn.get('pid', '')
                    suspect = conn.get('suspect', '')
                    protocol = conn.get('protocol', '')
                    local = conn.get('local', '')
                    remote = conn.get('remote', '')
                    ip_type = conn.get('ip_type', '')
                    name = conn.get('name', '')
                    way = 'IN' if (conn.get('state', '') == 'LISTEN' or conn.get('inbound')) else 'OUT'

                    if self.filter_remote:
                        remote_ip = _extract_remote_ip(remote, ip_type)
                        if not is_routable(remote_ip):
                            continue

                    hostname = conn.get('hostname', '')
                    key = (hostname, process, pid, suspect, protocol, local, remote, ip_type, way, name)

                    b_sent = conn.get('bytes_sent', 0) or 0
                    b_recv = conn.get('bytes_recv', 0) or 0

                    if key in connection_stats:
                        entry = connection_stats[key]
                        entry['count'] += 1
                        entry['bytes_sent'] += b_sent
                        entry['bytes_recv'] += b_recv
                    else:
                        connection_stats[key] = {'count': 1, 'bytes_sent': b_sent, 'bytes_recv': b_recv}

            sorted_stats = sorted(connection_stats.items(), key=lambda x: x[1]['count'], reverse=True)
            total_unique = len(sorted_stats)
            total_connections = sum(s['count'] for _, s in sorted_stats)
        except Exception as e:
            logging.error(f"SummaryAggregationWorker error: {e}")
            sorted_stats = []
            total_unique = 0
            total_connections = 0

        try:
            self.signals.finished.emit(sorted_stats, total_unique, total_connections)
        except RuntimeError:
            logging.debug("SummaryAggregationWorker: signal emit skipped (source deleted)")

class ConnectionCollectorWorker(QRunnable):
    """
    Runs get_active_tcp_connections() on a QThreadPool thread so the UI
    thread stays responsive while connections are being enumerated / enriched.
    """
    def __init__(self, collect_fn, slider_position):
        super().__init__()
        self.setAutoDelete(False)  # caller holds ref; signals object must outlive the pool thread
        self.collect_fn = collect_fn
        self.slider_position = slider_position
        self.signals = ConnectionCollectorSignals()

    def run(self):
        try:
            connections = self.collect_fn(self.slider_position)
        except Exception as e:
            logging.error(f"ConnectionCollectorWorker error: {e}")
            connections = []
        try:
            self.signals.finished.emit(connections, self.slider_position)
        except RuntimeError:
            logging.debug("ConnectionCollectorWorker: signal emit skipped (source deleted)")

class DNSWorker:
    """
    Background DNS worker pool that continuously warms the ip_cache.

    - Receives IPs via `enqueue_many` / `enqueue`.
    - Resolves with blocking socket.gethostbyaddr across multiple threads (off the UI thread).
    - Updates shared `ip_cache` under `cache_lock`.
    - Optionally calls `on_resolve(ip, hostname)` for each positive resolution
      (this callback must be thread-safe; the viewer uses QTimer.singleShot to marshal to UI).
    - Call `stop()` to request shutdown and `join()` to wait for termination.
    """
    def __init__(self, cache, lock, on_resolve=None, max_queue=10000, idle_sleep=0.05,
                 num_workers=16):
        self.cache = cache
        self.lock = lock
        self.on_resolve = on_resolve
        self.queue = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self.idle_sleep = idle_sleep
        self.num_workers = num_workers
        self._threads = []

    def enqueue(self, ip):
        try:
            # non-blocking; drop if full
            self.queue.put_nowait(ip)
        except queue.Full:
            pass

    def enqueue_many(self, ips):
        for ip in ips:
            self.enqueue(ip)

    def stop(self):
        self._stop.set()

    def start(self):
        """Launch the pool of worker threads."""
        for i in range(self.num_workers):
            t = threading.Thread(target=self._worker, daemon=True,
                                 name=f"DNSWorker-{i}")
            t.start()
            self._threads.append(t)

    def join(self, timeout=None):
        for t in self._threads:
            t.join(timeout=timeout)

    def _worker(self):
        while not self._stop.is_set():
            try:
                ip = self.queue.get(timeout=0.5)
            except queue.Empty:
                # small idle sleep to reduce CPU when queue empty
                time.sleep(self.idle_sleep)
                continue

            if not ip:
                try:
                    self.queue.task_done()
                except Exception:
                    pass
                continue

            # skip if already in cache
            with self.lock:
                if ip in self.cache:
                    try:
                        self.queue.task_done()
                    except Exception:
                        pass
                    continue

            # perform resolution
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = None

            # update cache
            try:
                with self.lock:
                    self.cache[ip] = hostname
            except Exception:
                pass

            # notify caller (UI) if positive result
            if hostname and self.on_resolve:
                try:
                    self.on_resolve(ip, hostname)
                except Exception:
                    pass

            try:
                self.queue.task_done()
            except Exception:
                pass


class TileRequestInterceptor(QWebEngineUrlRequestInterceptor):
    """Injects required User-Agent and Referer headers into OpenStreetMap tile requests."""
    def interceptRequest(self, info):
        if b'openstreetmap.org' in info.requestUrl().host().encode():
            info.setHttpHeader(b'User-Agent',
                f'TCPGeoMap/{VERSION} (+https://github.com/jclauzel/R001D00rs)'.encode())
            info.setHttpHeader(b'Referer', b'https://www.openstreetmap.org/')


# ---------------------------------------------------------------------------
# Built-in connection collector plugin (psutil + netstat)
# ---------------------------------------------------------------------------

class PsutilCollector(ConnectionCollectorPlugin):
    """Default collector — enumerates live TCP/UDP connections via psutil."""

    _SLEEP_GAP_THRESHOLD = 30.0  # seconds – same as ScapyLiveCollector

    def __init__(self):
        super().__init__()
        self._last_collect_time: float = 0.0

    @property
    def name(self) -> str:
        return "psutil (live connections)"

    @property
    def description(self) -> str:
        return "Enumerate live TCP (ESTABLISHED) and UDP connections using psutil. On Windows, supplements UDP with netstat."

    def collect_raw_connections(self) -> list:
        """Return a list of raw connection dicts from psutil.

        Each dict contains: process, pid, protocol, local, localport,
        remote, remoteport, ip_type, hostname.

        When ``do_always_supplement_psutil_with_netstat_when_available`` is
        True, delegates to ``get_os_connections()`` from ``os_conn_table``
        which merges psutil with the platform netstat parser and has a
        multi-tier process name resolver (psutil → tasklist → netstat).
        This eliminates "Unknown" process names for connections where
        psutil alone can't resolve the PID (race conditions on short-lived
        connections, AccessDenied on protected processes, etc.).
        """

        # ---- Sleep / resume detection ----------------------------------------
        import time as _time
        now = _time.monotonic()
        if self._last_collect_time:
            gap = now - self._last_collect_time
            if gap > self._SLEEP_GAP_THRESHOLD:
                logging.info(
                    f"PsutilCollector: detected sleep/resume "
                    f"(gap={gap:.1f}s) — flushing process caches"
                )
                _flush_os_caches()
        self._last_collect_time = now

        # --- Fast path: supplement enabled → use os_conn_table merge -----
        if do_always_supplement_psutil_with_netstat_when_available:
            merged_conns, _ = _get_os_connections(LOCAL_HOSTNAME)
            return list(merged_conns.values())

        # --- Original psutil-only path -----------------------------------
        raw = []

        # Get all connections once (both TCP and UDP)
        all_connections = psutil.net_connections(kind='inet')

        # On Windows, psutil's GetExtendedUdpTable does not report remote
        # addresses for connected UDP sockets — supplement with netstat.
        udp_remote_lookup = {}
        if platform.system() == "Windows":
            try:
                udp_remote_lookup = PsutilCollector._parse_netstat_udp_static()
            except Exception:
                pass

        for conn in all_connections:
            is_tcp = (conn.type == socket.SOCK_STREAM)
            is_udp = (conn.type == socket.SOCK_DGRAM)
            protocol = "TCP" if is_tcp else ("UDP" if is_udp else "Unknown")

            # For TCP, only active states (ESTABLISHED, SYN_SENT, SYN_RECV);
            # for UDP, all.  Optionally include LISTEN when setting is on.
            is_listen = False
            if is_tcp and conn.status not in (
                psutil.CONN_ESTABLISHED,
                psutil.CONN_SYN_SENT,
                psutil.CONN_SYN_RECV,
            ):
                if do_show_listening_connections and conn.status == psutil.CONN_LISTEN:
                    is_listen = True
                else:
                    continue

            try:
                pid = conn.pid

                # Resolve process name (with cache)
                if pid:
                    with process_cache_lock:
                        if pid in process_cache:
                            process_name = process_cache[pid]
                        else:
                            try:
                                p = psutil.Process(pid)
                                process_name = p.name()
                            except Exception:
                                process_name = ''
                            # Fallback: tasklist / os_conn_table resolver
                            # (handles AccessDenied for system/protected PIDs)
                            if not process_name:
                                process_name = _resolve_process_fallback(str(pid))
                            if process_name:
                                process_cache[pid] = process_name
                            else:
                                process_name = "Unknown"
                else:
                    process_name = "Unknown"

                laddr = getattr(conn, "laddr", None)
                raddr = getattr(conn, "raddr", None)

                local_addr = f"{laddr.ip}" if laddr else ""
                local_port = str(getattr(laddr, "port", "")) if laddr else ""

                # Determine if we have a real remote address
                has_real_raddr = False
                if raddr:
                    raddr_ip = getattr(raddr, "ip", None)
                    raddr_port = getattr(raddr, "port", None)
                    if raddr_ip and raddr_ip not in ("0.0.0.0", "::", "*", "") and raddr_port:
                        has_real_raddr = True

                if has_real_raddr:
                    remote_addr = f"{raddr.ip}"
                    remote_port = str(raddr.port)
                else:
                    if is_udp and udp_remote_lookup:
                        pid_str = str(pid) if pid else ""
                        ns_remote = udp_remote_lookup.get((local_addr, local_port, pid_str))
                        if ns_remote:
                            remote_addr, remote_port = ns_remote
                        else:
                            remote_addr = "*"
                            remote_port = "*"
                    elif is_udp:
                        remote_addr = "*"
                        remote_port = "*"
                    elif is_listen:
                        remote_addr = "*"
                        remote_port = "*"
                    else:
                        remote_addr = ""
                        remote_port = ""

                # Determine IP type
                family = getattr(conn, "family", None)
                ip_type = "IPv4" if family == socket.AF_INET else ("IPv6" if family == socket.AF_INET6 else "")

                # Label unresolved port-53 connections as DNS
                if ( process_name == "" or process_name == "Unknown") and remote_port == "53":
                    process_name = "DNS (System)"

                raw.append({
                    'process': process_name,
                    'pid': str(pid) if pid else "",
                    'protocol': protocol,
                    'local': local_addr,
                    'localport': local_port,
                    'remote': remote_addr,
                    'remoteport': remote_port,
                    'ip_type': ip_type,
                    'hostname': LOCAL_HOSTNAME,
                    'state': 'LISTEN' if is_listen else '',
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        return raw

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_netstat_udp_static():
        """Parse ``netstat -ano`` for UDP remote addresses (Windows only).

        Returns dict: (local_ip, local_port, pid) -> (remote_ip, remote_port)
        """
        lookup = {}
        try:
            output = subprocess.check_output(
                ['netstat', '-ano'], timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
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
                # Split local and remote into ip:port
                if ']:' in local_part:
                    l_ip = local_part.rsplit(':', 1)[0].strip('[]')
                    l_port = local_part.rsplit(':', 1)[1]
                else:
                    l_ip, l_port = local_part.rsplit(':', 1)
                if ']:' in remote_part:
                    r_ip = remote_part.rsplit(':', 1)[0].strip('[]')
                    r_port = remote_part.rsplit(':', 1)[1]
                else:
                    r_ip, r_port = remote_part.rsplit(':', 1)
                lookup[(l_ip, l_port, pid_str)] = (r_ip, r_port)
        except Exception:
            pass
        return lookup


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=4096)
def _format_bytes(num_bytes):
    """Return a human-readable byte string (e.g. '1.2 MB')."""
    if not num_bytes:
        return ''
    num_bytes = int(num_bytes)
    if num_bytes == 0:
        return '0 B'
    k = 1024
    sizes = ('B', 'KB', 'MB', 'GB', 'TB')
    i = min(int(num_bytes > 0 and (num_bytes).bit_length() - 1) // 10, len(sizes) - 1)
    val = num_bytes / (k ** i)
    return f'{val:.1f} {sizes[i]}'

def _make_bytes_item(num_bytes):
    """Create a QTableWidgetItem that displays a human-readable byte string
    but stores the raw integer in Qt.UserRole so that column sorting can
    compare numerically instead of lexicographically."""
    raw = int(num_bytes) if num_bytes else 0
    item = QTableWidgetItem(_format_bytes(raw))
    item.setData(Qt.UserRole, raw)
    return item

@functools.lru_cache(maxsize=4096)
def _extract_remote_ip(remote: str, ip_type: str) -> str:
    """Extract the bare IP address from a remote-address string.

    Handles the common patterns produced by the connection collectors:
    - ``'1.2.3.4:443'`` → ``'1.2.3.4'``
    - ``'1.2.3.4 (example.com)'`` → ``'1.2.3.4'``
    IPv6 addresses are returned as-is (no port suffix stripping).
    """
    if ip_type == 'IPv4':
        return remote.split(':')[0].split(' (')[0]
    return remote.split(' (')[0]

@functools.lru_cache(maxsize=4096)
def is_routable(ip_str: str) -> bool:
    """Return True if *ip_str* is a publicly routable (non-private) IP address.

    Uses :mod:`ipaddress` so every RFC-1918 / RFC-4193 / loopback / link-local
    address is treated as non-routable, matching the intent of the
    'Hide local connections' filter.
    Returns False for any value that is not a valid IP address.
    """
    if ip_str == '*':
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return not ip.is_private
    except ValueError:
        return False

def _discover_collector_plugins():
    """Scan the ``plugins/`` directory for ConnectionCollectorPlugin subclasses.

    Returns a list of *instances* (built-in PsutilCollector is always first).
    """
    import importlib, importlib.util, inspect

    collectors = [PsutilCollector()]

    plugins_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plugins')
    if not os.path.isdir(plugins_dir):
        return collectors

    # Ensure the project root is on sys.path so plugin modules can
    # ``from connection_collector_plugin import ...`` regardless of how
    # the application was launched.
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    for fname in sorted(os.listdir(plugins_dir)):
        if not fname.endswith('.py') or fname.startswith('_'):
            continue
        filepath = os.path.join(plugins_dir, fname)
        module_name = f"plugins.{fname[:-3]}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for _attr_name in dir(mod):
                obj = getattr(mod, _attr_name)
                if (inspect.isclass(obj)
                        and issubclass(obj, ConnectionCollectorPlugin)
                        and obj is not ConnectionCollectorPlugin
                        and obj is not PsutilCollector):
                    collectors.append(obj())
        except Exception as e:
            logging.warning(f"Failed to load plugin {fname}: {e}")

    return collectors


class TCPConnectionViewer(QMainWindow):
    # Colors available for agent assignment (round-robin).
    # Excluded colors (reserved by the local-host UI):
    #   blue   = new connections,   red    = suspect/C2,
    #   yellow = pinned marker,     gold   = too similar to yellow.
    # green is included but reserved as the default for the local server.
    _AGENT_COLOR_PALETTE = ['green', 'gold', 'yellow', 'orange', 'violet', 'black', 'grey']

    # Column-index → connection-dict key mapping used by _conn_matches_filters().
    # Defined once at class level to avoid rebuilding 12 lambdas on every call.
    _COL_TO_KEY = {
        HOSTNAME_ROW_INDEX:        lambda c: c.get('hostname', ''),
        PROCESS_ROW_INDEX:         lambda c: c.get('process', ''),
        PID_ROW_INDEX:             lambda c: c.get('pid', ''),
        SUSPECT_ROW_INDEX:         lambda c: c.get('suspect', ''),
        PROTOCOL_ROW_INDEX:        lambda c: c.get('protocol', 'TCP'),
        LOCAL_ADDRESS_ROW_INDEX:   lambda c: c.get('local', ''),
        LOCAL_PORT_ROW_INDEX:      lambda c: c.get('localport', ''),
        REMOTE_ADDRESS_ROW_INDEX:  lambda c: c.get('remote', ''),
        REMOTE_PORT_ROW_INDEX:     lambda c: c.get('remoteport', ''),
        NAME_ROW_INDEX:            lambda c: c.get('name', ''),
        IP_TYPE_ROW_INDEX:         lambda c: c.get('ip_type', ''),
        WAY_ROW_INDEX:             lambda c: 'IN' if c.get('state', '') == 'LISTEN' or c.get('inbound') else 'OUT',
    }

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"TCP/UDP Geo Map - R001D00rs - v {VERSION}")
        self.setGeometry(100, 100, 1200, 800)
        # pending restore info will be applied on first showEvent to avoid races
        self._pending_restore = None

        # Initialize saved map state (will be loaded from settings if available)
        self.saved_map_center_lat = None
        self.saved_map_center_lng = None
        self.saved_map_zoom = None
        
        # Initialize database readers
        self.reader_ipv4 = None
        self.reader_ipv6 = None
        self.reader_c2_tracker = None
        self.reader_c2_tracker_set = None  # Fast O(1) lookup set
        self._geo_cache = {}  # (ip_address, ip_type) -> (lat, lng) — avoids repeated maxminddb lookups
        self.connections = []
        self._last_map_connections = []  # fully-processed connections for map re-renders
        self._async_collection_in_progress = False  # guard: only one background collection at a time
        self._sync_collection_in_progress = False   # guard: prevent sync re-entrancy (defensive)

        # Pinned (double-clicked) connection — persists across refreshes, shown as yellow marker
        self._pinned_connection = None
        self._pinned_popup_open = False  # True while the pinned popup should stay open
        self._pinned_popup_generation = 0  # Monotonic counter — stale JS close events are ignored
        self._click_focus_conn = None  # Single-click focus — dict identifying the connection to auto-open popup for

        # Deferred single-click timer — allows double-click to cancel the single-click action
        self._click_timer = QTimer()
        self._click_timer.setSingleShot(True)
        self._click_timer.timeout.connect(self._execute_deferred_click)
        self._pending_click = None  # (row, column) awaiting execution

        # HTTP session for public IP checks (connection pooling)
        self._http_session = requests.Session()
        self._public_ip_cache = ""
        self._public_ip_cache_time = 0.0
        self._public_ip_cache_lock = threading.Lock()  # guards _public_ip_cache/_public_ip_cache_time
        self._last_local_addrs: frozenset = frozenset()  # for VPN/network-change detection

        # --- Server / Agent mode runtime state ---
        # Server mode: cache of latest submissions from each agent
        # Key = hostname (str), Value = dict with keys:
        #   hostname, ip_addresses, lat, lng, connections (list of connection dicts)
        self._agent_cache = {}          # protected by _agent_cache_lock
        self._agent_cache_lock = threading.Lock()
        self._agent_posted_since_last_cycle = set()  # hostnames that POSTed since last timer cycle (protected by _agent_cache_lock)
        self._agent_inactive_strikes = {}  # hostname -> consecutive cycles without a POST
        self._last_strike_advance_time = 0.0  # monotonic timestamp of last strike advancement
        self._last_agent_count = 0
        self._flask_thread = None       # daemon thread running Flask
        self._werkzeug_server = None    # werkzeug BaseServer instance (stoppable)
        # Per-agent color assignment: hostname -> color name (e.g. 'violet')
        # Colors are drawn round-robin from the agent palette (excludes colors
        # reserved for the UI: red=suspect, blue=new, yellow=pinned).
        # green is palette[0] but is reserved for LOCAL_HOSTNAME (the server),
        # so the round-robin index starts at 1 to skip it for remote agents.
        self._agent_colors = {}         # hostname -> color name
        self._agent_colors[LOCAL_HOSTNAME] = 'green'   # server default
        self._agent_hidden = {}         # hostname -> True if hidden on map
        self._agent_color_index = 1     # start at 1 — index 0 (green) reserved for server
        # Database persistence layer (None when disabled)
        self._db_provider = None
        self._db_queue = None       # queue.Queue — created when a provider is activated
        self._db_thread = None      # daemon thread consuming _db_queue
        self._db_stop = threading.Event()
        # Agent mode: HTTP session with short timeout for POSTing to server
        self._agent_http_session = requests.Session()
        self._agent_http_session.headers.update({'Content-Type': 'application/json'})
        # Background thread for non-blocking agent POSTs
        self._agent_post_pending = None          # latest payload (protected by _agent_post_lock)
        self._agent_post_lock = threading.Lock()
        self._agent_post_event = threading.Event()
        self._agent_post_stop = threading.Event()
        self._agent_post_thread = threading.Thread(
            target=self._agent_post_worker, daemon=True, name="AgentPostWorker")
        # NOTE: thread is started after init_ui() to avoid a heap-corruption race
        # (STATUS_HEAP_CORRUPTION / 0xC0000374) where background threads allocate
        # while QWebEngineView is initialising Chromium's PartitionAlloc on startup.
        self._agent_rejected_429 = False  # True when server returned HTTP 429 (agent limit reached)
        self._agent_server_unreachable = False  # True when agent cannot reach the server

        # Foreground agent: the hostname whose connections are rendered with the
        # standard localhost colour scheme (green/blue/yellow/red).  All other
        # agents (including localhost when demoted) render in their assigned
        # palette colour (grey for localhost when demoted).
        self._foreground_hostname = LOCAL_HOSTNAME

        # Summary table needs update flag
        self._summary_needs_update = True

        self.load_ip_cache()
 
        # Start persistent DNS worker that warms the ip_cache in background.
        # When a hostname is resolved we schedule a debounced UI refresh.
        self._dns_update_scheduled = False
        self._dns_update_lock = threading.Lock()

        _viewer_ref = weakref.ref(self)

        def _dns_notify(ip, hostname):
            # worker thread -> schedule debounced UI update on main thread.
            # Use a weakref so the lambda cannot keep the viewer alive after
            # closeEvent, preventing slots from firing on a destroyed object.
            def _deferred_dns():
                viewer = _viewer_ref()
                if viewer is not None:
                    viewer._on_dns_resolved(ip, hostname)
            try:
                QTimer.singleShot(0, _deferred_dns)
            except Exception:
                # fallback: no UI notification available
                pass

        # Use AsyncDNSWorker instead of DNSWorker for non-blocking DNS
        self.dns_worker = AsyncDNSWorker(ip_cache, cache_lock, on_resolve=_dns_notify)
        # NOTE: started after init_ui() — see _agent_post_thread note above.

        # Initialize thread pool for async operations (video generation, etc.)
        self.thread_pool = QThreadPool()
        self.thread_pool.setMaxThreadCount(2)  # Limit concurrent background tasks

        # --- Connection collector plugin system ---
        self._collector_plugins = _discover_collector_plugins()
        _default_collector = next((p for p in self._collector_plugins if p.name == "Scapy Live Capture"), None)
        self._active_collector = _default_collector if _default_collector is not None else self._collector_plugins[0]

        # Set up QWebChannel for JavaScript-to-Python communication (map marker clicks)
        self.map_bridge = MapBridge(self)
        self.channel = QWebChannel()
        self.channel.registerObject('mapBridge', self.map_bridge)

        # Inject required OSM tile headers (User-Agent + Referer) to satisfy OSM tile usage policy
        self._tile_interceptor = TileRequestInterceptor()
        QWebEngineProfile.defaultProfile().setUrlRequestInterceptor(self._tile_interceptor)

        # Video button flash animation timer
        self._video_btn_flash_timer = None
        self._video_btn_flash_state = False
        self._video_generating = False  # Flag to block clicks during generation

        # Start capture button flash animation timer
        self._start_capture_flash_timer = None
        self._start_capture_flash_state = False
        self._start_capture_flash_stop_timer = None  # Timer to auto-stop flash after duration

        # Stop button wave animation timer
        self._stop_btn_wave_timer = None
        self._stop_btn_wave_index = 0
        self._stop_btn_wave_patterns = ["....", ">...", ".>..", "..>.", "...>"]

        self.load_databases()
        self._check_and_download_leaflet_resources()

        # Load settings BEFORE init_ui() so saved map position is available when HTML is generated
        # Returns True if settings were loaded, None if this is first run
        self._is_first_run = (self._load_settings_early() is None)

        self.init_ui()

        # Apply UI-dependent settings after UI is created
        self._apply_settings_to_ui()

        # Start background threads now that QWebEngineView / Chromium heap is
        # fully initialised.  Starting them earlier races with PartitionAlloc
        # and causes intermittent STATUS_HEAP_CORRUPTION (0xC0000374) crashes.
        self._agent_post_thread.start()
        self.dns_worker.start()

        # Start Flask server if server mode was enabled (via CLI or settings)
        if enable_server_mode:
            self._start_flask_server()

        # When --force_complete_database_load is requested but no DB provider was
        # activated by _apply_settings_to_ui (e.g. db_provider_name is "Disabled"
        # or settings.json is absent on a different machine), automatically fall
        # back to SQLite — the standard file-based format — so the user can replay
        # a copied database without having to reconfigure settings first.
        if force_complete_database_load and self._db_provider is None:
            logging.info(
                "--force_complete_database_load: no DB provider active, "
                "auto-activating SQLite to load history.")
            self._activate_db_provider("SQLite")

        # Set up timer to refresh connections periodically
        self.timer.timeout.connect(self.refresh_connections)
        self.timer_replay_connections.timeout.connect(self.replay_connections)

        if force_complete_database_load:
            # Database-replay mode: the in-memory buffer has been pre-filled from
            # the database.  Do NOT start live capture — the purpose of this flag
            # is to browse / replay historical data (potentially from another
            # machine).  Leave the UI in the stopped/replay state so the slider
            # and the replay toggle button are immediately usable.
            #
            # Explicitly re-sync the slider here (authoritative pass) so the
            # displayed count always matches the actual buffer — regardless of
            # whether _restore_snapshots_from_db ran before or after the slider
            # was constructed.
            _n = len(self.connection_list)
            self.slider.blockSignals(True)
            self.slider.setMaximum(self.connection_list_counter)
            self.slider.setValue(self.connection_list_counter)
            self.slider.blockSignals(False)
            self.slider_value_label.setText(
                TIME_SLIDER_TEXT + str(_n) + "/" + str(_n))
            self.start_capture_btn.setVisible(True)
            self.stop_capture_btn.setVisible(False)
            self.toggle_button.setVisible(True)
            self._stop_capture_button_flash()  # ensure no stale flash state
            # Render the last loaded snapshot once the event loop is running so
            # the map HTML has had a chance to start loading.
            _last_idx = max(0, _n - 1)
            QTimer.singleShot(0, lambda: self.refresh_connections(slider_position=_last_idx))
        else:
            self.timer.start(map_refresh_interval)  # Refresh every 5 seconds
            # Start wave animation on stop button (since capture starts automatically)
            self._start_stop_button_wave()

        # Set up cleanup timer for public IP DNS attempt cache
        self.public_ip_dns_cache_cleanup_timer = QTimer(self)
        self.public_ip_dns_cache_cleanup_timer.timeout.connect(self._cleanup_public_ip_dns_cache)
        # Start timer only if reverse DNS is enabled (runs every 60 seconds = 60000 ms)
        if do_reverse_dns:
            self.public_ip_dns_cache_cleanup_timer.start(60000)

        # Set up periodic database expiration check timer (every 10 minutes = DATABASE_EXPIRE_TIME_CHECK_INTERVAL ms)
        self.database_refresh_timer = QTimer(self)
        self.database_refresh_timer.timeout.connect(self._on_database_refresh_timer)
        self.database_refresh_timer.start(DATABASE_EXPIRE_TIME_CHECK_INTERVAL)


    def _verify_map_ready(self):
        """Verify that window.map is actually ready before marking map as initialized"""
        def on_check(is_ready):
            if is_ready:
                logging.info("Map verified as ready - window.map exists and has required methods")
                self.map_initialized = True
            else:
                logging.warning("Map not ready yet - retrying in 500ms")
                # Retry a few times
                if not hasattr(self, '_map_ready_retries'):
                    self._map_ready_retries = 0

                self._map_ready_retries += 1

                if self._map_ready_retries < 10:  # Max 10 retries = 5 seconds
                    QTimer.singleShot(500, self._verify_map_ready)
                else:
                    logging.error("Map failed to initialize after 10 retries")
                    self._map_ready_retries = 0
                    # Show error on the loading overlay since the map never initialized
                    self._show_map_init_error("Map failed to initialize after multiple retries (no internet connectivity?)")

        check_code = """
        (function() {
            try {
                return (typeof window.map !== 'undefined' && 
                        window.map && 
                        typeof window.map.getCenter === 'function' && 
                        typeof window.map.getZoom === 'function');
            } catch(e) {
                console.error('[Map Ready Check] Error:', e);
                return false;
            }
        })();
        """

        try:
            self.map_view.page().runJavaScript(check_code, on_check)
        except Exception as e:
            logging.error(f"Error verifying map ready: {e}")

    def _show_map_init_error(self, error_msg):
        """Inject an error message into the map loading overlay via JavaScript."""
        escaped = error_msg.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ")
        js = f"""
        (function() {{
            try {{
                var ov = document.getElementById('map-loading-overlay');
                if (ov) {{ ov.style.display = ''; }}
                var errEl = document.getElementById('map-loading-error');
                if (errEl) {{
                    errEl.innerText = 'Failed connecting to the internet and initialize OpenStreetMap with error: ' + '{escaped}';
                }}
                var spinners = document.querySelectorAll('#map-loading-overlay .spinner');
                for (var i = 0; i < spinners.length; i++) {{ spinners[i].style.display = 'none'; }}
            }} catch(e) {{}}
        }})();
        """
        try:
            self.map_view.page().runJavaScript(js)
        except Exception as e:
            logging.error(f"Error showing map init error: {e}")

    def _toggle_fullscreen(self):
        """Toggle between fullscreen and normal state (defensive)."""
        try:
            win_state = self.windowState()
            is_fs = bool(win_state & Qt.WindowFullScreen) or self.isFullScreen()
            if is_fs:
                # leave fullscreen -> restore normal / maximized as appropriate
                self.showNormal()
            else:
                self.showFullScreen()
        except Exception:
            pass

    def _go_fullscreen_on_screen(self, screen):
        """Move window to `screen` and enter fullscreen (defensive)."""
        try:
            # set the QWindow's screen if possible so fullscreen happens on the target monitor
            try:
                wh = self.windowHandle()
                if wh is not None:
                    wh.setScreen(screen)
            except Exception:
                pass

            # move the window top-left to the target screen origin (helps some WM/OS combos)
            try:
                geom = screen.geometry()
                self.move(geom.x(), geom.y())
            except Exception:
                pass

            # finally request fullscreen; fall back to show() if it fails
            try:
                self.showFullScreen()
            except Exception:
                try:
                    self.show()
                except Exception:
                    pass
        except Exception:
            pass

    def _go_maximized_on_screen(self, screen):
        """Move window to `screen` and enter maximized state (defensive)."""
        try:
            try:
                wh = self.windowHandle()
                if wh is not None:
                    wh.setScreen(screen)
            except Exception:
                pass

            try:
                geom = screen.geometry()
                self.move(geom.x(), geom.y())
            except Exception:
                pass

            try:
                self.showMaximized()
            except Exception:
                try:
                    self.show()
                except Exception:
                    pass
        except Exception:
            pass

    def get_map_state(self):
        """Get current map center and zoom from JavaScript (synchronous via QEventLoop with timeout)"""
        if not hasattr(self, 'map_view'):
            logging.debug("get_map_state: map_view not available")
            return None

        if not getattr(self, 'map_initialized', False):
            logging.debug("get_map_state: map not initialized yet")
            return None

        from PySide6.QtCore import QEventLoop

        result = {'center': None, 'zoom': None, 'timed_out': False}
        loop = QEventLoop()

        def on_result(value):
            try:
                logging.debug(f"get_map_state: JavaScript returned raw value: {value!r} (type: {type(value).__name__})")
                # Parse JSON string returned from JavaScript
                if value and isinstance(value, str):
                    try:
                        parsed = json.loads(value)
                        if parsed and isinstance(parsed, dict):
                            result['center'] = parsed.get('center')
                            result['zoom'] = parsed.get('zoom')
                            logging.debug(f"get_map_state: Parsed JSON successfully: {parsed}")
                        else:
                            logging.warning(f"get_map_state: Parsed JSON is not a dict: {parsed}")
                    except json.JSONDecodeError as e:
                        logging.error(f"get_map_state: JSON decode error: {e}")
                elif value and isinstance(value, dict):
                    # Fallback: handle if QWebEngine did serialize it properly
                    result['center'] = value.get('center')
                    result['zoom'] = value.get('zoom')
                    logging.debug(f"get_map_state: Received dict directly (unexpected): {value}")
                else:
                    logging.warning(f"get_map_state: Invalid JavaScript result: {value!r}")
            except Exception as e:
                logging.error(f"get_map_state: Error processing result: {e}")
            finally:
                if loop.isRunning():
                    loop.quit()

        # Timeout handler
        def on_timeout():
            logging.warning("get_map_state: Timeout waiting for JavaScript response (2 seconds)")
            result['timed_out'] = True
            if loop.isRunning():
                loop.quit()

        # Set up timeout timer (2 seconds)
        timeout_timer = QTimer()
        timeout_timer.setSingleShot(True)
        timeout_timer.timeout.connect(on_timeout)
        timeout_timer.start(2000)

        js_code = """
        (function() {
            try {
                console.log('[Map State] Checking for window.map...');
                if (typeof window.map !== 'undefined' && window.map && window.map.getCenter && window.map.getZoom) {
                    var center = window.map.getCenter();
                    var zoom = window.map.getZoom();
                    console.log('[Map State] Successfully got map state:', center, zoom);
                    // Return JSON string instead of object (QWebEnginePage serialization workaround)
                    var result = {
                        center: {lat: center.lat, lng: center.lng},
                        zoom: zoom
                    };
                    return JSON.stringify(result);
                } else {
                    console.warn('[Map State] window.map not available or missing methods');
                    console.log('[Map State] window.map exists:', typeof window.map !== 'undefined');
                    if (typeof window.map !== 'undefined') {
                        console.log('[Map State] has getCenter:', typeof window.map.getCenter === 'function');
                        console.log('[Map State] has getZoom:', typeof window.map.getZoom === 'function');
                    }
                }
            } catch(e) {
                console.error('[Map State] Error getting map state:', e);
            }
            return null;
        })();
        """

        try:
            logging.debug("get_map_state: Executing JavaScript to get map state...")
            self.map_view.page().runJavaScript(js_code, on_result)
            # Wait for either result or timeout
            loop.exec()

            # Stop the timeout timer if still running
            timeout_timer.stop()

            if result['timed_out']:
                logging.warning("get_map_state: Timed out waiting for map state")
                return None

        except Exception as e:
            logging.error(f"get_map_state: Exception while getting map state: {e}")
            timeout_timer.stop()
            return None

        if result['center']:
            logging.info(f"get_map_state: Successfully retrieved map state: center={result['center']}, zoom={result['zoom']}")
            return result
        else:
            logging.warning("get_map_state: No valid center in result")
            return None

    def changeEvent(self, event):
        """Handle window state changes (fullscreen, maximize, minimize, etc.)"""
        try:
            super().changeEvent(event)
        except Exception:
            pass

        try:
            if event.type() == event.WindowStateChange:
                # In no-UI agent mode keep the window permanently hidden —
                # immediately re-hide it if anything tried to show it.
                if agent_no_ui and enable_agent_mode:
                    QTimer.singleShot(0, self.hide)
                    return
                # Schedule a delayed layout update to ensure proper rendering
                # This fixes the map overlapping issue when entering fullscreen via double-click
                QTimer.singleShot(100, self._update_layout_after_state_change)
        except Exception:
            pass

    def _update_layout_after_state_change(self):
        """Force layout recalculation after window state change"""
        try:
            # Save current splitter proportions
            saved_h_sizes = None
            saved_v_sizes = None

            try:
                if hasattr(self, 'splitter') and self.splitter is not None:
                    saved_h_sizes = self.splitter.sizes()
            except Exception:
                pass

            try:
                if hasattr(self, 'right_splitter') and self.right_splitter is not None:
                    saved_v_sizes = self.right_splitter.sizes()
            except Exception:
                pass

            # Force process any pending events
            try:
                QApplication.processEvents()
            except Exception:
                pass

            # Force the central widget to update its geometry first
            if self.centralWidget():
                try:
                    self.centralWidget().updateGeometry()
                    self.centralWidget().update()
                except Exception:
                    pass

            # Force the splitters to recalculate their sizes
            if hasattr(self, 'splitter') and self.splitter is not None:
                try:
                    self.splitter.updateGeometry()
                    self.splitter.update()
                except Exception:
                    pass

            if hasattr(self, 'right_splitter') and self.right_splitter is not None:
                try:
                    self.right_splitter.updateGeometry()
                    self.right_splitter.update()
                except Exception:
                    pass

            # Force the map view to update
            if hasattr(self, 'map_view') and self.map_view is not None:
                try:
                    self.map_view.updateGeometry()
                    self.map_view.update()
                except Exception:
                    pass

            # Force controls widget to update
            if hasattr(self, 'controls_widget') and self.controls_widget is not None:
                try:
                    self.controls_widget.updateGeometry()
                    self.controls_widget.update()
                except Exception:
                    pass

            # Restore splitter proportions if we had valid ones
            # This prevents the splitter from getting corrupted sizes during state changes
            try:
                if saved_h_sizes and hasattr(self, 'splitter') and self.splitter is not None:
                    total = sum(saved_h_sizes)
                    if total > 0:
                        self.splitter.setSizes(saved_h_sizes)
            except Exception:
                pass

            try:
                if saved_v_sizes and hasattr(self, 'right_splitter') and self.right_splitter is not None:
                    total = sum(saved_v_sizes)
                    if total > 0:
                        self.right_splitter.setSizes(saved_v_sizes)
            except Exception:
                pass

            # Final process events to apply all updates
            try:
                QApplication.processEvents()
            except Exception:
                pass
        except Exception:
            pass

    def resizeEvent(self, event):
        """Handle window resize events to ensure splitters adjust properly"""
        try:
            super().resizeEvent(event)
        except Exception:
            pass

        try:
            # Force splitters to refresh after resize
            if hasattr(self, 'right_splitter') and self.right_splitter is not None:
                # Ensure the vertical splitter recalculates its child widget sizes
                QTimer.singleShot(0, lambda: self.right_splitter.refresh() if hasattr(self.right_splitter, 'refresh') else self.right_splitter.update())
        except Exception:
            pass

        # Re-sync filter bar widths after the layout has settled
        QTimer.singleShot(0, self._sync_filter_widths)
        QTimer.singleShot(0, self._sync_summary_filter_widths)

    def save_settings(self):
        """Save current settings to a JSON file"""

        # Apply loaded settings
        global max_connection_list_filo_buffer_size,do_c2_check, do_always_supplement_psutil_with_netstat_when_available, show_only_new_active_connections, show_only_remote_connections, do_reverse_dns, map_refresh_interval, table_column_sort_index, table_column_sort_reverse, summary_table_column_sort_index, summary_table_column_sort_reverse, do_resolve_public_ip, do_pulse_exit_points, do_capture_screenshots, do_pause_table_sorting, do_show_traffic_gauge, do_show_traffic_histogram, do_collect_connections_asynchronously, agent_no_ui, agent_server_host, FLASK_SERVER_PORT, FLASK_AGENT_PORT, MAX_SERVER_AGENTS, db_provider_name, max_connection_list_database_size, logging_level, do_show_listening_connections, conn_table_column_order, summary_table_column_order, conn_table_column_widths, summary_table_column_widths, do_scapy_force_use_interface_name

        settings = {
            'max_connection_list_filo_buffer_size' : max_connection_list_filo_buffer_size,
            'do_c2_check' : do_c2_check,
            'do_always_supplement_psutil_with_netstat_when_available': do_always_supplement_psutil_with_netstat_when_available,
            'show_only_new_active_connections': show_only_new_active_connections,
            'show_only_remote_connections': show_only_remote_connections,
            'do_reverse_dns': do_reverse_dns,
            'do_resolve_public_ip': do_resolve_public_ip,
            'do_pulse_exit_points': do_pulse_exit_points,
            'do_capture_screenshots': do_capture_screenshots,
            'do_pause_table_sorting': do_pause_table_sorting,
            'do_show_traffic_gauge': do_show_traffic_gauge,
            'do_show_traffic_histogram': do_show_traffic_histogram,
            'do_collect_connections_asynchronously': do_collect_connections_asynchronously,
            'do_show_listening_connections': do_show_listening_connections,
            'do_scapy_force_use_interface_name': do_scapy_force_use_interface_name,
            'conn_table_column_order': self._get_conn_table_column_order(),
            'summary_table_column_order': self._get_summary_table_column_order(),
            'conn_table_column_widths': self._get_column_widths(self.connection_table),
            'summary_table_column_widths': self._get_column_widths(self.summary_table),
            'map_refresh_interval': map_refresh_interval,
            'table_column_sort_index': table_column_sort_index,
            'table_column_sort_reverse' : table_column_sort_reverse,
            'summary_table_column_sort_index': summary_table_column_sort_index,
            'summary_table_column_sort_reverse': summary_table_column_sort_reverse,
            'enable_server_mode': enable_server_mode,
            'enable_agent_mode': enable_agent_mode,
            'agent_server_host': agent_server_host,
            'flask_server_port': FLASK_SERVER_PORT,
            'flask_agent_port': FLASK_AGENT_PORT,
            'max_server_agents': MAX_SERVER_AGENTS,
            'agent_no_ui': agent_no_ui,
            'agent_colors': dict(self._agent_colors),
            'agent_hidden': {h: v for h, v in self._agent_hidden.items() if v},
            'active_collector_plugin': self._active_collector.name,
            'pcap_file_path': getattr(self, '_pcap_file_path', ''),
            'db_provider_name': db_provider_name,
            'max_connection_list_database_size': max_connection_list_database_size,
            'loggingLevel': logging_level,
        }

        # Save current map position and zoom
        try:
            map_state = self.get_map_state()
            if map_state and map_state['center']:
                settings['map_center_lat'] = map_state['center']['lat']
                settings['map_center_lng'] = map_state['center']['lng']
                settings['map_zoom'] = map_state['zoom']
                logging.info(f"Saved map state: center=({settings['map_center_lat']}, {settings['map_center_lng']}), zoom={settings['map_zoom']}")
            else:
                logging.debug("No map state to save (map not initialized or no valid state)")
        except Exception as e:
            logging.warning(f"Failed to save map state: {e}")

        # Save splitter states (Base64) if available
        try:
            settings['splitter_state'] = None
            settings['right_splitter_state'] = None
            if hasattr(self, 'splitter') and self.splitter is not None:
                settings['splitter_state'] = self.splitter.saveState().toBase64().data().decode('ascii')
            if hasattr(self, 'right_splitter') and self.right_splitter is not None:
                settings['right_splitter_state'] = self.right_splitter.saveState().toBase64().data().decode('ascii')
        except Exception:
            # don't fail saving other settings for splitter issues
            pass

        try:
            # record fullscreen / maximized info so we can restore on the same monitor
            # prefer explicit window state bitmask check over isFullScreen() alone
            win_state = self.windowState()
            is_fs = bool(win_state & Qt.WindowFullScreen) or self.isFullScreen()
            is_max = bool(win_state & Qt.WindowMaximized) or self.isMaximized()

            settings['is_fullscreen'] = is_fs
            settings['is_maximized'] = is_max
            settings['fullscreen_screen_name'] = None
            try:
                wh = self.windowHandle()
                if wh is not None and wh.screen() is not None:
                    settings['fullscreen_screen_name'] = wh.screen().name()
            except Exception:
                # ignore if windowHandle not available
                pass
        except Exception:
            pass

        try:
            with open(SETTINGS_FILE_NAME, 'w') as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            QMessageBox.critical(self, "Error saving settings", f"Error: {e}")
            

    def _load_settings_early(self):
        """Load settings from JSON file (early phase - before UI is created)

        Returns:
            True if settings file was found and loaded successfully
            None if settings file doesn't exist (first run)
        """
        if not os.path.exists(SETTINGS_FILE_NAME):
            logging.info("No settings file found - this appears to be first run")
            return None

        try:
            with open(SETTINGS_FILE_NAME, 'r') as f:
                settings = json.load(f)

                # Apply loaded settings to global variables
                global max_connection_list_filo_buffer_size, do_c2_check, show_only_new_active_connections
                global show_only_remote_connections, do_reverse_dns, map_refresh_interval
                global table_column_sort_index, table_column_sort_reverse
                global summary_table_column_sort_index, summary_table_column_sort_reverse, do_resolve_public_ip, do_pulse_exit_points, do_capture_screenshots, do_pause_table_sorting, do_show_traffic_gauge, do_show_traffic_histogram, do_collect_connections_asynchronously
                global db_provider_name, max_connection_list_database_size
                global logging_level
                global do_always_supplement_psutil_with_netstat_when_available
                global do_show_listening_connections
                global do_scapy_force_use_interface_name
                global conn_table_column_order, summary_table_column_order
                global conn_table_column_widths, summary_table_column_widths

                max_connection_list_filo_buffer_size = settings.get('max_connection_list_filo_buffer_size', max_connection_list_filo_buffer_size)

                do_c2_check = settings.get('do_c2_check', do_c2_check)
                do_always_supplement_psutil_with_netstat_when_available = settings.get('do_always_supplement_psutil_with_netstat_when_available', do_always_supplement_psutil_with_netstat_when_available)
                _set_supplement_psutil(do_always_supplement_psutil_with_netstat_when_available)
                show_only_new_active_connections = settings.get('show_only_new_active_connections', show_only_new_active_connections)
                show_only_remote_connections = settings.get('show_only_remote_connections', show_only_remote_connections)
                do_reverse_dns = settings.get('do_reverse_dns', do_reverse_dns)
                do_resolve_public_ip = settings.get('do_resolve_public_ip', do_resolve_public_ip)
                do_pulse_exit_points = settings.get('do_pulse_exit_points', do_pulse_exit_points)
                do_capture_screenshots = settings.get('do_capture_screenshots', do_capture_screenshots)
                do_pause_table_sorting = settings.get('do_pause_table_sorting', do_pause_table_sorting)
                do_show_traffic_gauge = settings.get('do_show_traffic_gauge', do_show_traffic_gauge)
                do_show_traffic_histogram = settings.get('do_show_traffic_histogram', do_show_traffic_histogram)
                do_collect_connections_asynchronously = settings.get('do_collect_connections_asynchronously', do_collect_connections_asynchronously)
                do_show_listening_connections = settings.get('do_show_listening_connections', do_show_listening_connections)
                try:
                    from plugins.os_conn_table import set_include_listening as _set_listening
                    _set_listening(do_show_listening_connections)
                except Exception:
                    pass
                do_scapy_force_use_interface_name = settings.get('do_scapy_force_use_interface_name', do_scapy_force_use_interface_name)
                _saved_conn_order = settings.get('conn_table_column_order', [])
                if isinstance(_saved_conn_order, list):
                    conn_table_column_order = [int(x) for x in _saved_conn_order]
                _saved_summary_order = settings.get('summary_table_column_order', [])
                if isinstance(_saved_summary_order, list):
                    summary_table_column_order = [int(x) for x in _saved_summary_order]
                _saved_conn_widths = settings.get('conn_table_column_widths', [])
                if isinstance(_saved_conn_widths, list) and _saved_conn_widths:
                    conn_table_column_widths = [int(x) for x in _saved_conn_widths]
                _saved_summary_widths = settings.get('summary_table_column_widths', [])
                if isinstance(_saved_summary_widths, list) and _saved_summary_widths:
                    summary_table_column_widths = [int(x) for x in _saved_summary_widths]
                map_refresh_interval = settings.get('map_refresh_interval', map_refresh_interval)
                table_column_sort_index = settings.get('table_column_sort_index', table_column_sort_index)
                table_column_sort_reverse = settings.get('table_column_sort_reverse', table_column_sort_reverse)
                summary_table_column_sort_index = settings.get('summary_table_column_sort_index', summary_table_column_sort_index)
                summary_table_column_sort_reverse = settings.get('summary_table_column_sort_reverse', summary_table_column_sort_reverse)

                # Restore database persistence layer settings
                db_provider_name = settings.get('db_provider_name', db_provider_name)
                try:
                    _saved_db_size = int(settings.get('max_connection_list_database_size', max_connection_list_database_size))
                    if _saved_db_size > 0:
                        max_connection_list_database_size = _saved_db_size
                except (ValueError, TypeError):
                    pass

                # Apply logging level from settings
                _level_str = str(settings.get('loggingLevel', 'WARNING')).upper()
                if _level_str in _LOGGING_LEVEL_MAP:
                    logging_level = _level_str
                    logging.getLogger().setLevel(_LOGGING_LEVEL_MAP[_level_str])
                    logging.info(f"Logging level set to: {logging_level}")

                # Restore server/agent mode settings (CLI args take precedence)
                global enable_server_mode, enable_agent_mode, agent_server_host, agent_no_ui, FLASK_SERVER_PORT, FLASK_AGENT_PORT, MAX_SERVER_AGENTS
                # Only restore no_ui from settings if neither --no_ui nor --no_ui_off was passed on CLI
                if not agent_no_ui and not _no_ui_off_requested:
                    agent_no_ui = bool(settings.get('agent_no_ui', False))

                # Restore max server agents (must be a positive integer)
                try:
                    _saved_max = int(settings.get('max_server_agents', MAX_SERVER_AGENTS))
                    if _saved_max > 0:
                        MAX_SERVER_AGENTS = _saved_max
                except (TypeError, ValueError):
                    pass

                def _valid_port(val, default):
                    try:
                        p = int(val)
                        return p if 1 <= p <= 65535 else default
                    except (TypeError, ValueError):
                        return default

                # Restore server port (always, regardless of current mode)
                FLASK_SERVER_PORT = _valid_port(
                    settings.get('flask_server_port',
                                 settings.get('flask_listen_port', FLASK_SERVER_PORT)),
                    FLASK_SERVER_PORT)
                # Restore agent port (always)
                FLASK_AGENT_PORT = _valid_port(
                    settings.get('flask_agent_port',
                                 settings.get('flask_listen_port', FLASK_AGENT_PORT)),
                    FLASK_AGENT_PORT)

                if not enable_server_mode and not enable_agent_mode:
                    # Only apply persisted mode settings when CLI didn't override
                    saved_server = settings.get('enable_server_mode', False)
                    saved_agent = settings.get('enable_agent_mode', False)
                    # Support legacy key 'agent_server_address' for old settings files
                    saved_host = settings.get('agent_server_host', '')
                    if not saved_host:
                        legacy = settings.get('agent_server_address', '')
                        if legacy.startswith('http://') or legacy.startswith('https://'):
                            import urllib.parse as _up
                            _p = _up.urlparse(legacy)
                            saved_host = _p.hostname or ''
                        else:
                            saved_host = legacy
                    if saved_server and not saved_agent:
                        enable_server_mode = True
                    elif saved_agent and not saved_server:
                        enable_agent_mode = True
                        agent_server_host = saved_host

                    # Restore per-agent color assignments
                    saved_colors = settings.get('agent_colors', {})
                    for h, c in saved_colors.items():
                        if isinstance(h, str) and isinstance(c, str) and c in self._AGENT_COLOR_PALETTE:
                            self._agent_colors[h] = c
                    # Ensure the local server always has a color (default: green)
                    if LOCAL_HOSTNAME not in self._agent_colors:
                        self._agent_colors[LOCAL_HOSTNAME] = 'green'
                    # Advance color index past already-claimed colors so new remote agents
                    # don't collide with persisted assignments.
                    # Start at 1 to skip green (index 0), which is reserved for the server.
                    self._agent_color_index = 1
                    remote_used = [c for h, c in self._agent_colors.items() if h != LOCAL_HOSTNAME]
                    for _color in self._AGENT_COLOR_PALETTE[1:]:
                        if _color not in remote_used:
                            break
                        self._agent_color_index += 1

                    # Restore per-agent hidden state
                    saved_hidden = settings.get('agent_hidden', {})
                    for h, v in saved_hidden.items():
                        if isinstance(h, str) and v:
                            self._agent_hidden[h] = True

                    # Restore active connection collector plugin
                    saved_collector = settings.get('active_collector_plugin', '')
                    if saved_collector:
                        for i, plugin in enumerate(self._collector_plugins):
                            if plugin.name == saved_collector:
                                self._active_collector = plugin
                                break

                    # Restore pcap file path
                    self._pcap_file_path = settings.get('pcap_file_path', '')

                    # Restore map position and zoom (CRITICAL: do this BEFORE init_ui/update_map)
                try:
                    lat = settings.get('map_center_lat')
                    lng = settings.get('map_center_lng')
                    zoom = settings.get('map_zoom')

                    if lat is not None and lng is not None and zoom is not None:
                        try:
                            lat_float = float(lat)
                            lng_float = float(lng)
                            zoom_float = float(zoom)

                            if -90 <= lat_float <= 90 and -180 <= lng_float <= 180 and 0 <= zoom_float <= 20:
                                self.saved_map_center_lat = lat_float
                                self.saved_map_center_lng = lng_float
                                self.saved_map_zoom = zoom_float
                                logging.info(f"Loaded map state (early): center=({self.saved_map_center_lat}, {self.saved_map_center_lng}), zoom={self.saved_map_zoom}")
                            else:
                                logging.warning(f"Invalid map state ranges: lat={lat_float}, lng={lng_float}, zoom={zoom_float}")
                        except (ValueError, TypeError) as e:
                            logging.warning(f"Invalid map state values: {e}")
                    else:
                        logging.debug("No saved map state found in settings")
                except Exception as e:
                    logging.warning(f"Error loading map state: {e}")

                # Store fullscreen/maximize info for later application
                try:
                    is_fs = settings.get('is_fullscreen', False)
                    is_max = settings.get('is_maximized', False)
                    screen_name = settings.get('fullscreen_screen_name')

                    restored = False

                    if is_fs:
                        if screen_name:
                            target = None
                            for s in QApplication.screens():
                                try:
                                    if s.name() == screen_name:
                                        target = s
                                        break
                                except Exception:
                                    continue
                            if target:
                                self._pending_restore = {'type': 'fullscreen', 'screen_name': target.name()}
                                restored = True
                        else:
                            self._pending_restore = {'type': 'fullscreen', 'screen_name': None}
                            restored = True

                    if not restored and is_max:
                        if screen_name:
                            target = None
                            for s in QApplication.screens():
                                try:
                                    if s.name() == screen_name:
                                        target = s
                                        break
                                except Exception:
                                    continue
                            if target:
                                self._pending_restore = {'type': 'maximized', 'screen_name': target.name()}
                            else:
                                self._pending_restore = {'type': 'maximized', 'screen_name': None}
                        else:
                            self._pending_restore = {'type': 'maximized', 'screen_name': None}
                except Exception:
                    pass

                # Store splitter states for later restoration (after UI is created)
                self._saved_splitter_state = settings.get('splitter_state')
                self._saved_right_splitter_state = settings.get('right_splitter_state')

                # Settings loaded successfully
                logging.info("Settings loaded successfully from file")
                return True

        except Exception as e:
            logging.error(f"Error loading settings (early phase): {e}")
            return None

    def _apply_settings_to_ui(self):
        """Apply settings to UI elements (late phase - after UI is created)"""
        if not os.path.exists(SETTINGS_FILE_NAME):
            return

        try:
            with open(SETTINGS_FILE_NAME, 'r') as f:
                settings = json.load(f)

                # Update UI elements with loaded settings
                map_refresh_interval_val = settings.get('map_refresh_interval', map_refresh_interval)
                self.refresh_interval_combo_box.blockSignals(True)
                self.refresh_interval_combo_box.setCurrentText(f"{map_refresh_interval_val}")
                self.refresh_interval_combo_box.blockSignals(False)

                self.only_show_new_connections.setChecked(show_only_new_active_connections)
                self.only_show_remote_connections.setChecked(show_only_remote_connections)
                self.reverse_dns_check.setChecked(do_reverse_dns)
                self.c2_check.setChecked(do_c2_check)
                self.resolve_public_ip.setChecked(do_resolve_public_ip)
                self.pulse_exit_points_check.setChecked(do_pulse_exit_points)
                self.capture_screenshots_check.setChecked(do_capture_screenshots)
                self.pause_table_sorting_check.setChecked(do_pause_table_sorting)
                self.show_traffic_gauge_check.setChecked(do_show_traffic_gauge)
                self.show_traffic_histogram_check.setChecked(do_show_traffic_histogram)
                self.collect_connections_async_check.setChecked(do_collect_connections_asynchronously)
                self.show_listening_connections_check.setChecked(do_show_listening_connections)

                # Restore column order for both tables
                self._apply_conn_table_column_order(conn_table_column_order)
                self._apply_summary_table_column_order(summary_table_column_order)

                # Restore persisted column widths for both tables
                self._apply_column_widths(self.connection_table, conn_table_column_widths)
                self._apply_column_widths(self.summary_table, summary_table_column_widths)

                # Update buffer size input field
                if hasattr(self, 'buffer_size_input'):
                    self.buffer_size_input.setText(str(max_connection_list_filo_buffer_size))

                # Sync database persistence UI
                if hasattr(self, 'db_provider_combo'):
                    self.db_provider_combo.blockSignals(True)
                    self._set_db_combo_by_name(db_provider_name)
                    self.db_provider_combo.blockSignals(False)
                if hasattr(self, 'db_buffer_size_input'):
                    self.db_buffer_size_input.setText(str(max_connection_list_database_size))

                # Activate the database provider if one was persisted
                if db_provider_name and db_provider_name != "Disabled":
                    self._activate_db_provider(db_provider_name)

                # Restore splitter states if saved
                try:
                    if hasattr(self, '_saved_splitter_state') and self._saved_splitter_state:
                        ba = QByteArray.fromBase64(self._saved_splitter_state.encode('ascii'))
                        self.splitter.restoreState(ba)
                except Exception:
                    pass

                try:
                    if hasattr(self, '_saved_right_splitter_state') and self._saved_right_splitter_state:
                        ba = QByteArray.fromBase64(self._saved_right_splitter_state.encode('ascii'))
                        self.right_splitter.restoreState(ba)
                except Exception:
                    pass

                # Restore server/agent mode UI state
                if hasattr(self, 'server_mode_check'):
                    self.server_mode_check.setChecked(enable_server_mode)
                if hasattr(self, 'agent_mode_check'):
                    self.agent_mode_check.setChecked(enable_agent_mode)
                if hasattr(self, 'agent_server_input'):
                    self.agent_server_input.setText(agent_server_host)
                if hasattr(self, 'flask_server_port_input'):
                    self.flask_server_port_input.setText(str(FLASK_SERVER_PORT))
                if hasattr(self, 'flask_agent_port_input'):
                    self.flask_agent_port_input.setText(str(FLASK_AGENT_PORT))
                if hasattr(self, 'no_ui_check'):
                    self.no_ui_check.setChecked(agent_no_ui)
                    self.no_ui_check.setEnabled(enable_agent_mode)

                # Populate Agent Management table if server mode is active and agents were saved
                if enable_server_mode and self._agent_colors:
                    self._refresh_agent_management_table(force_rebuild=True)

                # Restore active collector plugin in combo box
                if hasattr(self, '_collector_combo'):
                    for i in range(self._collector_combo.count()):
                        if self._collector_combo.itemData(i, Qt.UserRole) == self._active_collector.name:
                            self._collector_combo.setCurrentIndex(i)
                            break

                # Restore pcap file path input
                if hasattr(self, '_pcap_path_input'):
                    self._pcap_path_input.setText(getattr(self, '_pcap_file_path', ''))
                if hasattr(self, '_pcap_path_row'):
                    self._pcap_path_row.setVisible(self._active_collector.name == "PCAP File Collector")

                # Restore Scapy forced interface selection
                if hasattr(self, '_scapy_iface_combo'):
                    self._scapy_iface_combo.blockSignals(True)
                    self._set_scapy_iface_combo(do_scapy_force_use_interface_name)
                    self._scapy_iface_combo.blockSignals(False)
                if hasattr(self, '_scapy_iface_row'):
                    self._scapy_iface_row.setVisible(self._active_collector.name == "Scapy Live Capture")

                # Deferred filter-bar sync — splitter restoration above may have
                # changed the table width, invalidating earlier column widths.
                QTimer.singleShot(0, self._sync_filter_widths)
                QTimer.singleShot(0, self._sync_summary_filter_widths)

        except Exception as e:
            logging.error(f"Error applying settings to UI: {e}")

    # ── Server / Agent mode helpers ──────────────────────────────────────

    @Slot(int)
    def _on_server_mode_changed(self, state):
        global enable_server_mode, enable_agent_mode
        enabled = bool(state)
        if enabled:
            enable_server_mode = True
            enable_agent_mode = False
            if hasattr(self, 'agent_mode_check'):
                self.agent_mode_check.blockSignals(True)
                self.agent_mode_check.setChecked(False)
                self.agent_mode_check.blockSignals(False)
            self._start_flask_server()
        else:
            enable_server_mode = False
            # Flask cannot be gracefully stopped mid-process; it will die with the app.
        # Show or hide the Agent Management tab to match current mode
        if hasattr(self, 'tab_widget') and hasattr(self, '_agent_mgmt_tab_index'):
            self.tab_widget.setTabVisible(self._agent_mgmt_tab_index, enable_server_mode)
            if enable_server_mode:
                self._refresh_agent_management_table(force_rebuild=True)
        logging.info(f"Server mode {'enabled' if enable_server_mode else 'disabled'}")

    def _refresh_agent_management_table(self, force_rebuild=False):
        """Update the Agent Management table from the current agent registry.

        On periodic refresh cycles only the volatile columns (Hide, Is Active) are
        updated in-place so that open combo-box dropdowns are never destroyed.
        A full rebuild only happens when the set of known hosts changes or when
        force_rebuild=True (e.g. after a Clear action).
        """
        if not hasattr(self, 'agent_mgmt_table'):
            return
        try:
            # Collect all known hostnames: from color map, live cache, and local host
            known_hosts = set(self._agent_colors.keys())
            with self._agent_cache_lock:
                known_hosts.update(self._agent_cache.keys())
            # Always include the local server so it can be hidden/unhidden
            known_hosts.add(LOCAL_HOSTNAME)
            known_hosts = sorted(known_hosts)

            # Threshold for marking an agent inactive (read-only — strikes are
            # advanced in _collect_and_reset_agent_cache once per timer cycle).
            AGENT_INACTIVE_PASSES = 4

            # --- Decide whether a full rebuild is needed ---
            current_rows = getattr(self, '_agent_mgmt_rows', None)
            need_rebuild = force_rebuild or (current_rows != known_hosts)

            if need_rebuild:
                self._agent_mgmt_rows = known_hosts
                self.agent_mgmt_table.setRowCount(0)

                # Shared helper — defined once, referenced in closures below
                def _apply_combo_style(combo, chosen):
                    fg = 'white' if chosen in ('black', 'violet') else 'black'
                    combo.setStyleSheet(
                        f"QComboBox {{ background-color: {chosen}; color: {fg}; }}"
                        f"QComboBox QAbstractItemView {{ background-color: white; color: black; }}"
                    )

                for hostname in known_hosts:
                    row = self.agent_mgmt_table.rowCount()
                    self.agent_mgmt_table.insertRow(row)

                    # Column 0 — hostname
                    is_server = (hostname == LOCAL_HOSTNAME)
                    display_hostname = f"{hostname} (SERVER)" if is_server else hostname
                    host_item = QTableWidgetItem(display_hostname)
                    host_item.setFlags(Qt.ItemIsEnabled)
                    self.agent_mgmt_table.setItem(row, 0, host_item)

                    # Column 1 — color combo box with swatch + label per item
                    color_combo = QComboBox()
                    color_combo.setIconSize(QSize(16, 16))

                    for color in self._AGENT_COLOR_PALETTE:
                        pix = QPixmap(16, 16)
                        pix.fill(QColor(color))
                        color_combo.addItem(QIcon(pix), color)

                    # Default the server to green if not yet assigned
                    current_color = self._agent_colors.get(hostname)
                    if current_color is None and is_server:
                        current_color = 'green'
                        self._agent_colors[hostname] = 'green'
                    if current_color and current_color in self._AGENT_COLOR_PALETTE:
                        color_combo.blockSignals(True)
                        color_combo.setCurrentText(current_color)
                        color_combo.blockSignals(False)
                        _apply_combo_style(color_combo, current_color)

                    def make_color_changed(hn, combo):
                        def _on_color_changed(_index):
                            chosen = combo.currentText()
                            self._agent_colors[hn] = chosen
                            _apply_combo_style(combo, chosen)
                            self.save_settings()
                            # Re-stamp agent_color and icon on every live connection
                            # belonging to this agent so the map reflects the new color
                            # immediately without waiting for the next full refresh cycle.
                            if hasattr(self, 'connections') and self.connections:
                                for _conn in self.connections:
                                    if _conn.get('origin_hostname') == hn or _conn.get('hostname') == hn:
                                        _conn['agent_color'] = chosen
                                        if _conn.get('icon') not in ('redIcon', 'yellowIcon'):
                                            _conn['icon'] = chosen + 'Icon'
                            self._update_map_with_filter()
                        return _on_color_changed

                    color_combo.currentIndexChanged.connect(make_color_changed(hostname, color_combo))
                    self.agent_mgmt_table.setCellWidget(row, 1, color_combo)

                    # Column 2 — Hide toggle button
                    is_hidden = self._agent_hidden.get(hostname, False)
                    hide_btn = QPushButton("✖" if is_hidden else "✔")
                    hide_btn.setToolTip("Click to unhide agent on the map" if is_hidden else "Click to hide agent on the map")
                    hide_btn.setStyleSheet(
                        "color: red; font-weight: bold;" if is_hidden else "color: green; font-weight: bold;"
                    )

                    def make_hide_handler(hn):
                        def _on_hide_toggle():
                            currently_hidden = self._agent_hidden.get(hn, False)
                            self._agent_hidden[hn] = not currently_hidden
                            self.save_settings()
                            self._refresh_agent_management_table(force_rebuild=True)
                            self._update_map_with_filter()
                        return _on_hide_toggle

                    hide_btn.clicked.connect(make_hide_handler(hostname))
                    self.agent_mgmt_table.setCellWidget(row, 2, hide_btn)

                    # Column 3 — Is Active indicator
                    is_active = self._agent_inactive_strikes.get(hostname, 0) < AGENT_INACTIVE_PASSES
                    active_text, active_color = ("✔", "green") if is_active else ("✖", "red")
                    active_item = QTableWidgetItem(active_text)
                    active_item.setTextAlignment(Qt.AlignCenter)
                    active_item.setForeground(QColor(active_color))
                    active_item.setFlags(Qt.ItemIsEnabled)
                    self.agent_mgmt_table.setItem(row, 3, active_item)

                    # Column 4 — Clear button
                    clear_btn = QPushButton("Clear")
                    clear_btn.setToolTip(f"Remove all saved settings for {hostname}")

                    def make_clear_handler(hn):
                        def _on_clear():
                            self._agent_colors.pop(hn, None)
                            self._agent_hidden.pop(hn, None)
                            self._agent_inactive_strikes.pop(hn, None)
                            with self._agent_cache_lock:
                                self._agent_posted_since_last_cycle.discard(hn)
                                self._agent_cache.pop(hn, None)
                            self.save_settings()
                            self._refresh_agent_management_table(force_rebuild=True)
                            self._update_map_with_filter()
                        return _on_clear

                    clear_btn.clicked.connect(make_clear_handler(hostname))
                    self.agent_mgmt_table.setCellWidget(row, 4, clear_btn)

            else:
                # --- In-place update: only touch volatile columns (2 and 3) ---
                for row, hostname in enumerate(known_hosts):
                    # Column 2 — Hide toggle button: update text/style only
                    hide_btn = self.agent_mgmt_table.cellWidget(row, 2)
                    if hide_btn is not None:
                        is_hidden = self._agent_hidden.get(hostname, False)
                        new_text = "✖" if is_hidden else "✔"
                        new_tip  = "Click to unhide agent on the map" if is_hidden else "Click to hide agent on the map"
                        new_style = "color: red; font-weight: bold;" if is_hidden else "color: green; font-weight: bold;"
                        if hide_btn.text() != new_text:
                            hide_btn.setText(new_text)
                        if hide_btn.toolTip() != new_tip:
                            hide_btn.setToolTip(new_tip)
                        if hide_btn.styleSheet() != new_style:
                            hide_btn.setStyleSheet(new_style)

                    # Column 3 — Is Active indicator
                    is_active = self._agent_inactive_strikes.get(hostname, 0) < AGENT_INACTIVE_PASSES
                    active_text, active_color = ("✔", "green") if is_active else ("✖", "red")
                    active_item = self.agent_mgmt_table.item(row, 3)
                    if active_item is not None:
                        if active_item.text() != active_text:
                            active_item.setText(active_text)
                            active_item.setForeground(QColor(active_color))

        except Exception as e:
            logging.error(f"Error refreshing agent management table: {e}")

    @Slot(int)
    def _on_agent_mode_changed(self, state):
        global enable_agent_mode, enable_server_mode, agent_server_host
        enabled = bool(state)
        if enabled:
            enable_agent_mode = True
            enable_server_mode = False
            agent_server_host = self.agent_server_input.text().strip()
            if hasattr(self, 'server_mode_check'):
                self.server_mode_check.blockSignals(True)
                self.server_mode_check.setChecked(False)
                self.server_mode_check.blockSignals(False)
        else:
            enable_agent_mode = False
        # no_ui only makes sense when agent mode is on
        if hasattr(self, 'no_ui_check'):
            self.no_ui_check.setEnabled(enable_agent_mode)
        logging.info(f"Agent mode {'enabled' if enable_agent_mode else 'disabled'} -> {agent_server_host}:{FLASK_AGENT_PORT}")

    @Slot(int)
    def _on_collector_changed(self, index):
        """Switch the active connection collector plugin."""
        if 0 <= index < len(self._collector_plugins):
            # Stop the previous collector if it has a stop() method (e.g. live sniffer)
            prev = self._active_collector
            if hasattr(prev, 'stop') and callable(prev.stop):
                try:
                    prev.stop()
                except Exception:
                    pass
            self._active_collector = self._collector_plugins[index]
            logging.info(f"Connection collector changed to: {self._active_collector.name}")
            # Show the PCAP path row only when the PCAP file collector is active
            if hasattr(self, '_pcap_path_row'):
                self._pcap_path_row.setVisible(self._active_collector.name == "PCAP File Collector")
            # Show the Scapy forced interface row only when the Scapy collector is active
            if hasattr(self, '_scapy_iface_row'):
                self._scapy_iface_row.setVisible(self._active_collector.name == "Scapy Live Capture")
            self.save_settings()

    @Slot()
    def _on_pcap_path_changed(self):
        """Save the pcap file path to settings when the user edits it."""
        if hasattr(self, '_pcap_path_input'):
            self._pcap_file_path = self._pcap_path_input.text().strip()
            self.save_settings()

    @Slot()
    def _on_pcap_browse(self):
        """Open a file dialog to choose a pcap file."""
        start_dir = ''
        if hasattr(self, '_pcap_path_input'):
            start_dir = os.path.dirname(self._pcap_path_input.text().strip())
        path, _ = QFileDialog.getOpenFileName(
            self, "Select PCAP file", start_dir,
            "PCAP files (*.pcap *.pcapng);;All files (*)"
        )
        if path and hasattr(self, '_pcap_path_input'):
            self._pcap_path_input.setText(path)
            self._pcap_file_path = path

    @Slot()
    def _populate_scapy_iface_combo(self):
        """Populate the Scapy interface combo with 'Auto-detect' + available interfaces.

        Each entry shows a human-friendly label built from the Scapy
        ``NetworkInterface`` object (name, description, IP) while the
        item's *user-data* stores the ``network_name`` string that is
        passed to ``sniff(iface=…)``.
        """
        if not hasattr(self, '_scapy_iface_combo'):
            return
        combo = self._scapy_iface_combo
        combo.blockSignals(True)
        prev_value = combo.currentData() or ''
        combo.clear()
        # First item: auto-detect (empty string as user data)
        combo.addItem('Auto-detect (all interfaces)', '')
        # Enumerate interfaces via Scapy's IFACES registry (rich objects)
        try:
            from scapy.all import IFACES
            for iface in IFACES.values():
                net_name = getattr(iface, 'network_name', '') or ''
                if not net_name:
                    continue
                friendly = getattr(iface, 'name', '') or net_name
                desc = getattr(iface, 'description', '') or ''
                ip = getattr(iface, 'ip', '') or ''
                parts = [friendly]
                if desc and desc != friendly:
                    parts.append(desc)
                if ip:
                    parts.append(ip)
                display = ' — '.join(parts)
                combo.addItem(display, net_name)
        except Exception:
            # Fallback: use get_if_list() raw names when IFACES is unavailable
            try:
                from scapy.all import get_if_list
                for raw_name in get_if_list():
                    if raw_name:
                        combo.addItem(raw_name, raw_name)
            except Exception as e:
                logging.warning(f"Could not enumerate Scapy interfaces: {e}")
        # Restore previous selection (or the global setting)
        target = prev_value or do_scapy_force_use_interface_name
        self._set_scapy_iface_combo(target)
        combo.blockSignals(False)

    def _set_scapy_iface_combo(self, iface_name):
        """Select the combo item whose user-data matches *iface_name*."""
        combo = self._scapy_iface_combo
        for i in range(combo.count()):
            if combo.itemData(i) == iface_name:
                combo.setCurrentIndex(i)
                return
        # If the saved name is not in the list, fall back to auto-detect
        combo.setCurrentIndex(0)

    @Slot(int)
    def _on_scapy_iface_changed(self, _index=0):
        """Save the selected Scapy interface when the user picks one."""
        global do_scapy_force_use_interface_name
        if hasattr(self, '_scapy_iface_combo'):
            do_scapy_force_use_interface_name = self._scapy_iface_combo.currentData() or ''
            self.save_settings()

    @Slot(int)
    def _on_no_ui_changed(self, state):
        global agent_no_ui
        agent_no_ui = bool(state)
        self.save_settings()
        logging.info(f"No-UI mode {'enabled' if agent_no_ui else 'disabled'} (takes effect on next launch)")

    @Slot()
    def _on_agent_server_address_changed(self):
        global agent_server_host
        host = self.agent_server_input.text().strip()
        agent_server_host = host
        self.save_settings()
        if host:
            self._trigger_agent_connectivity_check()

    @Slot()
    def _on_flask_server_port_changed(self):
        global FLASK_SERVER_PORT
        previous_port = FLASK_SERVER_PORT
        raw = self.flask_server_port_input.text().strip()
        try:
            port = int(raw)
            if 1024 <= port <= 65535:
                FLASK_SERVER_PORT = port
                self.flask_server_port_input.setStyleSheet("")
            else:
                raise ValueError
        except (ValueError, AttributeError):
            FLASK_SERVER_PORT = previous_port
            self.flask_server_port_input.setText(str(previous_port))
            self.flask_server_port_input.setStyleSheet("border: 1px solid red;")
            return

        if not enable_server_mode:
            # Server not running — just persist the new value
            self.save_settings()
            logging.info(f"Flask server port set to {FLASK_SERVER_PORT} (server not running)")
            return

        # Server is running — restart it on the new port
        self._restart_flask_server(previous_port)

    @Slot()
    def _on_flask_agent_port_changed(self):
        global FLASK_AGENT_PORT
        raw = self.flask_agent_port_input.text().strip()
        try:
            port = int(raw)
            if 1024 <= port <= 65535:
                FLASK_AGENT_PORT = port
                self.flask_agent_port_input.setStyleSheet("")
            else:
                raise ValueError
        except (ValueError, AttributeError):
            FLASK_AGENT_PORT = 5000
            self.flask_agent_port_input.setText("5000")
            self.flask_agent_port_input.setStyleSheet("border: 1px solid red;")
        self.save_settings()
        logging.info(f"Flask agent port set to {FLASK_AGENT_PORT}")
        if agent_server_host:
            self._trigger_agent_connectivity_check()

    # ── Agent connectivity check ─────────────────────────────────────────────

    def _trigger_agent_connectivity_check(self):
        """Fire an async HTTP reachability check against the configured server.
        Updates self.agent_conn_status_label with the result on the main thread."""
        if not hasattr(self, 'agent_conn_status_label'):
            return
        host = agent_server_host.strip()
        port = FLASK_AGENT_PORT
        if not host:
            self.agent_conn_status_label.setText("")
            return
        self.agent_conn_status_label.setText("⏳ Checking…")
        self.agent_conn_status_label.setStyleSheet("color: grey;")

        viewer = self

        class _ConnCheckSignals(QObject):
            success = Signal()
            failure = Signal(str)

        class _ConnCheckWorker(QRunnable):
            def __init__(self, parent_obj):
                super().__init__()
                # Parent the signals object to the viewer so its lifetime is
                # tied to the viewer and it is deleted on the main thread.
                self.signals = _ConnCheckSignals(parent_obj)
                self.setAutoDelete(False)  # caller controls lifetime

            def run(self):
                try:
                    resp = requests.get(
                        f"http://{host}:{port}/",
                        timeout=4,
                        allow_redirects=False
                    )
                    # Any HTTP response means the server is reachable
                    self.signals.success.emit()
                except requests.exceptions.ConnectionError:
                    self.signals.failure.emit(
                        f"Connection refused — is the server running on {host}:{port}?"
                    )
                except requests.exceptions.Timeout:
                    self.signals.failure.emit(
                        f"Connection timed out reaching {host}:{port}."
                    )
                except Exception as exc:
                    self.signals.failure.emit(str(exc))

        worker = _ConnCheckWorker(viewer)
        worker.signals.success.connect(viewer._on_conn_check_success)
        worker.signals.failure.connect(viewer._on_conn_check_failure)
        self.thread_pool.start(worker)

    @Slot()
    def _on_conn_check_success(self):
        if not hasattr(self, 'agent_conn_status_label'):
            return
        logging.info("_on_conn_check_success: Setting label to ✔ Reachable")
        self.agent_conn_status_label.setText("✔ Reachable")
        self.agent_conn_status_label.setStyleSheet("color: green; font-weight: bold;")

    @Slot(str)
    def _on_conn_check_failure(self, error_msg: str):
        if not hasattr(self, 'agent_conn_status_label'):
            return
        logging.info(f"_on_conn_check_failure: Setting label to ✖ Unreachable, error: {error_msg}")
        self.agent_conn_status_label.setText("✖ Unreachable")
        self.agent_conn_status_label.setStyleSheet("color: red; font-weight: bold;")

        dlg = QDialog(self)
        dlg.setWindowTitle("Connection check failed")
        dlg.setMinimumWidth(400)
        layout = QVBoxLayout(dlg)

        icon_row = QHBoxLayout()
        icon_lbl = QLabel()
        icon_lbl.setPixmap(
            self.style().standardPixmap(QStyle.SP_MessageBoxWarning).scaled(32, 32)
        )
        icon_row.addWidget(icon_lbl)
        msg_lbl = QLabel(f"<b>Could not reach the server.</b><br><br>{error_msg}")
        msg_lbl.setWordWrap(True)
        icon_row.addWidget(msg_lbl, 1)
        layout.addLayout(icon_row)

        btns = QDialogButtonBox()
        retry_btn = btns.addButton("Retry", QDialogButtonBox.AcceptRole)
        btns.addButton("Cancel", QDialogButtonBox.RejectRole)
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        layout.addWidget(btns)

        if dlg.exec() == QDialog.Accepted:
            self._trigger_agent_connectivity_check()

    def _start_flask_server(self):
        """Start the Flask HTTP server in a background daemon thread.

        Uses werkzeug.serving.make_server() instead of app.run() so we hold a
        reference to the WSGI server object and can call .shutdown() later.
        A port-availability pre-check is done on the calling (UI) thread so
        that binding errors are reported immediately with a friendly message.
        """
        try:
            from flask import Flask, request as flask_request, jsonify
            from werkzeug.serving import make_server as werkzeug_make_server
        except ImportError:
            logging.error("Flask is not installed. Install it with: pip install flask")
            return

        # --- Pre-check: is the port available? -----------------------------------
        port_error = self._check_port_available(FLASK_SERVER_PORT)
        if port_error:
            self._show_flask_port_error(port_error, FLASK_SERVER_PORT)
            return
        # -------------------------------------------------------------------------

        app = Flask(__name__)
        # Security: limit request payload to 10 MB to prevent memory exhaustion
        app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
        viewer = self  # capture reference for the route closure

        @app.route("/submit_connections", methods=["POST"])
        def submit_connections():
            try:
                data = flask_request.get_json(force=True)
                if not isinstance(data, dict):
                    return jsonify({"status": "error", "message": "Invalid payload"}), 400
                hostname = data.get("hostname", "unknown")
                # Security: sanitize hostname — only allow printable, non-control characters, max 255 chars
                if not isinstance(hostname, str) or len(hostname) > 255:
                    return jsonify({"status": "error", "message": "Invalid hostname"}), 400
                hostname = hostname.strip()
                if not hostname:
                    hostname = "unknown"
                ip_addresses = data.get("ip_addresses", [])
                if not isinstance(ip_addresses, list):
                    ip_addresses = []
                public_ip = data.get("public_ip", "")
                if not isinstance(public_ip, str):
                    public_ip = ""
                loc_lat = data.get("lat")
                loc_lng = data.get("lng")
                # Security: validate lat/lng are numeric or None
                if loc_lat is not None:
                    try:
                        loc_lat = float(loc_lat)
                    except (TypeError, ValueError):
                        loc_lat = None
                if loc_lng is not None:
                    try:
                        loc_lng = float(loc_lng)
                    except (TypeError, ValueError):
                        loc_lng = None
                conns = data.get("connections", [])
                if not isinstance(conns, list):
                    conns = []
                # Security: cap the number of connections per agent to prevent memory exhaustion
                _MAX_CONNS_PER_AGENT = 10000
                conns = conns[:_MAX_CONNS_PER_AGENT]
                with viewer._agent_cache_lock:
                    # Enforce MAX_SERVER_AGENTS: reject new (unknown) agents
                    # when the limit is already reached.  Agents already in the
                    # cache are always allowed to update their data.
                    if hostname not in viewer._agent_cache and len(viewer._agent_cache) >= MAX_SERVER_AGENTS:
                        return jsonify({
                            "status": "rejected",
                            "message": f"Server agent limit reached ({MAX_SERVER_AGENTS}). "
                                       "Increase MAX_SERVER_AGENTS on the server to allow more agents."
                        }), 429
                    viewer._agent_cache[hostname] = {
                        "hostname": hostname,
                        "ip_addresses": ip_addresses,
                        "public_ip": public_ip,
                        "lat": loc_lat,
                        "lng": loc_lng,
                        "connections": conns,
                    }
                    viewer._agent_posted_since_last_cycle.add(hostname)
                return jsonify({"status": "ok", "accepted": len(conns)}), 200
            except Exception as e:
                logging.error(f"Error processing /submit_connections: {e}")
                # Security: do not expose internal error details to the client
                return jsonify({"status": "error", "message": "Bad request"}), 400

        try:
            srv = werkzeug_make_server("0.0.0.0", FLASK_SERVER_PORT, app)
        except OSError as e:
            self._show_flask_port_error(str(e), FLASK_SERVER_PORT)
            return

        self._werkzeug_server = srv

        def _run():
            wlog = logging.getLogger('werkzeug')
            wlog.setLevel(logging.ERROR)
            srv.serve_forever()

        self._flask_thread = threading.Thread(target=_run, daemon=True, name="FlaskServer")
        self._flask_thread.start()
        logging.info(f"Flask server started on port {FLASK_SERVER_PORT}")

    @staticmethod
    def _check_port_available(port: int) -> str:
        """Return an empty string if *port* is free on 0.0.0.0, else a human-readable error."""
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("0.0.0.0", port))
            probe.close()
            return ""
        except OSError as e:
            # errno 98  = EADDRINUSE  (Linux)
            # errno 10048 = WSAEADDRINUSE (Windows)
            if e.errno in (98, 10048):
                return f"Port {port} is already in use by another process."
            return f"Cannot bind to port {port}: {e.strerror} (error {e.errno})."

    def _show_flask_port_error(self, error_msg: str, failed_port: int):
        """Show a friendly error dialog and revert flask_server_port_input to the previous value."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Server port error")
        dlg.setMinimumWidth(420)
        layout = QVBoxLayout(dlg)

        icon_row = QHBoxLayout()
        icon_lbl = QLabel()
        icon_lbl.setPixmap(
            self.style().standardPixmap(QStyle.SP_MessageBoxCritical).scaled(32, 32)
        )
        icon_row.addWidget(icon_lbl)
        detail = (
            f"<b>Could not start the server on port {failed_port}.</b><br><br>"
            f"{error_msg}<br><br>"
            f"The port has been reverted to the previous value."
        )
        msg_lbl = QLabel(detail)
        msg_lbl.setWordWrap(True)
        icon_row.addWidget(msg_lbl, 1)
        layout.addLayout(icon_row)

        btns = QDialogButtonBox(QDialogButtonBox.Ok)
        btns.accepted.connect(dlg.accept)
        layout.addWidget(btns)
        dlg.exec()

    def _restart_flask_server(self, previous_port: int):
        """Stop the running Werkzeug server and restart on FLASK_SERVER_PORT.

        Shuts down the current server first, then probes the new port to catch
        conflicts with *other* processes before attempting to bind.
        If the new port is unavailable FLASK_SERVER_PORT is reverted to
        *previous_port* and the server is restarted on that port instead.
        """
        global FLASK_SERVER_PORT

        # --- Stop the current server first ---------------------------------------
        srv = getattr(self, '_werkzeug_server', None)
        if srv is not None:
            try:
                srv.shutdown()
            except Exception as e:
                logging.warning(f"Error shutting down Flask server: {e}")
            self._werkzeug_server = None

        if self._flask_thread is not None:
            self._flask_thread.join(timeout=3)
            self._flask_thread = None
        # -------------------------------------------------------------------------

        # Now that our port is released, probe for external conflicts
        port_error = self._check_port_available(FLASK_SERVER_PORT)
        if port_error:
            # Revert to previous port
            FLASK_SERVER_PORT = previous_port
            if hasattr(self, 'flask_server_port_input'):
                self.flask_server_port_input.setText(str(previous_port))
                self.flask_server_port_input.setStyleSheet("border: 1px solid orange;")
            self._show_flask_port_error(port_error, FLASK_SERVER_PORT)
            if hasattr(self, 'flask_server_port_input'):
                self.flask_server_port_input.setStyleSheet("")
            # Restart on the reverted (previous) port
            self._start_flask_server()
            self.save_settings()
            return

        # Start on new port
        self._start_flask_server()
        self.save_settings()
        logging.info(f"Flask server restarted on port {FLASK_SERVER_PORT}")

    def _collect_and_reset_agent_cache(self):
        """Return a snapshot of the agent cache without clearing it.

        The cache is intentionally *not* cleared here.  Each agent's entry is
        only replaced when the agent sends a new POST (in the Flask route).
        This means a single missed POST cycle no longer causes the agent to
        vanish from the map — the last-known data is kept until fresh data
        arrives or the server is restarted.
        """
        with self._agent_cache_lock:
            snapshot = dict(self._agent_cache)
            # Atomically read and clear the posted-since-last-cycle set under the
            # same lock the Flask POST handler uses, so there is no race.
            posted_this_cycle = set(self._agent_posted_since_last_cycle)
            self._agent_posted_since_last_cycle.clear()
        self._last_agent_count = len(snapshot)

        # Advance inactive-strike counters at most once per timer interval.
        # refresh_connections() can be called from multiple sources (timer,
        # checkbox toggles, DNS flush, start button) — without this guard
        # the strikes would be advanced multiple times per interval causing
        # agents to transiently appear inactive.
        import time as _time
        now = _time.monotonic()
        min_interval = (map_refresh_interval / 1000.0) * 0.8  # 80% of timer period
        if (now - self._last_strike_advance_time) >= min_interval:
            self._last_strike_advance_time = now
            all_known = set(self._agent_inactive_strikes.keys()) | set(snapshot.keys()) | posted_this_cycle
            for hostname in all_known:
                # The local server never POSTs to itself — always treat it as active
                if hostname == LOCAL_HOSTNAME:
                    self._agent_inactive_strikes[hostname] = 0
                elif hostname in posted_this_cycle:
                    self._agent_inactive_strikes[hostname] = 0
                else:
                    self._agent_inactive_strikes[hostname] = \
                        self._agent_inactive_strikes.get(hostname, 0) + 1

        # If the agent management table exists, schedule a refresh every cycle
        # so that the "Is Active" column stays current.
        if hasattr(self, 'agent_mgmt_table'):
            _self_ref = weakref.ref(self)
            def _deferred_refresh():
                v = _self_ref()
                if v is not None:
                    v._refresh_agent_management_table()
            QTimer.singleShot(0, _deferred_refresh)

        return snapshot

    def _get_local_ip_addresses(self):
        """Return a list of non-loopback IP addresses on this machine."""
        addrs = []
        try:
            for iface, snics in psutil.net_if_addrs().items():
                for snic in snics:
                    if snic.family in (socket.AF_INET, socket.AF_INET6):
                        addr = snic.address
                        if addr and addr not in ('127.0.0.1', '::1', ''):
                            addrs.append(addr)
        except Exception:
            pass
        return addrs

    def _get_local_geolocation(self):
        """Return (lat, lng) for this machine's public IP, or (None, None)."""
        try:
            public_ip = self.get_public_ip()
            if public_ip:
                return self._get_local_geolocation_for_ip(public_ip)
        except Exception:
            pass
        return None, None

    def _get_local_geolocation_for_ip(self, public_ip):
        """Return (lat, lng) for the given public IP, or (None, None)."""
        try:
            if public_ip:
                try:
                    ip_obj = ipaddress.ip_address(public_ip)
                    ip_type = "IPv4" if ip_obj.version == 4 else "IPv6"
                except Exception:
                    ip_type = "IPv4"
                reader = self.reader_ipv4 if ip_type == "IPv4" else self.reader_ipv6
                if reader:
                    res = reader.get(public_ip)
                    if res:
                        lat = res.get('latitude') or res.get('location', {}).get('latitude')
                        lng = res.get('longitude') or res.get('location', {}).get('longitude')
                        return lat, lng
        except Exception:
            pass
        return None, None

    def _agent_post_connections(self, connections):
        """Schedule a background POST of the local connection list to the server (agent mode).
        The actual network I/O runs on a dedicated daemon thread to avoid blocking the UI.
        Only the most recent payload is kept; if the worker is still busy with a previous
        POST, the older payload is silently replaced."""
        global agent_server_host
        if not agent_server_host:
            return

        import copy
        payload = {
            "hostname": LOCAL_HOSTNAME,
            "ip_addresses": self._get_local_ip_addresses(),
            "connections": copy.deepcopy(connections),
        }
        with self._agent_post_lock:
            self._agent_post_pending = payload
        # Wake the worker thread
        self._agent_post_event.set()

    def _agent_post_worker(self):
        """Background daemon thread that sends the latest agent payload to the server.
        Blocks on _agent_post_event until new data is available. Resolves the public IP
        and geolocation here (off the UI thread) so those network calls never block Qt."""
        while not self._agent_post_stop.is_set():
            # Wait for new data or stop signal
            self._agent_post_event.wait()
            if self._agent_post_stop.is_set():
                break
            self._agent_post_event.clear()

            # Grab the latest payload
            with self._agent_post_lock:
                payload = self._agent_post_pending
                self._agent_post_pending = None
            if payload is None:
                continue

            # Resolve public IP and geolocation on this background thread
            try:
                public_ip = self.get_public_ip() if do_resolve_public_ip else ""
                lat, lng = self._get_local_geolocation_for_ip(public_ip) if public_ip else (None, None)
                payload["public_ip"] = public_ip
                payload["lat"] = lat
                payload["lng"] = lng
            except Exception:
                payload.setdefault("public_ip", "")
                payload.setdefault("lat", None)
                payload.setdefault("lng", None)

            url = f"http://{agent_server_host}:{FLASK_AGENT_PORT}/submit_connections"
            max_retries = 3
            _post_succeeded = False
            for attempt in range(max_retries):
                if self._agent_post_stop.is_set():
                    return
                try:
                    resp = self._agent_http_session.post(url, json=payload, timeout=(3, 5))
                    if resp.status_code == 200:
                        self._agent_rejected_429 = False
                        self._agent_server_unreachable = False
                        _post_succeeded = True
                        logging.debug(f"Agent POST successful ({len(payload.get('connections', []))} conns)")
                        break
                    elif resp.status_code == 429:
                        self._agent_rejected_429 = True
                        self._agent_server_unreachable = False
                        _post_succeeded = True  # server is reachable, just rejecting
                        logging.warning(
                            "Agent POST rejected — server agent limit reached (HTTP 429). "
                            "Ask the server admin to increase MAX_SERVER_AGENTS."
                        )
                        break  # no point retrying a 429; the limit is server-side
                    else:
                        self._agent_server_unreachable = False
                        logging.warning(f"Agent POST returned {resp.status_code}: {resp.text[:200]}")
                except requests.exceptions.ConnectionError as e:
                    logging.error(f"Agent POST connection error (attempt {attempt+1}/{max_retries}): {e}")
                except requests.exceptions.Timeout:
                    logging.error(f"Agent POST timeout (attempt {attempt+1}/{max_retries})")
                except Exception as e:
                    logging.error(f"Agent POST error (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    # Interruptible sleep so we can stop quickly
                    self._agent_post_stop.wait(0.5)
            if not _post_succeeded:
                self._agent_server_unreachable = True

    def closeEvent(self, event):
        """Save settings when closing the application"""
        try:
            if getattr(self, "dns_worker", None) is not None:
                self.dns_worker.stop()
                self.dns_worker.join(timeout=2.0)
        except Exception:
            pass

        # Signal the agent POST background thread to stop
        try:
            self._agent_post_stop.set()
            self._agent_post_event.set()  # wake it so it sees the stop flag
        except Exception:
            pass

        # Stop the active collector plugin if it has a running background task
        try:
            if hasattr(self._active_collector, 'stop') and callable(self._active_collector.stop):
                self._active_collector.stop()
        except Exception:
            pass

        # Cleanly close the database provider
        self._deactivate_db_provider()

        self.save_settings()
        if self.reader_ipv4 is not None:
            self.reader_ipv4.close()
        if self.reader_ipv6 is not None:
            self.reader_ipv6.close()
        self.save_ip_cache()
        event.accept()

    def load_ip_cache(self):
        """
        Load ip_cache from disk (JSON) into the in-memory cache protected by cache_lock.
        File location: <DB_DIR>/ip_cache.json
        """
        global ip_cache, cache_lock

        if not PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK:
            return

        cache_file = os.path.join(DB_DIR, IP_DNS_NAME_CACHE_FILE)
        try:
            if not os.path.exists(cache_file):
                return

            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                with cache_lock:
                    ip_cache.clear()
                    # ensure keys/values are strings or None
                    for k, v in data.items():
                        ip_cache[str(k)] = v if v is None or isinstance(v, str) else str(v)
        except Exception:
            pass  # Fail silently — do not break startup

    def save_ip_cache(self):
        """
        Save the ip_cache to disk as JSON. Uses a atomic write (write temp, rename) where possible.
        """
        global ip_cache, cache_lock

        if not PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK:
            return

        try:
            os.makedirs(DB_DIR, exist_ok=True)
            cache_file = os.path.join(DB_DIR, IP_DNS_NAME_CACHE_FILE)
            tmp_file = cache_file + ".tmp"

            # snapshot the cache under lock to avoid blocking lookups longer than necessary
            with cache_lock:
                snapshot = dict(ip_cache)

            # write snapshot
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, ensure_ascii=False)

            # atomic replace
            try:
                os.replace(tmp_file, cache_file)
            except Exception:
                # fallback to non-atomic rename
                os.remove(cache_file) if os.path.exists(cache_file) else None
                os.rename(tmp_file, cache_file)

        except Exception:
            pass

    def reverse_dns(self, ips):
        """
        Fast, thread-safe reverse DNS with local caching.

        - Uses the shared `ip_cache` protected by `cache_lock`.
        - Avoids work for already-cached addresses.
        - Executes lookups in a ThreadPoolExecutor with a bounded worker count.
        - Updates cache from worker threads to minimize post-processing allocations.
        - Returns a dict mapping only resolved IP -> hostname.
        """
        if isinstance(ips, str):
            ips = [ips]

        # normalize input and filter falsy entries early
        ips = [ip for ip in ips if ip]

        if not ips:
            return {}

        # Local references to globals to reduce attribute lookups
        global ip_cache, cache_lock

        results = {}
        to_resolve = []

        # Fast path: check cache under lock and build list of addresses that need lookup
        with cache_lock:
            for ip in ips:
                if ip in ip_cache:
                    host = ip_cache[ip]
                    if host:
                        results[ip] = host
                else:
                    to_resolve.append(ip)

        if not to_resolve:
            return results

        # Choose a sensible worker count (avoid oversubscription)
        max_workers = min(32, max(4, len(to_resolve)))

        def _lookup_and_cache(ip_addr):
            global ip_cache, cache_lock
            """Worker function: resolve ip and atomically store result in cache."""
            try:
                hostname = socket.gethostbyaddr(ip_addr)[0]
            except Exception:
                hostname = None

            # update cache immediately under lock (store None for negative answers)
            with cache_lock:
                ip_cache[ip_addr] = hostname
            return ip_addr, hostname

        # Submit lookups and collect resolved hostnames
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {exe.submit(_lookup_and_cache, ip): ip for ip in to_resolve}
            for fut in as_completed(futures):
                try:
                    ip_addr, hostname = fut.result()
                except Exception:
                    # defensive: skip on unexpected worker exception
                    continue
                if hostname:
                    results[ip_addr] = hostname

        return results

    @Slot(str, str)
    def _on_dns_resolved(self, ip, hostname):
        """
        Called on the main thread when DNSWorker resolves a hostname.
        Debounces UI refreshes to avoid spamming refresh_connections().
        """
        with self._dns_update_lock:
            if self._dns_update_scheduled:
                return
            self._dns_update_scheduled = True

        # schedule a single refresh after short delay to batch multiple resolutions
        QTimer.singleShot(500, self._dns_updates_flush)

    @Slot()
    def _dns_updates_flush(self):
        """
        Called on the main thread to apply DNS updates (refresh UI once).
        """
        with self._dns_update_lock:
            self._dns_update_scheduled = False

        try:
            # Refresh current view to show newly-resolved hostnames.
            # Use current slider position to avoid resetting timeline.
            self.refresh_connections(slider_position=self.slider.value())
        except Exception:
            pass

    @Slot()
    def _cleanup_public_ip_dns_cache(self):
        """
        Periodic cleanup callback for public IP DNS attempt cache.
        Runs every 60 seconds when do_reverse_dns is True.
        Resets the cache if it exceeds 10000 entries to prevent unbounded memory growth.
        """
        global public_ip_dns_attempts, public_ip_dns_attempts_lock

        try:
            with public_ip_dns_attempts_lock:
                cache_size = len(public_ip_dns_attempts)
                if cache_size > PUBLIC_IP_ENQUEUE_MAX_CACHE_SIZE:
                    # Reset cache to prevent unbounded memory growth
                    public_ip_dns_attempts.clear()
                    logging.info(f"Public IP DNS cache cleared (exceeded {PUBLIC_IP_ENQUEUE_MAX_CACHE_SIZE} entries, was {cache_size})")
        except Exception as e:
            logging.warning(f"Error cleaning public IP DNS cache: {e}")



    @Slot(QPoint)
    def on_connection_table_context_menu(self, pos):
        """Show a right-click context menu for the connection table row under the cursor."""
        index = self.connection_table.indexAt(pos)
        if not index.isValid():
            return

        row = index.row()
        pid_item = self.connection_table.item(row, PID_ROW_INDEX)
        pid = pid_item.text().strip() if pid_item else ""
        process_item = self.connection_table.item(row, PROCESS_ROW_INDEX)
        process_name = process_item.text().strip() if process_item else ""
        hostname_item = self.connection_table.item(row, HOSTNAME_ROW_INDEX)
        row_hostname = hostname_item.text().strip() if hostname_item else ""

        menu = QMenu(self)

        # Hide / Unhide local connections (routable filter)
        action_toggle_remote = menu.addAction("Hide local connections and local network traffic")
        action_toggle_remote.setCheckable(True)
        action_toggle_remote.setChecked(show_only_remote_connections)
        menu.addSeparator()

        # Copy cell value — always the first action
        cell_item = self.connection_table.item(row, index.column())
        cell_text = cell_item.text() if cell_item else ""
        action_copy = menu.addAction("Copy")
        menu.addSeparator()

        # Bring to top layer — visible when multiple agents are present
        action_bring_to_top = menu.addAction("Bring to top layer")
        foreground_host = getattr(self, '_foreground_hostname', LOCAL_HOSTNAME)
        action_bring_to_top.setEnabled(bool(row_hostname) and row_hostname != foreground_host)
        menu.addSeparator()

        # Hide / Unhide agent actions (only when in server mode with agents)
        action_hide_agent = action_unhide_agent = None
        action_hide_all_others = action_unhide_all = None
        if enable_server_mode and row_hostname and row_hostname in self._agent_colors:
            is_hidden = self._agent_hidden.get(row_hostname, False)
            if is_hidden:
                action_unhide_agent = menu.addAction(f"Unhide agent \"{row_hostname}\" on map")
            else:
                action_hide_agent = menu.addAction(f"Hide agent \"{row_hostname}\" on map")
            action_hide_all_others = menu.addAction(f"Hide all other agents except \"{row_hostname}\"")
            action_unhide_all = menu.addAction("Unhide all agents")
            menu.addSeparator()

        # Only offer local-process tools when the row comes from this machine
        _is_remote_agent = bool(row_hostname) and row_hostname != LOCAL_HOSTNAME
        action_open = action_memory = action_procmon = None
        if not _is_remote_agent and process_name != "" and process_name != "Unknown":
            if platform.system() == "Windows":
                action_open = menu.addAction(f"Open {process_name} pid:{pid} in Process Explorer")
                action_memory = menu.addAction(f"Capture {process_name} pid:{pid} ProcDump full memory")
                action_procmon = menu.addAction(f"Open {process_name} pid:{pid} in Process Monitor")
            else:
                action_open = menu.addAction(f"Open {process_name} pid:{pid} in htop")
                action_memory = menu.addAction(f"Capture {process_name} pid:{pid} memory")

        chosen = menu.exec(self.connection_table.viewport().mapToGlobal(pos))
        if chosen is None:
            return

        if chosen == action_toggle_remote:
            self._toggle_only_remote_connections()
            return

        if chosen == action_copy:
            QApplication.clipboard().setText(cell_text)
            return

        if chosen == action_bring_to_top:
            if row_hostname:
                self.bring_to_top_layer(row_hostname)
            return

        if chosen == action_hide_agent:
            self._agent_hidden[row_hostname] = True
            self.save_settings()
            self._refresh_agent_management_table(force_rebuild=True)
            self._update_map_with_filter()
            return

        if chosen == action_unhide_agent:
            self._agent_hidden.pop(row_hostname, None)
            self.save_settings()
            self._refresh_agent_management_table(force_rebuild=True)
            self._update_map_with_filter()
            return

        if chosen == action_hide_all_others:
            all_agents = set(self._agent_colors.keys()) | {LOCAL_HOSTNAME}
            for hn in all_agents:
                if hn != row_hostname:
                    self._agent_hidden[hn] = True
                else:
                    self._agent_hidden.pop(hn, None)
            self.save_settings()
            self._refresh_agent_management_table(force_rebuild=True)
            self._update_map_with_filter()
            return

        if chosen == action_unhide_all:
            self._agent_hidden.clear()
            self.save_settings()
            self._refresh_agent_management_table(force_rebuild=True)
            self._update_map_with_filter()
            return

        if not pid:
            QMessageBox.warning(self, "No PID", "Could not determine the PID for the selected row.")
            return

        # Security: validate PID is purely numeric to prevent command injection
        # (especially via terminal -e on Linux which interprets args as shell commands)
        if not pid.isdigit():
            QMessageBox.warning(self, "Invalid PID", f"PID value '{pid}' is not a valid numeric process ID.")
            return

        if platform.system() == "Windows":
            if chosen == action_open:
                try:
                    # procexp /p:<pid> selects the process; fall back to plain procexp
                    subprocess.Popen(["procexp", f"/s:{pid}"])
                except FileNotFoundError:
                    QMessageBox.warning(self, "Process Explorer not found",
                                        "Process Explorer (procexp.exe) was not found on PATH.\n"
                                        "Download it from https://learn.microsoft.com/sysinternals/downloads/process-explorer")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))
            elif chosen == action_memory:
                try:
                    # procdump -ma <pid> writes a full minidump to the current directory.
                    # CREATE_NEW_CONSOLE gives the child its own console window and implicitly
                    # detaches it from ours. CREATE_NEW_PROCESS_GROUP puts it in an independent
                    # process group so closing that window never signals our process.
                    # NOTE: DETACHED_PROCESS and CREATE_NEW_CONSOLE are mutually exclusive.
                    CREATE_NEW_PROCESS_GROUP = 0x00000200
                    CREATE_NEW_CONSOLE = 0x00000010
                    subprocess.Popen(
                        ["procdump", "-ma", pid],
                        creationflags=CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
                        close_fds=True,
                    )
                except FileNotFoundError:
                    QMessageBox.warning(self, "ProcDump not found",
                                        "ProcDump (procdump.exe) was not found on PATH.\n"
                                        "Download it from https://learn.microsoft.com/sysinternals/downloads/procdump")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))
            elif chosen == action_procmon:

                if process_name != "" and process_name != "Unknown":
                    try:
                        try:
                            from procmon_parser import dump_configuration, Rule
                        except ImportError as e:
                            QMessageBox.warning(self, "procmon-parser not found",
                                                "procmon-parser is required to generate Process Monitor configurations.\n\n"
                                                "Install it using:\npip install procmon-parser\n\n"
                                                "See: https://github.com/eronnen/procmon-parser")
                            return

                        procmon_dir = "procmon"
                        os.makedirs(procmon_dir, exist_ok=True)

                        timestamp = datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
                        safe_name = "".join(c if c.isalnum() or c in ('_', '-') else '_' for c in process_name)
                        pmc_filename = f"tcp_geo_map_{timestamp}_{safe_name}_{pid}.pmc"
                        pmc_path = os.path.join(procmon_dir, pmc_filename)

                        config = {
                            "DestructiveFilter": 0,
                            "FilterRules": [
                                Rule('PID', 'is', pid, 'include'),
                                Rule('Process_Name', 'is', process_name, 'include'),
                            ],
                        }

                        with open(pmc_path, "wb") as f:
                            dump_configuration(config, f)

                        abs_pmc = os.path.abspath(pmc_path)
                        CREATE_NEW_PROCESS_GROUP = 0x00000200
                        CREATE_NEW_CONSOLE = 0x00000010
                        procmon_launched = False
                        for procmon_exe in ("Procmon64.exe", "Procmon.exe"):
                            try:
                                subprocess.Popen(
                                    [procmon_exe, "/LoadConfig", abs_pmc, "/Quiet"],
                                    creationflags=CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
                                    close_fds=True,
                                )
                                procmon_launched = True
                                break
                            except FileNotFoundError:
                                continue
                        if not procmon_launched:
                            QMessageBox.warning(self, "Process Monitor not found",
                                                "Process Monitor (Procmon64.exe / Procmon.exe) was not found on PATH.\n"
                                                "Download it from https://learn.microsoft.com/en-us/sysinternals/downloads/process-monitor")
                    except Exception as e:
                        QMessageBox.critical(self, "Error", str(e))
        else:
            if chosen == action_open:
                try:
                    # Open htop filtered to the selected PID in a new terminal.
                    # Use separate args for htop to avoid shell interpretation via -e.
                    for term in ("x-terminal-emulator", "xterm", "gnome-terminal", "konsole"):
                        try:
                            subprocess.Popen([term, "-e", "htop", "-p", pid])
                            break
                        except FileNotFoundError:
                            continue
                    else:
                        QMessageBox.warning(self, "Terminal not found",
                                            "Could not find a terminal emulator to open htop.\n"
                                            "Install xterm or another terminal emulator.")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))
            elif chosen == action_memory:
                try:
                    # gcore dumps the full process memory to core.<pid>
                    subprocess.Popen(["gcore", pid])
                except FileNotFoundError:
                    QMessageBox.warning(self, "gcore not found",
                                        "gcore was not found on PATH.\n"
                                        "Install it via: sudo apt install gdb  (or equivalent)")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))

    @Slot(QPoint)
    def on_summary_table_context_menu(self, pos):
        """Show the same right-click context menu for the summary table row under the cursor."""
        index = self.summary_table.indexAt(pos)
        if not index.isValid():
            return

        row = index.row()
        hostname_item = self.summary_table.item(row, 0)  # Hostname column
        row_hostname = hostname_item.text().strip() if hostname_item else ""
        process_item = self.summary_table.item(row, 1)  # Process column
        process_name = process_item.text().strip() if process_item else ""
        pid_item = self.summary_table.item(row, 2)      # PID column
        pid = pid_item.text().strip() if pid_item else ""

        menu = QMenu(self)

        # Hide / Unhide local connections (routable filter)
        action_toggle_remote = menu.addAction("Hide local connections")
        action_toggle_remote.setCheckable(True)
        action_toggle_remote.setChecked(show_only_remote_connections)
        menu.addSeparator()

        # Hide / Unhide agent actions (only when in server mode with agents)
        action_hide_agent = action_unhide_agent = None
        action_hide_all_others = action_unhide_all = None
        if enable_server_mode and row_hostname and row_hostname in self._agent_colors:
            is_hidden = self._agent_hidden.get(row_hostname, False)
            if is_hidden:
                action_unhide_agent = menu.addAction(f"Unhide agent \"{row_hostname}\" on map")
            else:
                action_hide_agent = menu.addAction(f"Hide agent \"{row_hostname}\" on map")
            action_hide_all_others = menu.addAction(f"Hide all other agents except \"{row_hostname}\"")
            action_unhide_all = menu.addAction("Unhide all agents")
            menu.addSeparator()

        # Only offer local-process tools when the row comes from this machine
        _is_remote_agent = bool(row_hostname) and row_hostname != LOCAL_HOSTNAME
        action_open = action_memory = action_procmon = None
        if not _is_remote_agent:
            if platform.system() == "Windows":
                action_open = menu.addAction(f"Open {process_name} pid:{pid} in Process Explorer")
                action_memory = menu.addAction(f"Capture {process_name} pid:{pid} ProcDump full memory")
                action_procmon = menu.addAction(f"Open {process_name} pid:{pid} in Process Monitor")
            else:
                action_open = menu.addAction(f"Open {process_name} pid:{pid} in htop")
                action_memory = menu.addAction(f"Capture {process_name} pid:{pid} memory")

        chosen = menu.exec(self.summary_table.viewport().mapToGlobal(pos))
        if chosen is None:
            return

        if chosen == action_toggle_remote:
            self._toggle_only_remote_connections()
            return

        if chosen == action_hide_agent:
            self._agent_hidden[row_hostname] = True
            self.save_settings()
            self._refresh_agent_management_table(force_rebuild=True)
            self._update_map_with_filter()
            return

        if chosen == action_unhide_agent:
            self._agent_hidden.pop(row_hostname, None)
            self.save_settings()
            self._refresh_agent_management_table(force_rebuild=True)
            self._update_map_with_filter()
            return

        if chosen == action_hide_all_others:
            all_agents = set(self._agent_colors.keys()) | {LOCAL_HOSTNAME}
            for hn in all_agents:
                if hn != row_hostname:
                    self._agent_hidden[hn] = True
                else:
                    self._agent_hidden.pop(hn, None)
            self.save_settings()
            self._refresh_agent_management_table(force_rebuild=True)
            self._update_map_with_filter()
            return

        if chosen == action_unhide_all:
            self._agent_hidden.clear()
            self.save_settings()
            self._refresh_agent_management_table(force_rebuild=True)
            self._update_map_with_filter()
            return

        if not pid:
            QMessageBox.warning(self, "No PID", "Could not determine the PID for the selected row.")
            return

        # Security: validate PID is purely numeric to prevent command injection
        if not pid.isdigit():
            QMessageBox.warning(self, "Invalid PID", f"PID value '{pid}' is not a valid numeric process ID.")
            return

        if platform.system() == "Windows":
            if chosen == action_open:
                try:
                    subprocess.Popen(["procexp", f"/s:{pid}"])
                except FileNotFoundError:
                    QMessageBox.warning(self, "Process Explorer not found",
                                        "Process Explorer (procexp.exe) was not found on PATH.\n"
                                        "Download it from https://learn.microsoft.com/sysinternals/downloads/process-explorer")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))
            elif chosen == action_memory:
                try:
                    CREATE_NEW_PROCESS_GROUP = 0x00000200
                    CREATE_NEW_CONSOLE = 0x00000010
                    subprocess.Popen(
                        ["procdump", "-ma", pid],
                        creationflags=CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
                        close_fds=True,
                    )
                except FileNotFoundError:
                    QMessageBox.warning(self, "ProcDump not found",
                                        "ProcDump (procdump.exe) was not found on PATH.\n"
                                        "Download it from https://learn.microsoft.com/sysinternals/downloads/procdump")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))
            elif chosen == action_procmon:
                try:
                    try:
                        from procmon_parser import dump_configuration, Rule
                    except ImportError:
                        QMessageBox.warning(self, "procmon-parser not found",
                                            "procmon-parser is required to generate Process Monitor configurations.\n\n"
                                            "Install it using:\npip install procmon-parser\n\n"
                                            "See: https://github.com/eronnen/procmon-parser")
                        return

                    procmon_dir = "procmon"
                    os.makedirs(procmon_dir, exist_ok=True)

                    timestamp = datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
                    safe_name = "".join(c if c.isalnum() or c in ('_', '-') else '_' for c in process_name)
                    pmc_filename = f"tcp_geo_map_{timestamp}_{safe_name}_{pid}.pmc"
                    pmc_path = os.path.join(procmon_dir, pmc_filename)

                    config = {
                        "DestructiveFilter": 0,
                        "FilterRules": [
                            Rule('PID', 'is', pid, 'include'),
                            Rule('Process_Name', 'is', process_name, 'include'),
                        ],
                    }

                    with open(pmc_path, "wb") as f:
                        dump_configuration(config, f)

                    abs_pmc = os.path.abspath(pmc_path)
                    CREATE_NEW_PROCESS_GROUP = 0x00000200
                    CREATE_NEW_CONSOLE = 0x00000010
                    procmon_launched = False
                    for procmon_exe in ("Procmon64.exe", "Procmon.exe"):
                        try:
                            subprocess.Popen(
                                [procmon_exe, "/LoadConfig", abs_pmc, "/Quiet"],
                                creationflags=CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
                                close_fds=True,
                            )
                            procmon_launched = True
                            break
                        except FileNotFoundError:
                            continue
                    if not procmon_launched:
                        QMessageBox.warning(self, "Process Monitor not found",
                                            "Process Monitor (Procmon64.exe / Procmon.exe) was not found on PATH.\n"
                                            "Download it from https://learn.microsoft.com/en-us/sysinternals/downloads/process-monitor")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))
        else:
            if chosen == action_open:
                try:
                    # Use separate args for htop to avoid shell interpretation via -e
                    for term in ("x-terminal-emulator", "xterm", "gnome-terminal", "konsole"):
                        try:
                            subprocess.Popen([term, "-e", "htop", "-p", pid])
                            break
                        except FileNotFoundError:
                            continue
                    else:
                        QMessageBox.warning(self, "Terminal not found",
                                            "Could not find a terminal emulator to open htop.\n"
                                            "Install xterm or another terminal emulator.")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))
            elif chosen == action_memory:
                try:
                    subprocess.Popen(["gcore", pid])
                except FileNotFoundError:
                    QMessageBox.warning(self, "gcore not found",
                                        "gcore was not found on PATH.\n"
                                        "Install it via: sudo apt install gdb  (or equivalent)")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))

    # ------------------------------------------------------------------
    # Column width helpers — persist / restore / debounce
    # ------------------------------------------------------------------

    @staticmethod
    def _get_column_widths(table: 'QTableWidget') -> list:
        """Return a list of column widths (by logical index) for *table*."""
        try:
            hdr = table.horizontalHeader()
            return [hdr.sectionSize(i) for i in range(hdr.count())]
        except Exception:
            return []

    @staticmethod
    def _apply_column_widths(table: 'QTableWidget', widths: list):
        """Restore column widths from a saved list (by logical index)."""
        try:
            if not widths:
                return
            hdr = table.horizontalHeader()
            for i, w in enumerate(widths):
                if i < hdr.count() and w > 0:
                    table.setColumnWidth(i, w)
        except Exception:
            pass

    def _debounced_save_column_widths(self):
        """Schedule a save_settings() call after a short delay so that
        rapid sectionResized signals (e.g. during a column-edge drag)
        don't trigger dozens of file writes."""
        if not hasattr(self, '_col_width_save_timer'):
            self._col_width_save_timer = QTimer(self)
            self._col_width_save_timer.setSingleShot(True)
            self._col_width_save_timer.setInterval(500)  # ms
            self._col_width_save_timer.timeout.connect(self.save_settings)
        self._col_width_save_timer.start()

    # ------------------------------------------------------------------
    # Column order helpers — connection table
    # ------------------------------------------------------------------

    def _get_conn_table_column_order(self) -> list:
        """Return the current visual-to-logical mapping as a list."""
        try:
            hdr = self.connection_table.horizontalHeader()
            return [hdr.logicalIndex(v) for v in range(hdr.count())]
        except Exception:
            return []

    def _apply_conn_table_column_order(self, order: list):
        """Restore a previously saved column order onto the connection table."""
        try:
            if not order:
                return
            hdr = self.connection_table.horizontalHeader()
            n = hdr.count()
            if len(order) != n:
                return
            # Move each logical column to its saved visual position
            for visual_pos, logical in enumerate(order):
                current_visual = hdr.visualIndex(logical)
                if current_visual != visual_pos:
                    hdr.moveSection(current_visual, visual_pos)
            self._sync_filter_order(self.connection_table, self._connection_filter_inputs,
                                    self._connection_filter_inner)
            self._sync_filter_widths()
        except Exception:
            pass

    def _on_conn_table_section_moved(self, logical, old_visual, new_visual):
        """Called when the user drags a column in the connection table."""
        self._sync_filter_order(self.connection_table, self._connection_filter_inputs,
                                self._connection_filter_inner)
        self._sync_filter_widths()
        self.save_settings()

    # ------------------------------------------------------------------
    # Column order helpers — summary table
    # ------------------------------------------------------------------

    def _get_summary_table_column_order(self) -> list:
        """Return the current visual-to-logical mapping for the summary table."""
        try:
            hdr = self.summary_table.horizontalHeader()
            return [hdr.logicalIndex(v) for v in range(hdr.count())]
        except Exception:
            return []

    def _apply_summary_table_column_order(self, order: list):
        """Restore a previously saved column order onto the summary table."""
        try:
            if not order:
                order = SUMMARY_TABLE_DEFAULT_COLUMN_ORDER
            hdr = self.summary_table.horizontalHeader()
            n = hdr.count()
            if len(order) != n:
                return
            for visual_pos, logical in enumerate(order):
                current_visual = hdr.visualIndex(logical)
                if current_visual != visual_pos:
                    hdr.moveSection(current_visual, visual_pos)
            self._sync_filter_order(self.summary_table, self._summary_filter_inputs,
                                    self._summary_filter_inner)
            self._sync_summary_filter_widths()
        except Exception:
            pass

    def _on_summary_table_section_moved(self, logical, old_visual, new_visual):
        """Called when the user drags a column in the summary table."""
        self._sync_filter_order(self.summary_table, self._summary_filter_inputs,
                                self._summary_filter_inner)
        self._sync_summary_filter_widths()
        self.save_settings()

    def _reset_column_order(self):
        """Reset both connection and summary tables to their default column order and widths."""
        global conn_table_column_widths, summary_table_column_widths
        try:
            hdr = self.connection_table.horizontalHeader()
            for logical in range(hdr.count()):
                current_visual = hdr.visualIndex(logical)
                if current_visual != logical:
                    hdr.moveSection(current_visual, logical)
            self._sync_filter_order(self.connection_table, self._connection_filter_inputs,
                                    self._connection_filter_inner)
            self._sync_filter_widths()
        except Exception:
            pass
        try:
            self._apply_summary_table_column_order(SUMMARY_TABLE_DEFAULT_COLUMN_ORDER)
        except Exception:
            pass
        # Clear persisted widths so the default sizes apply on next restart
        conn_table_column_widths = []
        summary_table_column_widths = []
        self.save_settings()

    # ------------------------------------------------------------------
    # Shared: reorder filter bar inputs to match the current visual order
    # ------------------------------------------------------------------

    def _sync_filter_order(self, table: 'QTableWidget', inputs: list,
                           inner_widget: 'QWidget'):
        """Re-insert filter QLineEdit widgets into *inner_widget* so their
        visual positions match the current column order of *table*.

        The inputs list is kept sorted by *logical* column index; the layout
        order is changed to match the current visual order."""
        try:
            hdr = table.horizontalHeader()
            layout = inner_widget.layout()
            # layout item 0 is the vertical-header spacer — leave it alone
            # Remove all inputs from the layout (without deleting them)
            for le in inputs:
                layout.removeWidget(le)
            # Re-add in visual order
            for visual_pos in range(hdr.count()):
                logical = hdr.logicalIndex(visual_pos)
                layout.addWidget(inputs[logical])
        except Exception:
            pass

    def _sync_filter_widths(self):
        """Resize filter bar inputs to match the current connection table column widths."""
        try:
            hdr = self.connection_table.horizontalHeader()
            vh_width = self.connection_table.verticalHeader().width()
            self._connection_filter_vheader_spacer.setFixedWidth(vh_width)
            total_width = vh_width
            for visual_pos in range(hdr.count()):
                logical = hdr.logicalIndex(visual_pos)
                col_width = self.connection_table.columnWidth(logical)
                self._connection_filter_inputs[logical].setFixedWidth(col_width)
                total_width += col_width
            self._connection_filter_inner.setFixedWidth(total_width)
        except Exception:
            pass

    def _get_active_filters(self):
        """Return a list of (col_index, filter_text) pairs for every non-empty filter input."""
        result = []
        for col, le in enumerate(self._connection_filter_inputs):
            f = le.text().strip().lower()
            if f:
                result.append((col, f))
        return result

    def _conn_matches_filters(self, conn, filters):
        """Return True when *conn* (a connection dict) satisfies all active filters.

        The filter columns map to connection dict keys via the same indices used
        by the table so the map and the table always agree on what is visible."""
        if not filters:
            return True
        col_to_key = self._COL_TO_KEY
        for col, f in filters:
            getter = col_to_key.get(col)
            value = getter(conn).lower() if getter else ''
            if f not in value:
                return False
        return True

    @Slot()
    def apply_connection_table_filter(self, update_map=True):
        """Show/hide connection table rows based on the active per-column filter inputs,
        then re-render the map so it reflects the same filtered view."""
        try:
            filters = [le.text().strip().lower() for le in self._connection_filter_inputs]
            has_filter = any(filters)
            for row in range(self.connection_table.rowCount()):
                if not has_filter:
                    self.connection_table.setRowHidden(row, False)
                    continue
                visible = True
                for col, f in enumerate(filters):
                    if f:
                        item = self.connection_table.item(row, col)
                        if f not in (item.text().lower() if item else ""):
                            visible = False
                            break
                self.connection_table.setRowHidden(row, not visible)
        except Exception:
            pass

        # Re-render the map to match the filtered table view
        if update_map:
            try:
                if hasattr(self, 'connections') and self.connections is not None:
                    self._update_map_with_filter()
            except Exception:
                pass

    def _sync_summary_filter_widths(self):
        """Resize summary filter bar inputs to match the current summary table column widths."""
        try:
            hdr = self.summary_table.horizontalHeader()
            vh_width = self.summary_table.verticalHeader().width()
            self._summary_filter_vheader_spacer.setFixedWidth(vh_width)
            total_width = vh_width
            for visual_pos in range(hdr.count()):
                logical = hdr.logicalIndex(visual_pos)
                col_width = self.summary_table.columnWidth(logical)
                self._summary_filter_inputs[logical].setFixedWidth(col_width)
                total_width += col_width
            self._summary_filter_inner.setFixedWidth(total_width)
        except Exception:
            pass

    @Slot()
    def apply_summary_table_filter(self):
        """Show/hide summary table rows based on the active per-column filter inputs."""
        try:
            filters = [le.text().strip().lower() for le in self._summary_filter_inputs]
            has_filter = any(filters)
            for row in range(self.summary_table.rowCount()):
                if not has_filter:
                    self.summary_table.setRowHidden(row, False)
                    continue
                visible = True
                for col, f in enumerate(filters):
                    if f:
                        item = self.summary_table.item(row, col)
                        if f not in (item.text().lower() if item else ""):
                            visible = False
                            break
                self.summary_table.setRowHidden(row, not visible)
        except Exception:
            pass

    def _update_sort_indicator(self, table, base_headers, sort_col, descending):
        """Set ▲ / ▼ on the sorted column header; reset all others to base text."""
        header = table.horizontalHeader()
        model = table.horizontalHeaderItem  # shortcut
        for i in range(table.columnCount()):
            base = base_headers[i] if i < len(base_headers) else ""
            if i == sort_col:
                arrow = " ▼" if descending else " ▲"
                label = base + arrow
            else:
                label = base
            item = model(i)
            if item is not None:
                item.setText(label)
            else:
                table.setHorizontalHeaderItem(i, QTableWidgetItem(label))

    @Slot(int)
    def on_header_clicked(self, index):
        """
        Handles sorting when a column header is clicked.

        Args:
            index (int): The column index that was clicked.
        """
        global table_column_sort_index
        global table_column_sort_reverse

        if table_column_sort_index == index:
            table_column_sort_reverse = not table_column_sort_reverse

        table_column_sort_index = index

        self.sort_table_by_column(index, table_column_sort_reverse)
        self._update_sort_indicator(self.connection_table, self._conn_table_base_headers,
                                    table_column_sort_index, table_column_sort_reverse)
        self.apply_connection_table_filter()


    def bring_to_top_layer(self, hostname):
        """Promote *hostname* to the foreground rendering layer.

        The foreground agent gets the standard localhost colour scheme
        (green / blue / yellow / red).  Localhost, when demoted, renders grey.
        Calling this with LOCAL_HOSTNAME restores the default state.
        """
        try:
            if not hostname:
                return
            self._foreground_hostname = hostname
            logging.debug("Foreground host set to: %s", hostname)
            # Re-render the map immediately to reflect the new layer order.
            self._update_map_with_filter()
        except Exception as e:
            logging.error(f"bring_to_top_layer error: {e}")

    def _update_map_with_filter(self):
        """Re-render the map using the last fully-processed connection list filtered
        by the active column filters.  Agent exit-point circles are always rendered
        for every known agent regardless of whether any of their connections survive
        the filter."""
        try:
            # Use the cached fully-processed list (includes remote agent data)
            # instead of self.connections which only holds raw local connections.
            source = getattr(self, '_last_map_connections', None)
            if not source:
                # Fallback for the very first render before any refresh has run
                if not hasattr(self, 'connections') or self.connections is None:
                    return
                source = self.connections

            active_filters = self._get_active_filters()

            if not active_filters:
                # No filter — re-render with the full connection list as-is.
                # (Do not return early: callers such as _on_color_changed rely on
                # this path to push an immediate map update without a full refresh.)
                stats_line = getattr(self, '_last_stats_line', '')
                datetime_text = getattr(self, '_last_datetime_text', '')
                force_tooltip = show_tooltip
                self.update_map(list(source), force_tooltip,
                                stats_text=stats_line, datetime_text=datetime_text,
                                skip_histogram=True)
                return

            filtered = []
            # Collect the set of agent origin-hostnames that appear in the *full* connection
            # list so we can inject stub entries for any agent that has no matched connections
            # (their exit-point circle must still appear on the map).
            all_agent_origins = {}   # hostname -> first conn that carries origin info
            for conn in source:
                oh = conn.get('origin_hostname')
                if oh and oh not in all_agent_origins:
                    all_agent_origins[oh] = conn

            matched_agent_origins = set()
            for conn in source:
                if self._conn_matches_filters(conn, active_filters):
                    filtered.append(conn)
                    oh = conn.get('origin_hostname')
                    if oh:
                        matched_agent_origins.add(oh)

            # For agents whose connections were all filtered out, inject a minimal stub
            # that carries only the origin metadata (no lat/lng for a marker) so that
            # update_map still synthesises the agentCircle for that agent.
            for hostname, ref_conn in all_agent_origins.items():
                if hostname not in matched_agent_origins:
                    filtered.append({
                        'process': '', 'pid': '', 'suspect': '', 'local': '', 'localport': '',
                        'remote': '', 'remoteport': '', 'name': '', 'ip_type': '',
                        'lat': None, 'lng': None, 'icon': '',
                        'origin_hostname': hostname,
                        'origin_lat':      ref_conn.get('origin_lat'),
                        'origin_lng':      ref_conn.get('origin_lng'),
                        'origin_public_ip': ref_conn.get('origin_public_ip', ''),
                        'agent_color':     self._agent_colors.get(hostname, ref_conn.get('agent_color', 'orange')),
                        'hostname':        hostname,
                    })

            # Re-use the last stats / datetime text from the most recent full render
            stats_line = getattr(self, '_last_stats_line', '')
            datetime_text = getattr(self, '_last_datetime_text', '')
            force_tooltip = show_tooltip
            self.update_map(filtered, force_tooltip,
                            stats_text=stats_line, datetime_text=datetime_text,
                            skip_histogram=True)
        except Exception as e:
            logging.error(f"_update_map_with_filter error: {e}")

    def column_resort(self, index):
        """
        Handles sorting when a column header is clicked.

        Args:
            index (int): The column index that was clicked.
        """
        global table_column_sort_index
        global table_column_sort_reverse

        self.sort_table_by_column(index, table_column_sort_reverse)
        self._update_sort_indicator(self.connection_table, self._conn_table_base_headers,
                                    table_column_sort_index, table_column_sort_reverse)

    def sort_table_by_column(self, column_index, reverse=False):
        """
        Sort the connection_table robustly.

        - Snapshot every row as a list of (text, user_data) pairs.
        - When user_data (Qt.UserRole) is present on the sort column,
          use it as the numeric key (used by Sent / Recv byte columns).
        - Otherwise detect numeric values for numeric sort (ints/floats).
        - Fall back to case-insensitive string comparison.
        - Uses a (type_rank, value) tuple key so that numeric and string
          values never compare against each other (avoids Python 3 TypeError).
        - Empty cells always sort to the end regardless of direction.
        - Rebuild the table from the sorted snapshot (stable).
        """
        # collect snapshot of all rows
        rows = []
        row_count = self.connection_table.rowCount()
        col_count = self.connection_table.columnCount()

        for r in range(row_count):
            row_cells = []  # list of (text, user_data_or_None)
            for c in range(col_count):
                item = self.connection_table.item(r, c)
                text = item.text() if item is not None else ""
                ud = item.data(Qt.UserRole) if item is not None else None
                row_cells.append((text, ud))
            # determine key from the sort column
            text, ud = row_cells[column_index] if column_index < len(row_cells) else ("", None)
            if text == "" and ud is None:
                sort_key = (2, "")
            elif ud is not None:
                # Qt.UserRole carries a raw numeric value (e.g. byte counts)
                try:
                    sort_key = (0, int(ud))
                except (TypeError, ValueError):
                    sort_key = (1, str(ud).lower())
            else:
                try:
                    if text.isdigit():
                        sort_key = (0, int(text))
                    else:
                        normalized = text.replace(",", "")
                        sort_key = (0, float(normalized))
                except Exception:
                    sort_key = (1, text.lower())
            rows.append((sort_key, row_cells))

        # stable sort — empty cells always sort to the end
        rows.sort(key=lambda x: x[0], reverse=reverse)
        if reverse:
            # When reversed, empties (rank 2) would move to the front; push them back
            empties = [r for r in rows if r[0][0] == 2]
            non_empties = [r for r in rows if r[0][0] != 2]
            rows = non_empties + empties

        # repopulate table from sorted snapshot
        self.connection_table.setUpdatesEnabled(False)
        self.connection_table.setRowCount(0)
        for _, row_cells in rows:
            new_row = self.connection_table.rowCount()
            self.connection_table.insertRow(new_row)
            for c, (text, ud) in enumerate(row_cells):
                item = QTableWidgetItem(text)
                if ud is not None:
                    item.setData(Qt.UserRole, ud)
                self.connection_table.setItem(new_row, c, item)
        self.connection_table.setUpdatesEnabled(True)

    @Slot(int)
    def on_summary_header_clicked(self, index):
        """
        Handles sorting when a summary table column header is clicked.

        Args:
            index (int): The column index that was clicked.
        """
        global summary_table_column_sort_index
        global summary_table_column_sort_reverse

        if summary_table_column_sort_index == index:
            summary_table_column_sort_reverse = not summary_table_column_sort_reverse

        summary_table_column_sort_index = index

        self.sort_summary_table_by_column(index, summary_table_column_sort_reverse)
        self._update_sort_indicator(self.summary_table, self._summary_table_base_headers,
                                    summary_table_column_sort_index, summary_table_column_sort_reverse)

    def sort_summary_table_by_column(self, column_index, reverse=False):
        """
        Sort the summary_table robustly.

        - Snapshot every row as a list of (text, user_data, color) tuples.
        - When user_data (Qt.UserRole) is present on the sort column,
          use it as the numeric key (used by Sent / Recv byte columns).
        - Otherwise detect numeric values for numeric sort (ints/floats).
        - Fall back to case-insensitive string comparison.
        - Uses a (type_rank, value) tuple key so that numeric and string
          values never compare against each other (avoids Python 3 TypeError).
        - Empty cells always sort to the end regardless of direction.
        - Rebuild the table from the sorted snapshot (stable).
        - Preserve red highlighting for suspect connections.
        """
        # collect snapshot of all rows with their formatting
        rows = []
        row_count = self.summary_table.rowCount()
        col_count = self.summary_table.columnCount()

        for r in range(row_count):
            row_cells = []  # list of (text, user_data_or_None, color)
            for c in range(col_count):
                item = self.summary_table.item(r, c)
                text = item.text() if item is not None else ""
                ud = item.data(Qt.UserRole) if item is not None else None
                color = item.foreground() if item is not None else None
                row_cells.append((text, ud, color))

            # determine key from the sort column
            text, ud, _color = row_cells[column_index] if column_index < len(row_cells) else ("", None, None)
            if text == "" and ud is None:
                sort_key = (2, "")
            elif ud is not None:
                try:
                    sort_key = (0, int(ud))
                except (TypeError, ValueError):
                    sort_key = (1, str(ud).lower())
            else:
                try:
                    if text.isdigit():
                        sort_key = (0, int(text))
                    else:
                        normalized = text.replace(",", "")
                        sort_key = (0, float(normalized))
                except Exception:
                    sort_key = (1, text.lower())
            rows.append((sort_key, row_cells))

        # stable sort — empty cells always sort to the end
        rows.sort(key=lambda x: x[0], reverse=reverse)
        if reverse:
            # When reversed, empties (rank 2) would move to the front; push them back
            empties = [r for r in rows if r[0][0] == 2]
            non_empties = [r for r in rows if r[0][0] != 2]
            rows = non_empties + empties

        # repopulate table from sorted snapshot
        self.summary_table.setUpdatesEnabled(False)
        self.summary_table.setRowCount(0)
        for _, row_cells in rows:
            new_row = self.summary_table.rowCount()
            self.summary_table.insertRow(new_row)
            for c, (text, ud, color) in enumerate(row_cells):
                item = QTableWidgetItem(text)
                if ud is not None:
                    item.setData(Qt.UserRole, ud)
                if color is not None:
                    item.setForeground(color)
                self.summary_table.setItem(new_row, c, item)
        self.summary_table.setUpdatesEnabled(True)

     # Update connection list when slider changes
    @Slot(int)
    def update_slider_value(self, value):

        # Update your connection list 
        self.slider.setMaximum(self.connection_list_counter)

        self.timer.stop()

        if value >= self.connection_list_counter:
            value = self.connection_list_counter
        
        self.slider_value_label.setText(TIME_SLIDER_TEXT + str(value) + "/" + str(len(self.connection_list) ))
        self.refresh_connections(slider_position=value)
        if not self.timer_replay_connections.isActive():
            self.start_capture_btn.setVisible(True)
            self.stop_capture_btn.setVisible(False)
            self.toggle_button.setVisible(True)
            # Stop wave animation when capture stops
            self._stop_stop_button_wave()
            # Start flashing to indicate ready to start
            self._start_capture_button_flash()

        if self.connection_list: 
           idx = min(value, len(self.connection_list) - 1)
           self.slider.setToolTip(f"Map time: {self.connection_list[idx]['datetime']}") 
        else: 
            self.slider.setToolTip("")

    @Slot()
    def update_resolve_public_ip(self):
        global do_resolve_public_ip

        new_state = self.resolve_public_ip.isChecked()
        if new_state == True:
            do_resolve_public_ip = True
        else:
            do_resolve_public_ip = False
        self.save_settings()

    @Slot()
    def update_pulse_exit_points(self):
        global do_pulse_exit_points

        do_pulse_exit_points = self.pulse_exit_points_check.isChecked()
        self.save_settings()

    @Slot()
    def update_show_traffic_histogram(self):
        global do_show_traffic_histogram

        do_show_traffic_histogram = self.show_traffic_histogram_check.isChecked()
        self.save_settings()

    @Slot()
    def update_capture_screenshots(self):
        global do_capture_screenshots

        new_state = self.capture_screenshots_check.isChecked()
        if new_state == True:
            do_capture_screenshots = True
            # Ensure screenshot directory exists
            try:
                os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
                logging.info(f"Screenshot capture enabled. Files will be saved to: {SCREENSHOTS_DIR}")
            except Exception as e:
                logging.error(f"Failed to create screenshot directory: {e}")
                QMessageBox.warning(self, "Screenshot Error", f"Failed to create screenshot directory: {e}")
        else:
            do_capture_screenshots = False
        self.save_settings()

    # ------------------------------------------------------------------ #
    # Database persistence layer helpers
    # ------------------------------------------------------------------ #
    def _activate_db_provider(self, provider_name: str) -> bool:
        """Instantiate and connect the chosen database provider.

        Returns True on success, False on failure (logs a warning and
        leaves ``self._db_provider`` as None so the app keeps running).
        """
        self._deactivate_db_provider()
        if not provider_name or provider_name == "Disabled":
            return True  # nothing to activate
        try:
            from db_providers import create_provider
            prov = create_provider(provider_name)
            if prov is None:
                logging.warning(f"Database provider '{provider_name}' is not available.")
                return False
            # Ensure the connection_databases subfolder exists
            os.makedirs(CONNECTION_DATABASES_DIR, exist_ok=True)
            # For file-based providers (e.g. SQLite) store inside the subfolder
            db_path = os.path.join(CONNECTION_DATABASES_DIR, "connection_history.db")
            prov.connect(db_path=db_path)
            self._db_provider = prov
            logging.info(f"Database provider '{provider_name}' connected.")
            # Pre-load historical snapshots into the in-memory timeline
            self._restore_snapshots_from_db()
            # Start the background worker thread for non-blocking DB writes
            self._db_stop.clear()
            self._db_queue = queue.Queue()
            self._db_thread = threading.Thread(
                target=self._db_worker, daemon=True, name="DbWorker")
            self._db_thread.start()
            return True
        except Exception as e:
            logging.error(f"Failed to activate database provider '{provider_name}': {e}")
            self._db_provider = None
            return False

    def _deactivate_db_provider(self) -> None:
        """Cleanly shut down the current database provider (if any)."""
        # Signal the worker thread to stop and wait for it to drain
        if self._db_thread is not None and self._db_thread.is_alive():
            self._db_stop.set()
            self._db_thread.join(timeout=5)
            self._db_thread = None
        self._db_queue = None
        if self._db_provider is not None:
            try:
                self._db_provider.close()
            except Exception:
                pass
            self._db_provider = None

    def _restore_snapshots_from_db(self) -> None:
        """Load saved snapshots from the database into ``self.connection_list``
        up to ``max_connection_list_filo_buffer_size`` so the slider can
        replay them immediately.

        When ``--force_complete_database_load`` is active the limit is
        temporarily raised to ``max_connection_list_database_size`` and the
        deque is resized accordingly so the full database history can be
        browsed with the time slider.
        """
        if self._db_provider is None:
            return
        try:
            # Determine effective load limit
            if force_complete_database_load:
                effective_limit = max_connection_list_database_size
                logging.info(
                    f"--force_complete_database_load: loading up to "
                    f"{effective_limit} snapshots from database.")
            else:
                effective_limit = max_connection_list_filo_buffer_size

            snapshots = self._db_provider.load_snapshots(effective_limit)
            if not snapshots:
                return
            logging.info(f"Restoring {len(snapshots)} snapshots from database.")
            # Reset the deque with the (possibly enlarged) maxlen
            self.connection_list = deque(snapshots, maxlen=effective_limit)
            self.connection_list_counter = len(self.connection_list)

            # Discover agents stored in the database so they appear in the
            # Agent Management pane even when the DB was captured on another
            # machine or agents are no longer posting live data.
            for snap in snapshots:
                agent_data = snap.get('agent_data')
                if not agent_data or not isinstance(agent_data, dict):
                    continue
                for hostname in agent_data.keys():
                    if hostname and hostname not in self._agent_colors:
                        palette = self._AGENT_COLOR_PALETTE
                        self._agent_colors[hostname] = palette[
                            self._agent_color_index % len(palette)]
                        self._agent_color_index += 1
                        logging.info(
                            f"Discovered agent '{hostname}' from database history.")

            # Sync slider (block signals to avoid triggering update_slider_value
            # which would stop the capture timer and flip button state)
            if hasattr(self, 'slider'):
                total = len(self.connection_list)
                self.slider.blockSignals(True)
                self.slider.setMaximum(self.connection_list_counter)
                # Point the slider at the last snapshot so the user immediately
                # sees the most-recent state and can scrub backwards from there.
                self.slider.setValue(self.connection_list_counter)
                self.slider.blockSignals(False)
                self.slider_value_label.setText(
                    TIME_SLIDER_TEXT + str(self.slider.value()) + "/" + str(total))

            if force_complete_database_load:
                # Update the window title so it is obvious the app is in
                # database-replay mode and is not collecting live traffic.
                self.setWindowTitle(
                    f"TCP/UDP Geo Map - R001D00rs - v {VERSION}  "
                    f"[Database Replay — {len(self.connection_list)} snapshots loaded]")
        except Exception as e:
            logging.error(f"Error restoring snapshots from database: {e}")

    def _db_save_snapshot(self, timestamp, connections, agent_data) -> None:
        """Enqueue a snapshot for the background DB worker thread.

        Called at the end of each connection cycle.  The connections list
        is deep-copied so the worker thread owns its own data and the
        UI thread is never blocked by database I/O.
        """
        if self._db_queue is None:
            return
        try:
            import copy
            self._db_queue.put_nowait(
                (timestamp, copy.deepcopy(connections), agent_data))
        except Exception as e:
            logging.error(f"Database snapshot enqueue error: {e}")

    def _db_worker(self) -> None:
        """Background thread that drains ``_db_queue`` and writes to the
        database provider.  Runs until ``_db_stop`` is set **and** the
        queue is empty, ensuring no snapshots are lost on shutdown."""
        while not self._db_stop.is_set():
            try:
                item = self._db_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self._db_process_item(item)
        # Drain remaining items before exiting
        while not self._db_queue.empty():
            try:
                item = self._db_queue.get_nowait()
            except queue.Empty:
                break
            self._db_process_item(item)
        logging.info("Database worker thread stopped.")

    def _db_process_item(self, item) -> None:
        """Process a single queued snapshot write + purge."""
        timestamp, connections, agent_data = item
        try:
            self._db_provider.save_snapshot(timestamp, connections, agent_data)
            self._db_provider.purge_oldest(max_connection_list_database_size)
        except Exception as e:
            logging.error(f"Database snapshot save error: {e}")

    @Slot(str)
    def _set_db_combo_by_name(self, name: str) -> None:
        """Select the combo item whose user data matches *name* (the real provider key)."""
        for i in range(self.db_provider_combo.count()):
            if self.db_provider_combo.itemData(i) == name:
                self.db_provider_combo.setCurrentIndex(i)
                return
        # Fallback: if not found (e.g. provider removed), select Disabled
        self.db_provider_combo.setCurrentIndex(0)

    def _on_db_provider_changed(self, text: str) -> None:
        global db_provider_name
        # Resolve the real provider key from the item's user data
        provider_key = self.db_provider_combo.currentData() or text
        if provider_key == db_provider_name:
            return
        if provider_key == "Disabled":
            self._deactivate_db_provider()
            db_provider_name = "Disabled"
            self.save_settings()
            logging.info("Database persistence disabled.")
            return
        ok = self._activate_db_provider(provider_key)
        if ok:
            db_provider_name = provider_key
            self.save_settings()
        else:
            QMessageBox.warning(
                self, "Database Error",
                f"Could not connect to the '{provider_key}' provider.\n"
                "Check logs for details. Reverting to Disabled."
            )
            self.db_provider_combo.blockSignals(True)
            self._set_db_combo_by_name(db_provider_name)
            self.db_provider_combo.blockSignals(False)

    @Slot()
    def _on_db_buffer_size_changed(self) -> None:
        global max_connection_list_database_size
        try:
            val = int(self.db_buffer_size_input.text().strip())
            if val <= 0:
                raise ValueError("Must be positive")
            max_connection_list_database_size = val
            self.save_settings()
            logging.info(f"Database max snapshot size set to {val}")
        except (ValueError, TypeError):
            self.db_buffer_size_input.setText(str(max_connection_list_database_size))

    @Slot()
    def update_buffer_size(self):
        """Validate and update the max_connection_list_filo_buffer_size setting"""
        global max_connection_list_filo_buffer_size

        # Store the previous valid value
        previous_value = max_connection_list_filo_buffer_size

        try:
            # Get the text from the input field
            new_value_text = self.buffer_size_input.text().strip()

            # Try to convert to integer
            new_value = int(new_value_text)

            # Validate that it's a positive number
            if new_value <= 0:
                raise ValueError("Buffer size must be greater than 0")

            # Valid value - update the global
            max_connection_list_filo_buffer_size = new_value
            logging.info(f"Updated max_connection_list_filo_buffer_size to {new_value}")

            # Check if capture was running before reset
            was_running = False
            if hasattr(self, 'timer') and self.timer.isActive():
                was_running = True
                self.timer.stop()
                logging.debug("Stopped capture timer before reset")

            # Stop replay timer if active
            if hasattr(self, 'timer_replay_connections') and self.timer_replay_connections.isActive():
                self.timer_replay_connections.stop()
                logging.debug("Stopped replay timer before reset")

            # Always reset connections when buffer size changes
            logging.info("Resetting connections due to buffer size change")

            # Clear connection data — recreate deque with updated maxlen
            if hasattr(self, 'connection_list'):
                self.connection_list = deque(maxlen=max_connection_list_filo_buffer_size)
            if hasattr(self, 'connections'):
                self.connections = []

            self.connection_list_counter = 0

            # Update slider
            if hasattr(self, 'slider'):
                self.slider.setMaximum(self.connection_list_counter)
                self.slider_value_label.setText(TIME_SLIDER_TEXT + str(self.slider.value()) + "/" + str(len(self.connection_list)))

            # Clear map
            if hasattr(self, 'connections'):
                self.update_map(self.connections)

            # Update UI buttons
            if hasattr(self, 'start_capture_btn'):
                self.start_capture_btn.setVisible(True)
                # Start flashing to indicate ready to start
                self._start_capture_button_flash()
            if hasattr(self, 'stop_capture_btn'):
                self.stop_capture_btn.setVisible(False)
                # Stop wave animation
                self._stop_stop_button_wave()

            # Trigger screenshot cleanup if enabled (to match new buffer size)
            global do_capture_screenshots
            if do_capture_screenshots:
                try:
                    logging.info("Triggering screenshot cleanup after buffer size change")
                    self._cleanup_old_screenshots()
                except Exception as e:
                    logging.error(f"Failed to cleanup screenshots after buffer resize: {e}")

            # Restart capture if it was running before
            if was_running:
                logging.info("Restarting capture after buffer size change")
                if hasattr(self, 'timer'):
                    self.timer.start(map_refresh_interval)
                    if hasattr(self, 'start_capture_btn'):
                        self.start_capture_btn.setVisible(False)
                        # Stop flashing when capture resumes
                        self._stop_capture_button_flash()
                    if hasattr(self, 'stop_capture_btn'):
                        self.stop_capture_btn.setVisible(True)
                        # Start wave animation when capture resumes
                        self._start_stop_button_wave()
                    self.save_settings()

        except ValueError as e:
            # Invalid input - show error and revert
            QMessageBox.warning(
                self,
                "Invalid Buffer Size",
                f"Invalid value: '{new_value_text}'\n\n"
                f"The buffer size must be a positive integer greater than 0.\n\n"
                f"Reverting to previous value: {previous_value}"
            )

            # Revert to previous value
            max_connection_list_filo_buffer_size = previous_value
            self.buffer_size_input.setText(str(previous_value))
            logging.warning(f"Invalid buffer size input '{new_value_text}', reverted to {previous_value}")

        except Exception as e:
            # Unexpected error - show error and revert
            QMessageBox.warning(
                self,
                "Buffer Size Error",
                f"Error updating buffer size: {str(e)}\n\n"
                f"Reverting to previous value: {previous_value}"
            )

            # Revert to previous value
            max_connection_list_filo_buffer_size = previous_value
            self.buffer_size_input.setText(str(previous_value))
            logging.error(f"Error updating buffer size: {e}, reverted to {previous_value}")



    @Slot()
    def update_reverse_dns(self):
        global do_reverse_dns

        new_state = self.reverse_dns_check.isChecked()
        if new_state == True:
            do_reverse_dns = True
            # Start the cleanup timer when reverse DNS is enabled
            try:
                if hasattr(self, 'public_ip_dns_cache_cleanup_timer'):
                    self.public_ip_dns_cache_cleanup_timer.start(PUBLIC_IP_ENQUEUE_TIMER_INTERVAL)
            except Exception:
                pass
        else:
            do_reverse_dns = False
            # Stop the cleanup timer when reverse DNS is disabled
            try:
                if hasattr(self, 'public_ip_dns_cache_cleanup_timer'):
                    self.public_ip_dns_cache_cleanup_timer.stop()
            except Exception:
                pass
        self.save_settings()

    @Slot()
    def update_c2_check(self):
        global do_c2_check

        new_state = self.c2_check.isChecked()
        if new_state == True:
            do_c2_check = True
        else:
            do_c2_check = False
            self.setStyleSheet("") # Reset any previous styles

        self.refresh_connections()
        self.save_settings()

    @Slot()
    def only_show_new_connections_changed(self):
        global show_only_new_active_connections

        new_state = self.only_show_new_connections.isChecked()
        if new_state == True:
            show_only_new_active_connections = True
        else:
            show_only_new_active_connections = False
            self.setStyleSheet("") # Reset any previous styles

        self.refresh_connections()
        self.save_settings()

    def _toggle_only_remote_connections(self):
        """Toggle the 'Hide local connections' filter and keep the Settings checkbox in sync."""
        global show_only_remote_connections
        show_only_remote_connections = not show_only_remote_connections
        self.only_show_remote_connections.setChecked(show_only_remote_connections)
        if not show_only_remote_connections:
            self.setStyleSheet("")  # Reset any previous styles
        self.refresh_connections()
        self.save_settings()

    @Slot()
    def only_show_remote_connections_changed(self):
        global show_only_remote_connections

        new_state = self.only_show_remote_connections.isChecked()
        if new_state == True:
            show_only_remote_connections = True
        else:
            show_only_remote_connections = False
            self.setStyleSheet("") # Reset any previous styles

        self.refresh_connections()
        self.save_settings()

    @Slot()
    def update_pause_table_sorrting(self):
        global do_pause_table_sorting
        do_pause_table_sorting = self.pause_table_sorting_check.isChecked()
        self.save_settings()

    @Slot()
    def update_show_listening_connections(self):
        global do_show_listening_connections
        do_show_listening_connections = self.show_listening_connections_check.isChecked()
        try:
            from plugins.os_conn_table import set_include_listening as _set_listening
            _set_listening(do_show_listening_connections)
        except Exception:
            pass
        self.refresh_connections()
        self.save_settings()

    @Slot()
    def update_collect_connections_asynchronously(self):
        global do_collect_connections_asynchronously
        do_collect_connections_asynchronously = self.collect_connections_async_check.isChecked()
        self.save_settings()

    @Slot()
    def update_show_traffic_gauge(self):
        global do_show_traffic_gauge
        do_show_traffic_gauge = self.show_traffic_gauge_check.isChecked()
        self.save_settings()

    @Slot()
    def update_refresh_interval(self):
        global map_refresh_interval

        selected_interval = int(self.refresh_interval_combo_box.currentText())
        map_refresh_interval = selected_interval
        self.timer.stop()
        self.timer.start(map_refresh_interval)
        self.save_settings()

    @Slot()
    def reset_connections(self):

        response = QMessageBox.question(
            self,
            "Reset Connections?",
            f"Are you sure you want to reset all connections?",
            QMessageBox.Yes | QMessageBox.No
        )
    
        if response == QMessageBox.Yes:

            if self.timer.isActive():
                self.timer.stop()
            if self.timer_replay_connections.isActive():    
                self.timer_replay_connections.stop()

            self.connection_list.clear()
            self.connections = []
            self.connection_list_counter = 0
            self.slider.setMaximum(self.connection_list_counter)
            self.slider_value_label.setText(TIME_SLIDER_TEXT + str(self.slider.value()) + "/" + str(len(self.connection_list)))
            self.update_map(self.connections)
            self.start_capture_btn.setVisible(True)
            self.stop_capture_btn.setVisible(False)
            # Stop wave animation when capture stops
            self._stop_stop_button_wave()
            # Start flashing to indicate ready to start
            self._start_capture_button_flash()

    @Slot()
    def save_connection_list_to_csv(self):
        """
        Saves the connection list for a specific timeline index into a CSV file.
        
        Parameters:
            self: The instance containing the connection data.
            timeline_index (int): The index of the timeline to save.
            filename (str, optional): Name of the output CSV file. If not provided,
                                    a default name is generated based on the timeline index.
        """
        try:
            if len(self.connection_list) == 0:
                return

            # Access the connection list for the specified timeline index
            connection_data = self.connection_list[0]['connection_list']
            timeline_time = self.connection_list[0]['datetime'].strftime('%Y-%m-%d-%H-%M-%S') 
            
            
            # Determine headers from the keys of the first item in the connection list
            headers = list(connection_data[0].keys())
            
            # Generate default filename if none is provided
            if not filename:
                filename = f"connection_list_at_{timeline_time}.csv"
            
            # Ensure the output directory exists
            output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)
            full_path = os.path.join(output_dir, filename)
            
            with open(full_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                
                # Write the header
                writer.writeheader()
                
                # Write each connection data row
                for item in connection_data:
                    writer.writerow(item)

            QMessageBox.information(
                self,
                "Save complete",
                f"Connection list for {timeline_time} saved to {full_path}"
            )
            
        except IndexError as e:
            QMessageBox.critical(self, "Save Error", f"Error: Invalid timeline index provided. {e}")
        except KeyError as e:
            QMessageBox.critical(self, "Save Error", f"Error: Missing key '{e}' in data structure.")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"An error occurred while saving the file: {e}")   
            
               
    def save_all_connection_list_to_csv(self, timeline_index=0, filename=None):
        """
        Save all recorded timelines into a single, simple CSV file.

        Format:
        - One connection per CSV row.
        - First column is the timeline datetime.
        - Remaining columns are connection fields (process, pid, suspect, local, localport,
          remote, remoteport, name, ip_type, lat, lng, icon).

        Note: the `timeline_index` parameter is ignored (kept for compatibility with UI).
        """

        try:
            if not self.connection_list:
                QMessageBox.information(self, "No data", "No timeline data available to save.")
                return

            # Ensure output directory exists
            output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)

            if not filename:
                filename = f"connection_timelines_{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.csv"

            full_path = os.path.join(output_dir, filename)

            # Fixed column order (datetime first)
            columns = [
                "datetime",
                "hostname",
                "process",
                "pid",
                "suspect",
                "local",
                "localport",
                "remote",
                "remoteport",
                "name",
                "ip_type",
                "lat",
                "lng",
                "icon"
            ]

            rows_written = 0
            with open(full_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=columns)
                writer.writeheader()

                for timeline in self.connection_list:
                    dt = timeline.get("datetime")
                    if isinstance(dt, datetime.datetime):
                        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        dt_str = str(dt)

                    for conn in timeline.get("connection_list", []):
                        row = {"datetime": dt_str}
                        if isinstance(conn, dict):
                            for col in columns:
                                if col == "datetime":
                                    continue
                                value = conn.get(col, "")
                                # Normalize None and complex objects
                                if value is None:
                                    row[col] = ""
                                elif isinstance(value, (str, int, float)):
                                    row[col] = value
                                else:
                                    # fallback to string representation for other types
                                    try:
                                        row[col] = str(value)
                                    except Exception:
                                        row[col] = ""
                        else:
                            # fallback if conn is not dict
                            for col in columns:
                                if col == "datetime":
                                    continue
                                row[col] = ""
                            row["process"] = str(conn)

                        writer.writerow(row)
                        rows_written += 1

            QMessageBox.information(self, "Save complete", f"Saved {rows_written} rows across {len(self.connection_list)} timelines to {full_path}")

        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"An error occurred while saving the file: {e}")


    @Slot(bool)
    def toggle_auto_refresh_replay_connections(self, enabled):
        if enabled:
            if self.timer_replay_connections.isActive():
                return  # Already running

            try:
                self.toggle_action.setIcon(self._toggle_stop_icon)
                self.toggle_action.setText("Replaying connections")
            except Exception:
                pass

            # Start refresh timer or process here
            self.timer_replay_connections.start(map_refresh_interval)

            self.start_capture_btn.setText(" ")
            self.start_capture_btn.setIcon(self._toggle_play_icon)
            self.start_capture_btn.setEnabled(False)
            self.stop_capture_btn.setVisible(False)
            # Stop wave animation when replay starts
            self._stop_stop_button_wave()
            # Stop flashing when replay starts
            self._stop_capture_button_flash()

        else:
            try:
                self.toggle_action.setIcon(self._toggle_play_icon)
                self.toggle_action.setText("Replay connections")
            except Exception:
                pass

            # Stop refresh timer or process here
            self.timer_replay_connections.stop()
            self.start_capture_btn.setText(START_CAPTURE_BUTTON_TEXT)
            self.start_capture_btn.setIcon(QIcon())
            self.start_capture_btn.setEnabled(True)
            self.stop_capture_btn.setVisible(False)
            # Stop wave animation when replay stops
            self._stop_stop_button_wave()
            # Start flashing to indicate ready to start
            self._start_capture_button_flash()

    def init_ui(self):
        self.connection_list = deque(maxlen=max_connection_list_filo_buffer_size)
        self.connection_list_counter = 0

        # Use a horizontal splitter so the user can resize left/right panels with the mouse
        self.splitter = QSplitter(Qt.Horizontal)

        # Main layout
        main_layout = QHBoxLayout()
        self.timer = QTimer(self)
        self.timer_replay_connections = QTimer(self)

        # Left panel for connection list
        self.left_panel = QGroupBox("Active TCP/UDP Connections")
        self.left_layout = QVBoxLayout()

        # Right panel for map
        self.right_panel = QGroupBox("Network Connections Map (TCP/UDP)")
        self.right_layout = QVBoxLayout()

        self.slider = QSlider(Qt.Horizontal)
        self.slider_value_label = QLabel(TIME_SLIDER_TEXT)
        
        # Save Button
        self.save_connections_btn = QPushButton("Save connection list to CSV file")
        self.save_connections_btn.clicked.connect(self.save_all_connection_list_to_csv)

        self.save_connections_btn.setVisible(True)

        # Get play and stop icons from Qt's standard icons
        style = self.style()
        play_icon = style.standardIcon(QStyle.StandardPixmap.SP_MediaPlay)
        stop_icon = style.standardIcon(QStyle.StandardPixmap.SP_MediaStop)
        self._toggle_play_icon = play_icon
        self._toggle_stop_icon = stop_icon

        # Refresh button with play icon
        self.start_capture_btn = QToolButton()
        self.start_capture_btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.start_capture_btn.setIcon(play_icon)
        self.start_capture_btn.setText(START_CAPTURE_BUTTON_TEXT)
        self.start_capture_btn.clicked.connect(self.refresh_connections)
        self.start_capture_btn.setVisible(False)

        # Stop button with stop icon
        self.stop_capture_btn = QToolButton()
        self.stop_capture_btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.stop_capture_btn.setIcon(stop_icon)
        self.stop_capture_btn.setText(STOP_CAPTURE_BUTTON_TEXT)
        self.stop_capture_btn.clicked.connect(self.stop_capture_connections)
        self.stop_capture_btn.setVisible(True)
        # Use monospace font to prevent text shifting during wave animation (all chars same width)
        
        # Connection table
        self.connection_table = QTableWidget(0, BYTES_RECV_ROW_INDEX+1)
        self._conn_table_base_headers = [
            "Hostname", "Process", "PID", "C2", "Protocol", "Local Addr", "Local Port", "Remote Addr", "Remote Port", "Name", "IP Type", "Way", "Loc lat", "Loc lon", "Sent", "Recv"
        ]
        self.connection_table.setHorizontalHeaderLabels(self._conn_table_base_headers)

        # Connect the header clicked signal to a custom sort function
        self.connection_table.horizontalHeader().sectionClicked.connect(self.on_header_clicked)
        self.connection_table.setMinimumSize(CONNECTION_TABLE_MIN_WIDTH, CONNECTION_TABLE_MIN_HEIGHT)
        self.connection_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.connection_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.connection_table.cellClicked.connect(self._on_table_cell_clicked_deferred)
        self.connection_table.cellDoubleClicked.connect(self.on_table_cell_double_clicked)
        self.connection_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.connection_table.customContextMenuRequested.connect(self.on_connection_table_context_menu)

        # Ensure header is interactive and enforce a minimum width for the "C2" column (index = SUSPECT_ROW_INDEX)
        self.connection_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        self.connection_table.setColumnWidth(PID_ROW_INDEX, PID_COLUMN_SIZE)
        self.connection_table.setColumnWidth(SUSPECT_ROW_INDEX, SUSPECT_COLUMN_SIZE)
        self.connection_table.setColumnWidth(PROTOCOL_ROW_INDEX, PROTOCOL_COLUMN_SIZE)
        self.connection_table.setColumnWidth(LOCAL_PORT_ROW_INDEX, PORTS_COLUMN_SIZE)
        self.connection_table.setColumnWidth(REMOTE_PORT_ROW_INDEX, PORTS_COLUMN_SIZE)
        self.connection_table.setColumnWidth(IP_TYPE_ROW_INDEX, IP_TYPE_COLUMN_SIZE)
        self.connection_table.setColumnWidth(WAY_ROW_INDEX, 40)

        self.connection_table.horizontalHeader().setMinimumSectionSize(SUSPECT_COLUMN_SIZE)

        # Per-column filter bar — one QLineEdit per column, scrolls in sync with the table
        _filter_placeholders = [
            "Hostname", "Process", "PID", "C2", "Protocol", "Local Addr", "Local Port",
            "Remote Addr", "Remote Port", "Name", "IP Type", "Way", "Lat", "Lon", "Sent", "Recv"
        ]
        self._connection_filter_inner = QWidget()
        _filter_inner_layout = QHBoxLayout(self._connection_filter_inner)
        _filter_inner_layout.setContentsMargins(0, 0, 0, 0)
        _filter_inner_layout.setSpacing(0)
        self._connection_filter_vheader_spacer = QWidget()
        _filter_inner_layout.addWidget(self._connection_filter_vheader_spacer)
        self._connection_filter_inputs = []
        for placeholder in _filter_placeholders:
            le = QLineEdit()
            le.setPlaceholderText(placeholder)
            le.setClearButtonEnabled(True)
            le.setFixedHeight(24)
            le.textChanged.connect(self.apply_connection_table_filter)
            self._connection_filter_inputs.append(le)
            _filter_inner_layout.addWidget(le)
        self._connection_filter_scroll = QScrollArea()
        self._connection_filter_scroll.setWidget(self._connection_filter_inner)
        self._connection_filter_scroll.setWidgetResizable(False)
        self._connection_filter_scroll.setFixedHeight(28)
        self._connection_filter_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._connection_filter_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._connection_filter_scroll.setFrameShape(QFrame.NoFrame)
        self.connection_table.horizontalScrollBar().valueChanged.connect(
            self._connection_filter_scroll.horizontalScrollBar().setValue)
        self.connection_table.horizontalHeader().sectionResized.connect(
            lambda *_: self._sync_filter_widths())
        self.connection_table.horizontalHeader().sectionResized.connect(
            lambda *_: self._debounced_save_column_widths())
        self.connection_table.horizontalHeader().setSectionsMovable(True)
        self.connection_table.horizontalHeader().sectionMoved.connect(
            self._on_conn_table_section_moved)

        self.left_layout.addWidget(self._connection_filter_scroll)
        self.left_layout.addWidget(self.connection_table)
        
        # Respect minimum sizes and set sensible initial sizes for the splitter children
        self.left_panel.setMinimumWidth(CONNECTION_TABLE_MIN_WIDTH)
        self.right_panel.setMinimumWidth(MAP_TABLE_MIN_WIDTH)
        self.splitter.setSizes([int(self.width() * 0.35), int(self.width() * 0.65)])  # initial ratio
        self.splitter.setHandleWidth(6)

        self.left_panel.setLayout(self.left_layout)

        self.splitter.addWidget(self.left_panel)
        self.splitter.addWidget(self.right_panel)
        
        # Map view
        self.map_view = QWebEngineView()
        self.map_view.setMinimumSize(MAP_TABLE_MIN_WIDTH, MAP_TABLE_MIN_HEIGHT)

        # Enable developer console logging (for debugging)
        try:
            from PySide6.QtWebEngineCore import QWebEnginePage

            class DebugPage(QWebEnginePage):
                def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
                    logging.debug(f"[JS Console] {message} (line {lineNumber} in {sourceID})")

            # Create debug page FIRST
            debug_page = DebugPage(self.map_view)

            # Set WebChannel on the debug page BEFORE setting it as the page
            debug_page.setWebChannel(self.channel)

            # Now assign the debug page to the view
            self.map_view.setPage(debug_page)
        except Exception as e:
            logging.warning(f"Could not enable console logging: {e}")
            # Fallback: set webchannel on default page if debug page creation fails
            try:
                self.map_view.page().setWebChannel(self.channel)
            except Exception:
                pass

        # Set initial loading HTML after page is configured
        self.map_view.setHtml("<html><body><h2>Loading map...</h2></body></html>")

        self.map_objects = 0
        self.map_initialized = False
        self._map_reload_attempts = 0  # Track reload attempts to prevent infinite loops
        self._map_loading_in_progress = False  # True while setHtml is in flight, prevents re-entry

        self.right_splitter = QSplitter(Qt.Vertical)
        self.right_splitter.setHandleWidth(6)

        # Controls container placed below the map in the vertical splitter
        self.controls_widget = QWidget()
        self.controls_layout = QVBoxLayout(self.controls_widget)
        self.controls_layout.setContentsMargins(0, 0, 0, 0)
        self.controls_layout.setSpacing(0)

        # Add control widgets to controls_layout (moved from right_layout)
        self.controls_layout.addWidget(self.start_capture_btn)
        self.controls_layout.addWidget(self.stop_capture_btn)

        # Create slider
        self.slider.setMinimum(0)
        self.slider.setMaximum(0)  # Adjust based on your needs
        self.slider.setValue(0)  # Default position   
        self.controls_layout.addWidget(self.slider)
        self.controls_layout.addWidget(self.slider_value_label)
        self.slider.valueChanged.connect(self.update_slider_value)

        # Add play/pause button
        self.toggle_button = QToolButton()
        self.toggle_button.setVisible(False)
        self.toggle_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle_action = QAction("Replay connections", self)
        self.toggle_action.setIcon(self._toggle_play_icon)
        self.toggle_action.setCheckable(True)
        self.toggle_action.toggled.connect(self.toggle_auto_refresh_replay_connections)
        self.toggle_button.setDefaultAction(self.toggle_action)
        # Fix toggle_button width so it doesn't jump when text changes
        _fm = QFontMetrics(self.toggle_button.font())
        _longest_text_w = _fm.horizontalAdvance("Replaying connections")
        _icon_and_padding = self.toggle_button.iconSize().width() + 24
        self.toggle_button.setMinimumWidth(_longest_text_w + _icon_and_padding)
        self.controls_layout.addWidget(self.toggle_button)

        # Push all controls to the top; absorb remaining vertical space at the bottom
        self.controls_layout.addStretch(1)

        # Generate video button
        self.generate_video_btn = QPushButton("Generate .mp4 video file")
        self.generate_video_btn.clicked.connect(self.generate_video_from_screenshots)
        self.generate_video_btn.setVisible(False)  # Hidden by default, shown when screenshots exist

        # Put map and controls into the vertical splitter (map on top, controls below)
        self.right_splitter.addWidget(self.map_view)
        self.right_splitter.addWidget(self.controls_widget)

        # Set minimal minimum heights - just enough to prevent complete overlap but allow user flexibility
        self.map_view.setMinimumHeight(100)
        self.controls_widget.setMinimumHeight(50)

        # Give the map more initial stretch so it's larger by default
        self.right_splitter.setStretchFactor(0, 8)
        self.right_splitter.setStretchFactor(1, 2)

        # Set initial 50/50 split for the vertical splitter (only on first launch)
        initial_height = 800  # Use initial window height
        self.right_splitter.setSizes([initial_height // 2, initial_height // 2])

        # Allow collapsing for user flexibility (they can minimize the controls if desired)
        self.right_splitter.setCollapsible(0, False)  # Map cannot collapse completely
        self.right_splitter.setCollapsible(1, True)   # Controls can be minimized by user

        # Finally, add the vertical splitter to the right panel layout
        self.right_layout.addWidget(self.right_splitter)

        self.right_panel.setLayout(self.right_layout)    

        # Add panels to main layout
        main_layout.addWidget(self.left_panel, 1)
        main_layout.addWidget(self.right_panel, 2)

        # Create Main tab widget that holds the existing splitter-based UI
        main_tab_widget = QWidget()
        main_tab_layout = QHBoxLayout(main_tab_widget)
        main_tab_layout.setContentsMargins(0, 0, 0, 0)
        main_tab_layout.addWidget(self.splitter)

        # Create Summary tab with aggregated connection statistics
        summary_tab_widget = QWidget()
        summary_tab_layout = QVBoxLayout(summary_tab_widget)
        summary_tab_layout.setContentsMargins(10, 10, 10, 10)
        summary_tab_layout.setSpacing(10)

        # Add title label
        summary_title_label = QLabel("Connection Summary Statistics")
        summary_title_label.setStyleSheet("font-size: 14pt; font-weight: bold;")
        summary_tab_layout.addWidget(summary_title_label)

        # Create summary table with 12 columns
        self.summary_table = QTableWidget(0, 13)
        self._summary_table_base_headers = [
            "Hostname", "Process", "PID", "C2", "Protocol", "Local Address", "Remote Address", "Type", "Way", "Name", "Count", "Sent", "Recv"
        ]
        self.summary_table.setHorizontalHeaderLabels(self._summary_table_base_headers)
        self.summary_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.summary_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.summary_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.summary_table.setMinimumHeight(400)

        # Connect the header clicked signal to the summary table sort function
        self.summary_table.horizontalHeader().sectionClicked.connect(self.on_summary_header_clicked)
        self.summary_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.summary_table.customContextMenuRequested.connect(self.on_summary_table_context_menu)

        # Per-column filter bar — one QLineEdit per column, scrolls in sync with the table
        _summary_filter_placeholders = [
            "Hostname", "Process", "PID", "C2", "Protocol", "Local Address", "Remote Address", "Type", "Way", "Name", "Count", "Sent", "Recv"
        ]
        self._summary_filter_inner = QWidget()
        _summary_filter_inner_layout = QHBoxLayout(self._summary_filter_inner)
        _summary_filter_inner_layout.setContentsMargins(0, 0, 0, 0)
        _summary_filter_inner_layout.setSpacing(0)
        self._summary_filter_vheader_spacer = QWidget()
        _summary_filter_inner_layout.addWidget(self._summary_filter_vheader_spacer)
        self._summary_filter_inputs = []
        for placeholder in _summary_filter_placeholders:
            le = QLineEdit()
            le.setPlaceholderText(placeholder)
            le.setClearButtonEnabled(True)
            le.setFixedHeight(24)
            le.textChanged.connect(self.apply_summary_table_filter)
            self._summary_filter_inputs.append(le)
            _summary_filter_inner_layout.addWidget(le)
        self._summary_filter_scroll = QScrollArea()
        self._summary_filter_scroll.setWidget(self._summary_filter_inner)
        self._summary_filter_scroll.setWidgetResizable(False)
        self._summary_filter_scroll.setFixedHeight(28)
        self._summary_filter_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._summary_filter_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._summary_filter_scroll.setFrameShape(QFrame.NoFrame)
        self.summary_table.horizontalScrollBar().valueChanged.connect(
            self._summary_filter_scroll.horizontalScrollBar().setValue)
        self.summary_table.horizontalHeader().sectionResized.connect(
            lambda *_: self._sync_summary_filter_widths())
        self.summary_table.horizontalHeader().sectionResized.connect(
            lambda *_: self._debounced_save_column_widths())
        self.summary_table.horizontalHeader().setSectionsMovable(True)
        self.summary_table.horizontalHeader().sectionMoved.connect(
            self._on_summary_table_section_moved)

        # Wrap filter bar + table in a zero-spacing container so inputs sit flush against the header
        _summary_table_container = QWidget()
        _summary_table_container_layout = QVBoxLayout(_summary_table_container)
        _summary_table_container_layout.setContentsMargins(0, 0, 0, 0)
        _summary_table_container_layout.setSpacing(0)
        _summary_table_container_layout.addWidget(self._summary_filter_scroll)
        _summary_table_container_layout.addWidget(self.summary_table)
        summary_tab_layout.addWidget(_summary_table_container)

        # Create Settings tab with all checkboxes
        settings_tab_widget = QWidget()
        settings_tab_layout = QVBoxLayout(settings_tab_widget)
        settings_tab_layout.setContentsMargins(10, 10, 10, 10)
        settings_tab_layout.setSpacing(10)

        # Add a title label
        settings_title_label = QLabel("Application Settings")
        settings_title_label.setStyleSheet("font-size: 14pt; font-weight: bold;")
        settings_tab_layout.addWidget(settings_title_label)

        # Map refresh interval selector
        refresh_interval_layout = QHBoxLayout()
        refresh_interval_label = QLabel("Map refresh interval (ms):")
        refresh_interval_label.setToolTip("How often the map and connection tables are refreshed")
        refresh_interval_layout.addWidget(refresh_interval_label)

        self.refresh_interval_combo_box = QComboBox()
        self.refresh_interval_combo_box.setToolTip("Select map refresh interval in milliseconds")
        self.refresh_interval_combo_box.addItems(["1000", "2000", "5000", "10000", "20000", "30000", "40000", "50000", "120000", "300000", "600000", "1200000", "180000000"])
        self.refresh_interval_combo_box.currentIndexChanged.connect(self.update_refresh_interval)
        refresh_interval_layout.addWidget(self.refresh_interval_combo_box)
        refresh_interval_layout.addStretch()
        settings_tab_layout.addLayout(refresh_interval_layout)

        # Reverse DNS checkbox
        self.reverse_dns_check = QCheckBox("Perform Reverse DNS Lookup on captured IPs")
        self.reverse_dns_check.setChecked(True)
        settings_tab_layout.addWidget(self.reverse_dns_check)    
        self.reverse_dns_check.stateChanged.connect(self.update_reverse_dns)

        # C2 Check checkbox
        self.c2_check = QCheckBox("Perform C2 checks against C2-TRACKER database")
        self.c2_check.setChecked(False)
        settings_tab_layout.addWidget(self.c2_check)    
        self.c2_check.stateChanged.connect(self.update_c2_check)
        self.c2_check.setChecked(True)

        # Only show new connections
        self.only_show_new_connections = QCheckBox("Only show new connections")
        self.only_show_new_connections.setChecked(False)
        settings_tab_layout.addWidget(self.only_show_new_connections)    
        self.only_show_new_connections.stateChanged.connect(self.only_show_new_connections_changed)

        # Hide remote local connections
        self.only_show_remote_connections = QCheckBox("Hide local connections and local network traffic on tables")
        self.only_show_remote_connections.setChecked(False)
        settings_tab_layout.addWidget(self.only_show_remote_connections)    
        self.only_show_remote_connections.stateChanged.connect(self.only_show_remote_connections_changed)

        # Show listening connections
        self.show_listening_connections_check = QCheckBox("Show listening sockets (LISTEN state)")
        self.show_listening_connections_check.setChecked(do_show_listening_connections)
        settings_tab_layout.addWidget(self.show_listening_connections_check)
        self.show_listening_connections_check.stateChanged.connect(self.update_show_listening_connections)

        # Resolve public IP using ipfy checkbox
        self.resolve_public_ip = QCheckBox("Resolve public internet IP using ipfy.com")
        self.resolve_public_ip.setChecked(False)
        settings_tab_layout.addWidget(self.resolve_public_ip)    
        self.resolve_public_ip.stateChanged.connect(self.update_resolve_public_ip)

        # Pulse exit points checkbox
        self.pulse_exit_points_check = QCheckBox("Pulse ipify.com exit points")
        self.pulse_exit_points_check.setChecked(do_pulse_exit_points)
        settings_tab_layout.addWidget(self.pulse_exit_points_check)
        self.pulse_exit_points_check.stateChanged.connect(self.update_pulse_exit_points)

        # Show traffic histogram on map checkbox
        self.show_traffic_histogram_check = QCheckBox("Show network traffic histogram on map")
        self.show_traffic_histogram_check.setChecked(do_show_traffic_histogram)
        settings_tab_layout.addWidget(self.show_traffic_histogram_check)
        self.show_traffic_histogram_check.stateChanged.connect(self.update_show_traffic_histogram)

        # Capture screenshots checkbox
        self.capture_screenshots_check = QCheckBox("Capture screenshots of the map to disk")
        self.capture_screenshots_check.setChecked(False)
        settings_tab_layout.addWidget(self.capture_screenshots_check)
        self.capture_screenshots_check.stateChanged.connect(self.update_capture_screenshots)

        # Max connection buffer size input
        buffer_size_layout = QHBoxLayout()
        buffer_size_label = QLabel("Maximum connection snapshots to keep in memory:")
        buffer_size_label.setToolTip("Controls how many historical connection snapshots are stored.\nAlso determines how many screenshot files to keep on disk.")
        buffer_size_layout.addWidget(buffer_size_label)

        self.buffer_size_input = QLineEdit()
        self.buffer_size_input.setText(str(max_connection_list_filo_buffer_size))
        self.buffer_size_input.setMaximumWidth(100)
        self.buffer_size_input.setToolTip("Enter a positive number greater than 0")
        self.buffer_size_input.editingFinished.connect(self.update_buffer_size)
        buffer_size_layout.addWidget(self.buffer_size_input)
        buffer_size_layout.addStretch()

        settings_tab_layout.addLayout(buffer_size_layout)

        # --- Database persistence layer ---
        db_section_label = QLabel("<b>Database Persistence</b>")
        settings_tab_layout.addWidget(db_section_label)

        db_provider_layout = QHBoxLayout()
        db_provider_label = QLabel("Connection history database:")
        db_provider_label.setToolTip(
            "When enabled, every connection snapshot is persisted to the selected\n"
            "database engine so history survives application restarts.\n"
            "Set to 'Disabled' to run without a database (default)."
        )
        db_provider_layout.addWidget(db_provider_label)

        self.db_provider_combo = QComboBox()
        # "Disabled" — no user data needed (display == key)
        self.db_provider_combo.addItem("Disabled", "Disabled")
        # Discover available providers from the db_providers package.
        # SQLite is always listed second (Recommended); remaining providers follow alphabetically.
        try:
            from db_providers import get_available_providers
            _providers = sorted(get_available_providers().keys())
            if "SQLite" in _providers:
                self.db_provider_combo.addItem("SQLite (Recommended)", "SQLite")
            for pname in _providers:
                if pname == "SQLite":
                    continue
                self.db_provider_combo.addItem(pname, pname)
        except Exception:
            pass  # package not importable — only "Disabled" shown
        self._set_db_combo_by_name(db_provider_name)
        self.db_provider_combo.currentTextChanged.connect(self._on_db_provider_changed)
        db_provider_layout.addWidget(self.db_provider_combo)
        db_provider_layout.addStretch()
        settings_tab_layout.addLayout(db_provider_layout)

        # Max database snapshot size
        db_size_layout = QHBoxLayout()
        db_size_label = QLabel("Maximum connection snapshots in database:")
        db_size_label.setToolTip(
            "Older snapshots beyond this limit are automatically deleted\n"
            "to prevent the database from growing indefinitely."
        )
        db_size_layout.addWidget(db_size_label)

        self.db_buffer_size_input = QLineEdit()
        self.db_buffer_size_input.setText(str(max_connection_list_database_size))
        self.db_buffer_size_input.setMaximumWidth(100)
        self.db_buffer_size_input.setToolTip("Enter a positive number greater than 0 (default: 100000)")
        self.db_buffer_size_input.editingFinished.connect(self._on_db_buffer_size_changed)
        db_size_layout.addWidget(self.db_buffer_size_input)
        db_size_layout.addStretch()
        settings_tab_layout.addLayout(db_size_layout)

        # Pause table sorting checkbox
        self.pause_table_sorting_check = QCheckBox("Pause main tab connection table sorting")
        self.pause_table_sorting_check.setChecked(False)
        self.pause_table_sorting_check.stateChanged.connect(self.update_pause_table_sorrting)
        settings_tab_layout.addWidget(self.pause_table_sorting_check)

        # Async connection collection checkbox
        self.collect_connections_async_check = QCheckBox("Collect connections asynchronously (prevents UI hangs during VPN switches etc.)")
        self.collect_connections_async_check.setChecked(do_collect_connections_asynchronously)
        self.collect_connections_async_check.stateChanged.connect(self.update_collect_connections_asynchronously)
        settings_tab_layout.addWidget(self.collect_connections_async_check)

        # Show traffic gauge on markers checkbox
        self.show_traffic_gauge_check = QCheckBox("Show traffic gauge on map markers (sent/recv — requires Scapy or PCAP collector)")
        self.show_traffic_gauge_check.setChecked(do_show_traffic_gauge)
        self.show_traffic_gauge_check.stateChanged.connect(self.update_show_traffic_gauge)
        settings_tab_layout.addWidget(self.show_traffic_gauge_check)

        # --- Connection Collector plugin selector ---
        collector_separator = QLabel("─── Connection Collector Plugin ───")
        collector_separator.setStyleSheet("font-weight: bold; color: #555; margin-top: 8px;")
        settings_tab_layout.addWidget(collector_separator)

        collector_row = QHBoxLayout()
        collector_label = QLabel("Active collector:")
        collector_row.addWidget(collector_label)
        self._collector_combo = QComboBox()
        for plugin in self._collector_plugins:
            display_name = f"{plugin.name} (Recommended)" if plugin.name == "Scapy Live Capture" else plugin.name
            self._collector_combo.addItem(display_name)
            idx = self._collector_combo.count() - 1
            self._collector_combo.setItemData(idx, plugin.name, Qt.UserRole)
            if plugin.description:
                self._collector_combo.setItemData(idx, plugin.description, Qt.ToolTipRole)
        self._collector_combo.currentIndexChanged.connect(self._on_collector_changed)
        collector_row.addWidget(self._collector_combo, 1)
        settings_tab_layout.addLayout(collector_row)

        # PCAP file path row — visible only when PcapCollector is active
        self._pcap_path_row = QWidget()
        pcap_path_layout = QHBoxLayout(self._pcap_path_row)
        pcap_path_layout.setContentsMargins(0, 0, 0, 0)
        pcap_path_layout.addWidget(QLabel("PCAP file:"))
        self._pcap_path_input = QLineEdit()
        self._pcap_path_input.setPlaceholderText("Path to .pcap / .pcapng file…")
        self._pcap_path_input.setText(getattr(self, '_pcap_file_path', ''))
        self._pcap_path_input.editingFinished.connect(self._on_pcap_path_changed)
        pcap_path_layout.addWidget(self._pcap_path_input, 1)
        pcap_browse_btn = QPushButton("Browse…")
        pcap_browse_btn.setFixedWidth(80)
        pcap_browse_btn.clicked.connect(self._on_pcap_browse)
        pcap_path_layout.addWidget(pcap_browse_btn)
        settings_tab_layout.addWidget(self._pcap_path_row)
        # Show/hide based on current active collector
        self._pcap_path_row.setVisible(self._active_collector.name == "PCAP File Collector")

        # Scapy forced interface name row — visible only when Scapy collector is active
        self._scapy_iface_row = QWidget()
        scapy_iface_layout = QHBoxLayout(self._scapy_iface_row)
        scapy_iface_layout.setContentsMargins(0, 0, 0, 0)
        scapy_iface_layout.addWidget(QLabel("Scapy interface:"))
        self._scapy_iface_combo = QComboBox()
        self._scapy_iface_combo.setToolTip(
            "Select the network interface Scapy will sniff on.\n"
            "'Auto-detect' sniffs on all available interfaces.\n"
            "If Scapy fails with an OSError about 'Network interface was not found',\n"
            "try selecting a specific interface from this list."
        )
        self._populate_scapy_iface_combo()
        self._scapy_iface_combo.currentIndexChanged.connect(self._on_scapy_iface_changed)
        scapy_iface_layout.addWidget(self._scapy_iface_combo, 1)
        # Refresh button to re-enumerate interfaces
        scapy_iface_refresh_btn = QPushButton("Refresh")
        scapy_iface_refresh_btn.setFixedWidth(70)
        scapy_iface_refresh_btn.setToolTip("Re-enumerate available network interfaces")
        scapy_iface_refresh_btn.clicked.connect(self._populate_scapy_iface_combo)
        scapy_iface_layout.addWidget(scapy_iface_refresh_btn)
        settings_tab_layout.addWidget(self._scapy_iface_row)
        self._scapy_iface_row.setVisible(self._active_collector.name == "Scapy Live Capture")

        # --- Server / Agent mode settings ---
        server_agent_separator = QLabel("─── Server / Agent Mode ───")
        server_agent_separator.setStyleSheet("font-weight: bold; color: #555; margin-top: 8px;")
        settings_tab_layout.addWidget(server_agent_separator)

        server_mode_layout = QHBoxLayout()
        self.server_mode_check = QCheckBox("Enable server mode (listen for agent connections)")
        self.server_mode_check.setChecked(enable_server_mode)
        self.server_mode_check.stateChanged.connect(self._on_server_mode_changed)
        server_mode_layout.addWidget(self.server_mode_check)
        server_mode_layout.addWidget(QLabel("Port:"))
        self.flask_server_port_input = QLineEdit()
        self.flask_server_port_input.setPlaceholderText("5000")
        self.flask_server_port_input.setText(str(FLASK_SERVER_PORT))
        self.flask_server_port_input.setFixedWidth(60)
        self.flask_server_port_input.setToolTip("High port (1024–65535)")
        self.flask_server_port_input.textChanged.connect(
            lambda t: self.flask_server_port_input.setStyleSheet(
                "" if (t.isdigit() and 1024 <= int(t) <= 65535) else "border: 1px solid red;"
            )
        )
        self.flask_server_port_input.editingFinished.connect(self._on_flask_server_port_changed)
        server_mode_layout.addWidget(self.flask_server_port_input)
        server_mode_layout.addStretch()
        settings_tab_layout.addLayout(server_mode_layout)

        agent_mode_layout = QHBoxLayout()
        self.agent_mode_check = QCheckBox("Enable agent mode:")
        self.agent_mode_check.setChecked(enable_agent_mode)
        self.agent_mode_check.stateChanged.connect(self._on_agent_mode_changed)
        agent_mode_layout.addWidget(self.agent_mode_check)

        # Hostname / IP of the server (no scheme, no port)
        self.agent_server_input = QLineEdit()
        self.agent_server_input.setPlaceholderText("Server hostname or IP (e.g. 192.168.1.10)")
        self.agent_server_input.setText(agent_server_host)
        self.agent_server_input.setMinimumWidth(220)
        self.agent_server_input.editingFinished.connect(self._on_agent_server_address_changed)
        agent_mode_layout.addWidget(self.agent_server_input)

        # Port the agent POSTs to on the remote server
        agent_mode_layout.addWidget(QLabel("Port:"))
        self.flask_agent_port_input = QLineEdit()
        self.flask_agent_port_input.setPlaceholderText("5000")
        self.flask_agent_port_input.setText(str(FLASK_AGENT_PORT))
        self.flask_agent_port_input.setFixedWidth(60)
        self.flask_agent_port_input.setToolTip("High port (1024–65535)")
        self.flask_agent_port_input.textChanged.connect(
            lambda t: self.flask_agent_port_input.setStyleSheet(
                "" if (t.isdigit() and 1024 <= int(t) <= 65535) else "border: 1px solid red;"
            )
        )
        self.flask_agent_port_input.editingFinished.connect(self._on_flask_agent_port_changed)
        agent_mode_layout.addWidget(self.flask_agent_port_input)

        # Connectivity status indicator — updated live by _trigger_agent_connectivity_check
        self.agent_conn_status_label = QLabel("")
        self.agent_conn_status_label.setMinimumWidth(120)
        agent_mode_layout.addWidget(self.agent_conn_status_label)

        agent_mode_layout.addStretch()
        settings_tab_layout.addLayout(agent_mode_layout)

        self.no_ui_check = QCheckBox(
            "No UI mode — run as a hidden background agent (takes effect on next launch)"
        )
        self.no_ui_check.setChecked(agent_no_ui)
        self.no_ui_check.setEnabled(enable_agent_mode)
        self.no_ui_check.setToolTip(
            "When checked and agent mode is active the application window is completely\n"
            "hidden on the next launch (no taskbar button, not restorable by the user).\n"
            "Equivalent to passing --no_ui on the command line."
        )
        self.no_ui_check.stateChanged.connect(self._on_no_ui_changed)
        settings_tab_layout.addWidget(self.no_ui_check)

        # Reset column order button
        self.reset_column_order_btn = QPushButton("Reset columns table order to default")
        self.reset_column_order_btn.setToolTip("Reset both the connection table and summary table columns to their default order")
        self.reset_column_order_btn.clicked.connect(self._reset_column_order)
        settings_tab_layout.addWidget(self.reset_column_order_btn)

        # Add stretch to push settings to the top
        settings_tab_layout.addStretch()

        # Actions tab
        actions_tab_widget = QWidget()
        actions_tab_layout = QVBoxLayout()
        actions_tab_widget.setLayout(actions_tab_layout)

        self.reset_connections_btn = QPushButton("Clear existing captured live connections")
        self.reset_connections_btn.clicked.connect(self.reset_connections)
        actions_tab_layout.addWidget(self.reset_connections_btn)

        self.save_connections_btn.clicked.connect(self.save_connection_list_to_csv)
        actions_tab_layout.addWidget(self.save_connections_btn)

        actions_tab_layout.addWidget(self.generate_video_btn)

        # Database status table
        db_group = QGroupBox("Databases")
        db_group_layout = QVBoxLayout()
        db_group.setLayout(db_group_layout)

        self.db_status_table = QTableWidget(0, 4)
        self.db_status_table.setHorizontalHeaderLabels(["Database", "Last Downloaded", "Expires", ""])
        self.db_status_table.horizontalHeader().setStretchLastSection(False)
        self.db_status_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.db_status_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.db_status_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.db_status_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.db_status_table.verticalHeader().setVisible(False)
        self.db_status_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.db_status_table.setSelectionMode(QTableWidget.NoSelection)
        self.db_status_table.setMinimumHeight(130)
        self.db_status_table.setSizeAdjustPolicy(QTableWidget.AdjustToContents)
        db_group_layout.addWidget(self.db_status_table)

        self.refresh_all_db_btn = QPushButton("Refresh All Databases")
        self.refresh_all_db_btn.clicked.connect(self._refresh_all_databases)
        db_group_layout.addWidget(self.refresh_all_db_btn)

        actions_tab_layout.addWidget(db_group)

        self._populate_db_status_table()

        actions_tab_layout.addStretch()

        # Create QTabWidget and add all tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(main_tab_widget, "Main")
        self.tab_widget.addTab(summary_tab_widget, "Summary")
        self.tab_widget.addTab(actions_tab_widget, "Actions")
        self.tab_widget.addTab(settings_tab_widget, "Settings")

        # --- Agent Management tab (only shown when server mode is active) ---
        agent_mgmt_tab_widget = QWidget()
        agent_mgmt_tab_layout = QVBoxLayout(agent_mgmt_tab_widget)
        agent_mgmt_tab_layout.setContentsMargins(10, 10, 10, 10)
        agent_mgmt_tab_layout.setSpacing(10)

        agent_mgmt_title = QLabel("Agent Management")
        agent_mgmt_title.setStyleSheet("font-size: 14pt; font-weight: bold;")
        agent_mgmt_tab_layout.addWidget(agent_mgmt_title)

        agent_mgmt_desc = QLabel(
            "All known agents seen by this server. "
            "Assign a display color from the palette or clear an agent's settings."
        )
        agent_mgmt_desc.setWordWrap(True)
        agent_mgmt_tab_layout.addWidget(agent_mgmt_desc)

        self.agent_mgmt_table = QTableWidget(0, 5)
        self.agent_mgmt_table.setHorizontalHeaderLabels(["Hostname", "Color", "Hide", "Is Active", "Action"])
        self.agent_mgmt_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.agent_mgmt_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.agent_mgmt_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.agent_mgmt_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.agent_mgmt_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.agent_mgmt_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.agent_mgmt_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.agent_mgmt_table.verticalHeader().setVisible(False)
        self.agent_mgmt_table.setSelectionMode(QTableWidget.NoSelection)
        agent_mgmt_tab_layout.addWidget(self.agent_mgmt_table)
        agent_mgmt_tab_layout.addStretch()

        self.tab_widget.addTab(agent_mgmt_tab_widget, "Agent Management")
        # Keep track of the agent management tab index
        self._agent_mgmt_tab_index = self.tab_widget.count() - 1
        # Only show it when server mode is active
        self.tab_widget.setTabVisible(self._agent_mgmt_tab_index, enable_server_mode)

        # Connect tab change event to update summary when Summary tab is selected
        self.tab_widget.currentChanged.connect(self.on_tab_changed)

        # Set QTabWidget as central widget
        self.setCentralWidget(self.tab_widget)

        # keyboard shortcuts for fullscreen / exit-fullscreen
        try:
            act_toggle_fs = QAction("Toggle Fullscreen", self)
            # F11 commonly toggles fullscreen on Windows/Linux; Ctrl+Meta+F for macOS
            act_toggle_fs.setShortcuts(["F11", "Ctrl+Meta+F"])
            act_toggle_fs.setShortcutContext(Qt.ApplicationShortcut)
            act_toggle_fs.triggered.connect(self._toggle_fullscreen)
            self.addAction(act_toggle_fs)

            # Escape should leave fullscreen (defensive: only act when fullscreen)
            act_escape = QAction(self)
            act_escape.setShortcut("Escape")
            act_escape.setShortcutContext(Qt.ApplicationShortcut)
            act_escape.triggered.connect(lambda: (self.showNormal() if (bool(self.windowState() & Qt.WindowFullScreen) or self.isFullScreen()) else None))
            self.addAction(act_escape)
        except Exception:
            pass

        # Connect the web view's load finished signal
        self.map_view.loadFinished.connect(self.on_map_loaded)
        # Defer initial filter bar width sync until the layout is finalized
        QTimer.singleShot(0, self._sync_filter_widths)
        QTimer.singleShot(0, self._sync_summary_filter_widths)

    def _populate_db_status_table(self):
        """Fill (or refresh) the database status table in the Actions tab."""
        try:
            db_entries = [
                ("GeoLite2 IPv4", IPV4_DB_PATH, GEOLITE2_IPV4_DOWNLOAD_URL),
                ("GeoLite2 IPv6", IPV6_DB_PATH, GEOLITE2_IPV6_DOWNLOAD_URL),
                ("C2 Tracker",    C2_TRACKER_DB_PATH, C2_TRACKER_DB_DOWNLOAD_URL),
            ]

            self.db_status_table.setRowCount(0)

            for db_name, db_path, db_url in db_entries:
                row = self.db_status_table.rowCount()
                self.db_status_table.insertRow(row)

                self.db_status_table.setItem(row, 0, QTableWidgetItem(db_name))

                if os.path.exists(db_path):
                    mtime = os.path.getmtime(db_path)
                    downloaded_dt = datetime.datetime.fromtimestamp(mtime)
                    expires_dt = downloaded_dt + datetime.timedelta(days=DATABASE_EXPIRE_AFTER_DAYS)
                    downloaded_str = downloaded_dt.strftime("%Y-%m-%d %H:%M:%S")
                    expires_str = expires_dt.strftime("%Y-%m-%d %H:%M:%S")
                    expires_item = QTableWidgetItem(expires_str)
                    if datetime.datetime.now() > expires_dt:
                        expires_item.setForeground(Qt.red)
                else:
                    downloaded_str = "Not downloaded"
                    expires_item = QTableWidgetItem("N/A")

                self.db_status_table.setItem(row, 1, QTableWidgetItem(downloaded_str))
                self.db_status_table.setItem(row, 2, expires_item)

                refresh_btn = QPushButton("Refresh")
                refresh_btn.clicked.connect(lambda checked=False, p=db_path, u=db_url: self._refresh_single_database(p, u))
                self.db_status_table.setCellWidget(row, 3, refresh_btn)

        except Exception as e:
            logging.error(f"Error populating DB status table: {e}")

    def _refresh_single_database(self, db_path, db_url):
        """Download a single database, reload it into memory, and update the status table."""
        try:
            was_capturing = hasattr(self, 'timer') and self.timer.isActive()
            if was_capturing:
                self.timer.stop()

            self.download_database(db_path, db_url)

            # Reload the relevant in-memory reader
            try:
                if db_path == IPV4_DB_PATH:
                    if self.reader_ipv4 is not None:
                        self.reader_ipv4.close()
                    self.reader_ipv4 = maxminddb.open_database(IPV4_DB_PATH)
                    self._geo_cache.clear()
                elif db_path == IPV6_DB_PATH:
                    if self.reader_ipv6 is not None:
                        self.reader_ipv6.close()
                    self.reader_ipv6 = maxminddb.open_database(IPV6_DB_PATH)
                    self._geo_cache.clear()
                elif db_path == C2_TRACKER_DB_PATH:
                    self.reader_c2_tracker = {}
                    self.reader_c2_tracker_set = set()
                    if os.path.exists(C2_TRACKER_DB_PATH):
                        with open(C2_TRACKER_DB_PATH, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue
                                parts = line.split("\t")
                                ip = parts[0]
                                self.reader_c2_tracker_set.add(ip)
                                typ = parts[1] if len(parts) > 1 else ""
                                info = parts[2] if len(parts) > 2 else ""
                                self.reader_c2_tracker[ip] = (typ, info)
            except Exception as reload_err:
                logging.error(f"Failed to reload database {db_path}: {reload_err}")
                QMessageBox.warning(self, "Reload Error", f"Database downloaded but failed to reload: {reload_err}")

            # Refresh the status table display
            self._populate_db_status_table()

            if was_capturing:
                self.timer.start(map_refresh_interval)

        except Exception as e:
            logging.error(f"Error refreshing database {db_path}: {e}")

    @Slot()
    def _refresh_all_databases(self):
        """Download all databases in sequence, reload them, then update the status table."""
        db_entries = [
            (IPV4_DB_PATH, GEOLITE2_IPV4_DOWNLOAD_URL),
            (IPV6_DB_PATH, GEOLITE2_IPV6_DOWNLOAD_URL),
            (C2_TRACKER_DB_PATH, C2_TRACKER_DB_DOWNLOAD_URL),
        ]
        was_capturing = hasattr(self, 'timer') and self.timer.isActive()
        if was_capturing:
            self.timer.stop()
        try:
            for db_path, db_url in db_entries:
                self._refresh_single_database(db_path, db_url)
        finally:
            if was_capturing and not self.timer.isActive():
                self.timer.start(map_refresh_interval)

    def _is_any_database_expired(self):
        """Return True if any of the tracked databases is missing or older than DATABASE_EXPIRE_AFTER_DAYS."""
        for db_path in (IPV4_DB_PATH, IPV6_DB_PATH, C2_TRACKER_DB_PATH):
            if not os.path.exists(db_path):
                return True
            modification_time = os.path.getmtime(db_path)
            days_old = (datetime.datetime.now() - datetime.datetime.fromtimestamp(modification_time)).days
            if days_old > DATABASE_EXPIRE_AFTER_DAYS:
                return True
        return False

    @Slot()
    def _on_database_refresh_timer(self):
        """Periodic callback (every 10 minutes) that checks database expiration and refreshes expired databases."""
        try:
            if not self._is_any_database_expired():
                return

            logging.info("Database refresh timer: expired database(s) detected, starting refresh.")

            was_capturing = hasattr(self, 'timer') and self.timer.isActive()
            if was_capturing:
                self.timer.stop()

            # Stop the refresh timer itself while updating to avoid re-entry
            self.database_refresh_timer.stop()

            try:
                for db_path, db_url in [
                    (IPV4_DB_PATH, GEOLITE2_IPV4_DOWNLOAD_URL),
                    (IPV6_DB_PATH, GEOLITE2_IPV6_DOWNLOAD_URL),
                    (C2_TRACKER_DB_PATH, C2_TRACKER_DB_DOWNLOAD_URL),
                ]:
                    if not os.path.exists(db_path):
                        self._refresh_single_database(db_path, db_url)
                    else:
                        modification_time = os.path.getmtime(db_path)
                        days_old = (datetime.datetime.now() - datetime.datetime.fromtimestamp(modification_time)).days
                        if days_old > DATABASE_EXPIRE_AFTER_DAYS:
                            self._refresh_single_database(db_path, db_url)
            finally:
                # Restart the periodic database refresh timer
                self.database_refresh_timer.start(DATABASE_EXPIRE_TIME_CHECK_INTERVAL)

                # Resume capture if it was running before
                if was_capturing and not self.timer.isActive():
                    self.timer.start(map_refresh_interval)

            logging.info("Database refresh timer: refresh complete.")

        except Exception as e:
            logging.error(f"Error in database refresh timer: {e}")
            # Ensure the timer keeps running even after an error
            if not self.database_refresh_timer.isActive():
                self.database_refresh_timer.start(DATABASE_EXPIRE_TIME_CHECK_INTERVAL)

    def load_databases(self):
        try:
            # Ensure database directory exists
            if not os.path.exists(DB_DIR):
                os.makedirs(DB_DIR)

            # Check each database file
            self._check_and_download_database(IPV4_DB_PATH, "IPv4", GEOLITE2_IPV4_DOWNLOAD_URL, GEOLITE2_IPV4_DOWNLOAD_IPV4_ABOUT_TITLE, GEOLITE2_IPV4_DOWNLOAD_IPV4_ABOUT_TEXT)
            self._check_and_download_database(IPV6_DB_PATH, "IPv6", GEOLITE2_IPV6_DOWNLOAD_URL, GEOLITE2_IPV6_DOWNLOAD_IPV4_ABOUT_TITLE, GEOLITE2_IPV6_DOWNLOAD_IPV4_ABOUT_TEXT)
            self._check_and_download_database(C2_TRACKER_DB_PATH, "C2-TRACKER", C2_TRACKER_DB_DOWNLOAD_URL, C2_TRACKER_DB_DOWNLOAD_ABOUT_TITLE, C2_TRACKER_DB_DOWNLOAD_ABOUT_TEXT)

            # Open databases
            self.reader_ipv4 = maxminddb.open_database(IPV4_DB_PATH)
            self.reader_ipv6 = maxminddb.open_database(IPV6_DB_PATH)

            # Load C2-TRACKER into both set (fast lookup) and dict (details)
            self.reader_c2_tracker = {}
            self.reader_c2_tracker_set = set()
            if os.path.exists(C2_TRACKER_DB_PATH):
                with open(C2_TRACKER_DB_PATH, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split("\t")
                        ip = parts[0]
                        self.reader_c2_tracker_set.add(ip)  # Fast O(1) lookup
                        typ = parts[1] if len(parts) > 1 else ""
                        info = parts[2] if len(parts) > 2 else ""
                        self.reader_c2_tracker[ip] = (typ, info)

        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load databases: {str(e)}, nothing may show on map.")
    
    def check_ip_is_present_in_c2_tracker(self, ip_address):
        """Check if an IP address is present in the C2-TRACKER database (optimized)"""
        try:
            # Fast O(1) lookup in set first
            if self.reader_c2_tracker_set and ip_address in self.reader_c2_tracker_set:
                # Get details from dict only if found
                entry = self.reader_c2_tracker.get(ip_address)
                if entry:
                    return True, entry[0], entry[1]
            return False, None, None
        except Exception:
            return False, None, None

    def download_database(self, db_path, url):
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

            # Download file
            response = requests.get(url, stream=True, timeout=30)
            if response.status_code == 200:
                if os.path.exists(db_path):
                    os.remove(db_path)  # remove the previous file first
                with open(db_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)
                
                if not ACCEPT_EULA:
                    QMessageBox.information(
                        self,
                        "Download Complete",
                        f"Successfully downloaded GeoLite2 database to {db_path}"
                    )
                else:
                    logging.info(f"Downloaded database {url} to {db_path}. This means you FULLY AGREE with the database' EULA and their liceensing terms.")
            else:
                raise Exception(f"Failed to download. HTTP Status Code: {response.status_code}")
        except Exception as e:
            QMessageBox.critical(
                self,
                "Download Error",
                f"Failed to download database: {str(e)}"
            )

    def _check_and_download_database(self, db_path, db_type, download_url, about_title, about_text):

        if db_type == "" or db_type is None:
            about_title = "Unknown Database"
            about_text = f"Unexpected database type."

        if os.path.exists(db_path):
            # Check file age
            modification_time = os.path.getmtime(db_path)
            days_old = (datetime.datetime.now() - datetime.datetime.fromtimestamp(modification_time)).days

            if days_old > DATABASE_EXPIRE_AFTER_DAYS:
                self._prompt_to_download(db_type, db_path, download_url, about_title=about_title + f" (current version is older than {DATABASE_EXPIRE_AFTER_DAYS} days)", about_text=about_text)

        else:
            self._prompt_to_download(db_type, db_path, download_url, about_title=about_title, about_text=about_text)

    def _prompt_to_download(self, db_type, db_path, download_url, about_title="", about_text=""):

        if ACCEPT_EULA:
            try:
                self.download_database(db_path, download_url)
            except Exception as e:
                QMessageBox.critical(self, "Download Error", f"Failed to download database: {e}")
                return []
        else:

            # Show license information
            QMessageBox.about(
                self,
                about_title,
                about_text
            )

            response = QMessageBox.question(
                self,
                "Download Required",
                f"The {db_type} database is either missing or older than {DATABASE_EXPIRE_AFTER_DAYS} days. Downloading means your are accepting database licensing terms by its publisher. Would you like to download it now?",
                QMessageBox.Yes | QMessageBox.No
            )

            if not ACCEPT_EULA and response == QMessageBox.Yes:
                self.download_database(db_path, download_url)

    def _download_leaflet_file(self, file_path, url, file_description=""):
        """Download a single Leaflet resource file"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Download file
            response = requests.get(url, stream=True, timeout=30)
            if response.status_code == 200:
                # Remove existing file if present
                if os.path.exists(file_path):
                    os.remove(file_path)

                with open(file_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

                if not ACCEPT_EULA:
                    logging.info(f"Successfully downloaded {file_description} to {file_path}")
                else:
                    logging.info(f"Downloaded {file_description} from {url} to {file_path}.")
                return True
            else:
                raise Exception(f"Failed to download. HTTP Status Code: {response.status_code}")
        except Exception as e:
            logging.warning(f"Failed to download {file_description}: {str(e)}")
            return False

    def _check_and_download_leaflet_resources(self):
        """Check if Leaflet resources exist locally and download them if missing"""
        try:
            # Define resources to check/download
            resources = [
                (LEAFLET_CSS_PATH, LEAFLET_CSS_URL, "Leaflet CSS"),
                (LEAFLET_JS_PATH, LEAFLET_JS_URL, "Leaflet JavaScript"),
                (LEAFLET_MARKER_RED_PATH,    LEAFLET_MARKER_RED_URL,    "Red marker icon"),
                (LEAFLET_MARKER_GREEN_PATH,  LEAFLET_MARKER_GREEN_URL,  "Green marker icon"),
                (LEAFLET_MARKER_BLUE_PATH,   LEAFLET_MARKER_BLUE_URL,   "Blue marker icon"),
                (LEAFLET_MARKER_YELLOW_PATH, LEAFLET_MARKER_YELLOW_URL, "Yellow marker icon"),
                (LEAFLET_MARKER_ORANGE_PATH, LEAFLET_MARKER_ORANGE_URL, "Orange marker icon"),
                (LEAFLET_MARKER_VIOLET_PATH, LEAFLET_MARKER_VIOLET_URL, "Violet marker icon"),
                (LEAFLET_MARKER_BLACK_PATH,  LEAFLET_MARKER_BLACK_URL,  "Black marker icon"),
                (LEAFLET_MARKER_GREY_PATH,   LEAFLET_MARKER_GREY_URL,   "Grey marker icon"),
                (LEAFLET_MARKER_GOLD_PATH,   LEAFLET_MARKER_GOLD_URL,   "Gold marker icon"),
            ]

            # Check which resources are missing
            missing_resources = []
            for file_path, url, description in resources:
                if not os.path.exists(file_path):
                    missing_resources.append((file_path, url, description))

            # If all resources exist, no action needed
            if not missing_resources:
                return

            # Determine if we should download automatically or prompt
            should_download = ACCEPT_EULA

            if not ACCEPT_EULA:
                # Show information dialog
                QMessageBox.about(
                    self,
                    LEAFLET_RESOURCES_ABOUT_TITLE,
                    LEAFLET_RESOURCES_ABOUT_TEXT
                )

                # Ask user if they want to download
                response = QMessageBox.question(
                    self,
                    "Download Leaflet Resources?",
                    f"Would you like to download {len(missing_resources)} Leaflet resource file(s) locally?\n\n"
                    f"This will speed up application startup and enable offline map functionality.\n\n"
                    f"Files will be saved to: {LEAFLET_DIR}",
                    QMessageBox.Yes | QMessageBox.No
                )

                should_download = (response == QMessageBox.Yes)

            # Download resources if approved
            if should_download:
                # Ensure directory exists
                os.makedirs(LEAFLET_DIR, exist_ok=True)

                success_count = 0
                fail_count = 0

                for file_path, url, description in missing_resources:
                    if self._download_leaflet_file(file_path, url, description):
                        success_count += 1
                    else:
                        fail_count += 1

                # Show summary if not in auto-accept mode
                if not ACCEPT_EULA:
                    if fail_count == 0:
                        QMessageBox.information(
                            self,
                            "Download Complete",
                            f"Successfully downloaded {success_count} Leaflet resource file(s) to {LEAFLET_DIR}\n\n"
                            f"The application will now use local resources for faster startup and offline support."
                        )
                    else:
                        QMessageBox.warning(
                            self,
                            "Download Partially Complete",
                            f"Downloaded {success_count} file(s) successfully.\n"
                            f"Failed to download {fail_count} file(s).\n\n"
                            f"The application will fall back to CDN for missing resources."
                        )
                else:
                    logging.info(f"Leaflet resources download complete: {success_count} succeeded, {fail_count} failed.")

        except Exception as e:
            error_msg = f"Error checking/downloading Leaflet resources: {str(e)}"
            logging.error(error_msg)
            if not ACCEPT_EULA:
                QMessageBox.warning(
                    self,
                    "Leaflet Resources Error",
                    f"{error_msg}\n\nThe application will use CDN resources instead."
                )

    def _is_pinned_connection(self, conn):
        """Check if *conn* matches the pinned (double-clicked) connection.

        Uses a relaxed comparison that strips hostname suffixes from the remote
        address and ignores PID (which may change across process restarts) so
        that the pin survives refreshes reliably.
        """
        pin = self._pinned_connection
        if pin is None:
            return False
        # Strip " (hostname)" suffix for comparison
        def _bare_remote(r):
            return r.split(' (')[0] if r else r
        return (
            conn.get('process') == pin.get('process') and
            conn.get('protocol') == pin.get('protocol') and
            conn.get('local') == pin.get('local') and
            conn.get('localport') == pin.get('localport') and
            _bare_remote(conn.get('remote', '')) == _bare_remote(pin.get('remote', '')) and
            conn.get('remoteport') == pin.get('remoteport') and
            conn.get('ip_type') == pin.get('ip_type')
        )

    def get_active_tcp_connections(self, position_timeline=None):
        """
        Enumerate TCP and UDP connections and build the connection snapshot.

        Raw connection enumeration is delegated to the active collector plugin
        (default: PsutilCollector).  This method then enriches each raw dict
        with geolocation, reverse DNS, C2 checks, icon assignment, agent merge,
        and timeline management.
        """

        connections = []
        c2_connections = []
        global do_capture_screenshots, geo_cache, geo_cache_lock, process_cache, process_cache_lock

        # Performance timing
        start_time = time.perf_counter()

        # Timeline replay short-circuit
        if position_timeline is not None:
            idx = min(position_timeline, len(self.connection_list) - 1)
            if idx >= 0:
                return self.connection_list[idx]['connection_list']
            else:
                return []

        # --- Phase 1: Collect raw connections via the active plugin -----------
        try:
            raw_connections = self._active_collector.collect_raw_connections()
        except Exception as e:
            logging.error(f"Collector plugin '{self._active_collector.name}' failed: {e}")
            raw_connections = []

        # --- Phase 2: Batch DNS warm-up for all remote IPs -------------------
        ips_to_resolve = set()
        for rc in raw_connections:
            remote = rc.get('remote', '')
            ip = remote.split(' ')[0].split(':')[0]
            if ip and ip not in ('127.0.0.1', '::1', 'N/A', '*', '0.0.0.0', '::'):
                ips_to_resolve.add(ip)

        ip_hostnames = {}
        if do_reverse_dns and ips_to_resolve:
            ips_to_enqueue = set()
            global public_ip_dns_attempts, public_ip_dns_attempts_lock

            with public_ip_dns_attempts_lock:
                for ip in ips_to_resolve:
                    if ip not in public_ip_dns_attempts:
                        public_ip_dns_attempts[ip] = datetime.datetime.now()
                        ips_to_enqueue.add(ip)

            if ips_to_enqueue:
                try:
                    if getattr(self, "dns_worker", None) is not None:
                        self.dns_worker.enqueue_many(ips_to_enqueue)
                except Exception:
                    pass

            with cache_lock:
                for ip in ips_to_resolve:
                    host = ip_cache.get(ip)
                    if host:
                        ip_hostnames[ip] = host

        # Local references for speed
        reader_ipv4 = self.reader_ipv4
        reader_ipv6 = self.reader_ipv6
        do_c2 = do_c2_check

        # Build a set of connection keys from the previous snapshot for O(1)
        # new-connection detection (replaces the old O(n²) is_connection_in_list).
        # Use the raw remote IP (strip DNS-enriched hostname) so that a background
        # DNS resolution does not cause existing connections to be detected as "new",
        # which would trigger a global tooltip flash and visible map refresh.
        _prev_conn_keys = set()
        if self.connection_list:
            try:
                for _pc in self.connection_list[-1]['connection_list']:
                    _prev_remote_raw = _pc.get('remote', '').split(' (')[0]
                    _prev_conn_keys.add((
                        _pc.get('process', ''), _pc.get('pid', ''),
                        _pc.get('protocol', ''), _pc.get('local', ''),
                        _pc.get('localport', ''), _prev_remote_raw,
                        _pc.get('remoteport', ''), _pc.get('ip_type', ''),
                    ))
            except Exception:
                pass

        # --- Phase 3: Enrich each raw connection with geo/DNS/C2/icons -------
        # Build a set of (local_addr, local_port, protocol) tuples for LISTEN
        # sockets so we can tag established connections arriving at those ports
        # as "inbound" (rendered with a red line on the map).
        _listen_ports = set()
        if do_show_listening_connections:
            for rc in raw_connections:
                if rc.get('state', '') == 'LISTEN':
                    _listen_ports.add((rc.get('localport', ''), rc.get('protocol', 'TCP')))

        for rc in raw_connections:
            try:
                process_name = rc.get('process', 'Unknown')
                pid = rc.get('pid', '')
                protocol = rc.get('protocol', 'TCP')
                local_addr = rc.get('local', '')
                local_port = rc.get('localport', '')
                remote_addr = rc.get('remote', '')
                remote_port = rc.get('remoteport', '')
                ip_type = rc.get('ip_type', '')
                hostname = rc.get('hostname', LOCAL_HOSTNAME)
                bytes_sent = rc.get('bytes_sent', 0)
                bytes_recv = rc.get('bytes_recv', 0)
                conn_state = rc.get('state', '')

                lat = lng = None
                name = ""

                ip_lookup = remote_addr.split(' ')[0].split(':')[0]

                if ip_lookup and ip_lookup not in ('127.0.0.1', '::1', 'N/A', '*', '0.0.0.0', '::'):
                    # Geolocation
                    with geo_cache_lock:
                        if ip_lookup in geo_cache:
                            lat, lng = geo_cache[ip_lookup]
                        else:
                            try:
                                if ip_type == "IPv4" and reader_ipv4:
                                    res = reader_ipv4.get(ip_lookup)
                                    if res is not None:
                                        lat = res.get('latitude') or res.get('location', {}).get('latitude')
                                        lng = res.get('longitude') or res.get('location', {}).get('longitude')
                                elif ip_type == "IPv6" and reader_ipv6:
                                    res = reader_ipv6.get(ip_lookup)
                                    if res is not None:
                                        lat = res.get('latitude') or res.get('location', {}).get('latitude')
                                        lng = res.get('longitude') or res.get('location', {}).get('longitude')
                                geo_cache[ip_lookup] = (lat, lng)
                            except Exception:
                                lat = lng = None
                                geo_cache[ip_lookup] = (None, None)

                    # Reverse DNS
                    if do_reverse_dns:
                        resolved = ip_hostnames.get(ip_lookup)
                        if resolved:
                            remote_addr = f"{remote_addr}"
                            name = resolved

                    # C2 check
                    if do_c2 and self.reader_c2_tracker_set is not None:
                        try:
                            is_c2, c2_type, c2_info = self.check_ip_is_present_in_c2_tracker(ip_lookup)
                            if is_c2:
                                c2_connections.append({
                                    'process': process_name,
                                    'pid': pid,
                                    'suspect': 'Yes',
                                    'protocol': protocol,
                                    'local': local_addr,
                                    'localport': local_port,
                                    'remote': remote_addr,
                                    'remoteport': remote_port,
                                    'name': name,
                                    'ip_type': ip_type,
                                    'lat': lat,
                                    'lng': lng,
                                    'icon': 'redIcon',
                                    'hostname': hostname,
                                    'bytes_sent': bytes_sent,
                                    'bytes_recv': bytes_recv,
                                })
                        except Exception:
                            pass

                # Determine if this is an inbound connection to a listening port
                is_inbound = bool(conn_state != 'LISTEN'
                                  and _listen_ports
                                  and (local_port, protocol) in _listen_ports)

                # Standard connection entry
                connections.append({
                    'process': process_name,
                    'pid': pid,
                    'suspect': '',
                    'protocol': protocol,
                    'local': local_addr,
                    'localport': local_port,
                    'remote': remote_addr,
                    'remoteport': remote_port,
                    'name': name,
                    'ip_type': ip_type,
                    'lat': lat,
                    'lng': lng,
                    'icon': 'listenIcon' if conn_state == 'LISTEN' else 'greenIcon',
                    'hostname': hostname,
                    'bytes_sent': bytes_sent,
                    'bytes_recv': bytes_recv,
                    'state': conn_state,
                    'inbound': is_inbound,
                })

                # New connection detection — O(1) set lookup.
                # Use the raw remote IP (before DNS enrichment) so that
                # background name resolution does not cause a false positive.
                if _prev_conn_keys:
                    _raw_remote_for_key = remote_addr.split(' (')[0]
                    _key = (process_name, pid, protocol, local_addr, local_port,
                            _raw_remote_for_key, remote_port, ip_type)
                    if _key not in _prev_conn_keys:
                        connections[-1]['icon'] = 'blueIcon'

            except Exception:
                continue

        # Merge C2 entries at front if present
        if c2_connections:
            c2_connections.extend(connections)
            connections = c2_connections

        # Server mode: drain agent cache and merge remote agent connections
        agent_snapshot = {}
        if enable_server_mode and position_timeline is None:
            agent_snapshot = self._collect_and_reset_agent_cache()
            for hostname, agent_data in agent_snapshot.items():
                agent_origin_lat = agent_data.get('lat')
                agent_origin_lng = agent_data.get('lng')
                agent_public_ip = agent_data.get('public_ip', '')
                # Assign a persistent color to this agent on first encounter
                if hostname not in self._agent_colors:
                    palette = self._AGENT_COLOR_PALETTE
                    self._agent_colors[hostname] = palette[self._agent_color_index % len(palette)]
                    self._agent_color_index += 1
                agent_color = self._agent_colors[hostname]
                for agent_conn in agent_data.get('connections', []):
                    agent_conn['hostname'] = hostname
                    # Inject the agent's exit-point origin so the map can draw
                    # per-agent circles and polylines from the correct origin.
                    agent_conn['origin_lat'] = agent_origin_lat
                    agent_conn['origin_lng'] = agent_origin_lng
                    agent_conn['origin_hostname'] = hostname
                    agent_conn['origin_public_ip'] = agent_public_ip
                    agent_conn['agent_color'] = agent_color
                    # Use the agent's assigned color icon (fall back if not suspect)
                    if agent_conn.get('icon') not in ('redIcon',):
                        agent_conn['icon'] = agent_color + 'Icon'
                    connections.append(agent_conn)

        # record timeline snapshot only when requested (position_timeline is None)
        if position_timeline is None:
            snap_ts = datetime.datetime.now()
            snap_agent = agent_snapshot if enable_server_mode and agent_snapshot else None
            another_connection = {
                "datetime": snap_ts,
                "connection_list": connections,
                "agent_data": snap_agent,
            }

            # append — deque with maxlen auto-evicts the oldest entry
            self.connection_list.append(another_connection)
            self.connection_list_counter = len(self.connection_list)

            # Persist to database if enabled
            self._db_save_snapshot(snap_ts, connections, snap_agent)

            # Mark summary as needing update (simple bool, safe from any thread)
            self._summary_needs_update = True

            # NOTE: All UI-widget updates (slider sync, summary table refresh,
            # screenshot scheduling, video button visibility) are handled by
            # _post_collection_ui_update() which is called from _apply_connections()
            # on the GUI thread.  This avoids heap corruption when
            # get_active_tcp_connections() runs on a QThreadPool worker thread.

            # Performance logging
            elapsed = time.perf_counter() - start_time
            if elapsed > 1.0:  # Log if took more than 1 second
                logging.warning(f"get_active_tcp_connections took {elapsed:.2f}s to process {len(connections)} connections")

        # Agent mode: POST local connections to the server
        if enable_agent_mode and position_timeline is None:
            try:
                self._agent_post_connections(connections)
            except Exception as e:
                logging.error(f"Agent POST failed: {e}")

        return connections
    
    def get_coordinates(self, ip_address, ip_type):
        """Get coordinates for an IP address (cached to avoid repeated maxminddb lookups)."""

        cache_key = (ip_address, ip_type)
        cached = self._geo_cache.get(cache_key)
        if cached is not None:
            return cached

        lat, lng = None, None

        if ip_type == "IPv4":
            try:
                result = self.reader_ipv4.get(ip_address)
                if result is not None:
                    lat = result.get('latitude') or result.get('location', {}).get('latitude')
                    lng = result.get('longitude') or result.get('location', {}).get('longitude')
            except:
                pass

        elif ip_type == "IPv6":
            try:
                result = self.reader_ipv6.get(ip_address)
                if result is not None:
                    lat = result.get('latitude') or result.get('location', {}).get('latitude')
                    lng = result.get('longitude') or result.get('location', {}).get('longitude')
            except:
                pass

        coords = (lat, lng) if (lat is not None and lng is not None) else (None, None)
        self._geo_cache[cache_key] = coords
        return coords

    def _pulse_map_indicator(self):
        """Trigger green pulse animation on the map overlay (JavaScript-based)."""
        try:
            # Call JavaScript to show the pulse overlay on the map
            js_code = "if (typeof window.triggerPulse === 'function') { window.triggerPulse(); }"
            self.map_view.page().runJavaScript(js_code)
        except Exception:
            # defensive: ignore if map not ready yet
            pass

    def _call_update_js(self, js, connection_data=None, force_show_tooltip=False, retries=10, delay_ms=200):
        """
        Safely call JS updater by first checking that `window.updateConnections` is defined.
        Retries a few times with a delay; shows error if function never becomes available.
        """

        try:
            check_expr = "typeof window.updateConnections === 'function';"

            # Use a list to create a mutable container for retries (closure-friendly)
            retries_remaining = [retries]

            def _on_check(result):
                if result:
                    try:
                        self.map_view.page().runJavaScript(js)
                        # Reset reload counter on successful call
                        try:
                            self._map_reload_attempts = 0
                        except Exception:
                            pass
                    except Exception as e:
                        # Log error but don't reload to prevent infinite loop
                        logging.error(f"Failed to execute map update JS: {e}")
                else:
                    # Decrement retries
                    retries_remaining[0] -= 1

                    if retries_remaining[0] <= 0:
                        # Give up - show error instead of reloading
                        logging.warning("Map initialization failed - updateConnections function not found (exhausted retries)")
                        # DON'T reload here - that causes infinite loop
                    else:
                        # schedule another existence check with same closure
                        logging.debug(f"Retrying map initialization ({retries_remaining[0]} attempts remaining)")
                        QTimer.singleShot(delay_ms, lambda: self.map_view.page().runJavaScript(check_expr, _on_check))

            # run the check asynchronously; _on_check will be called with the boolean result
            self.map_view.page().runJavaScript(check_expr, _on_check)
        except Exception as e:
            # Log error but don't reload to prevent infinite loop
            logging.error(f"Exception in _call_update_js: {e}")

    @property
    def _PUBLIC_IP_TTL(self):
        return map_refresh_interval / 1000  # seconds between external IP lookups

    def _check_network_changed(self) -> bool:
        """Return True (and reset caches) if the local NIC addresses changed.

        Detects VPN connect/disconnect, Wi-Fi roaming, or NIC up/down events
        by comparing the current set of local IP addresses against the
        previous snapshot.  When a change is detected:

        * The ``_public_ip_cache`` is invalidated so the next
          ``get_public_ip()`` call queries ipify immediately.
        * The HTTP session is closed and recreated so stale keep-alive
          connections through the old network path are discarded.
        """
        try:
            current = frozenset(self._get_local_ip_addresses())
        except Exception:
            return False
        if not self._last_local_addrs:
            self._last_local_addrs = current
            return False
        if current != self._last_local_addrs:
            logging.info(
                "Network change detected (local addresses changed) "
                "— flushing public IP cache and HTTP session"
            )
            self._last_local_addrs = current
            with self._public_ip_cache_lock:
                self._public_ip_cache = ""
                self._public_ip_cache_time = 0.0
            # Close the old session (drops stale keep-alive connections that
            # may route through the previous VPN tunnel) and open a fresh one.
            try:
                self._http_session.close()
            except Exception:
                pass
            self._http_session = requests.Session()
            return True
        return False

    def get_public_ip(self):
        """Get public IP address using ipify API with connection pooling and TTL cache.

        The result is cached for ``_PUBLIC_IP_TTL`` seconds so that the
        blocking HTTP call is not repeated on every 2-second refresh cycle.
        Thread-safe: may be called from both the main thread and background
        workers (e.g. _agent_post_worker).
        Returns empty string on error.
        """
        # Check for VPN / network change and invalidate cache if needed.
        self._check_network_changed()

        now = time.time()
        with self._public_ip_cache_lock:
            if self._public_ip_cache and (now - self._public_ip_cache_time) < self._PUBLIC_IP_TTL:
                return self._public_ip_cache
        try:
            response = self._http_session.get('https://api.ipify.org', timeout=5)
            if response.status_code == 200:
                result = response.text.strip()
                with self._public_ip_cache_lock:
                    self._public_ip_cache = result
                    self._public_ip_cache_time = now
                return result
            else:
                with self._public_ip_cache_lock:
                    return self._public_ip_cache or ""
        except Exception:
            with self._public_ip_cache_lock:
                return self._public_ip_cache or ""

    def update_map(self, connection_data, force_show_tooltip=False, stats_text="", datetime_text="", skip_histogram=False):
        """
        Load map HTML once and afterwards update markers via injected JavaScript.
        Use `_call_update_js` to avoid calling `updateConnections` before the JS function exists.
        """
        display_name = ""

        if do_resolve_public_ip:
            try:
                public_ip = self.get_public_ip()
                if public_ip:
                    # Determine IP type
                    try:
                        ip_obj = ipaddress.ip_address(public_ip)
                        ip_type = "IPv4" if ip_obj.version == 4 else "IPv6"
                    except Exception:
                        ip_type = "IPv4"

                    # Get reverse DNS if enabled
                    dns_name = ""
                    if do_reverse_dns:

                        # Try to get from cache immediately
                        global cache_lock, ip_cache, public_ip_dns_attempts, public_ip_dns_attempts_lock

                        if not ip_cache.get(public_ip):
                            # Check if we've already attempted to resolve this IP
                            should_enqueue = False
                            with public_ip_dns_attempts_lock:
                                if public_ip not in public_ip_dns_attempts:
                                    # First time seeing this IP - mark it as attempted
                                    public_ip_dns_attempts[public_ip] = datetime.datetime.now()
                                    should_enqueue = True

                            # Enqueue for background resolution only if not previously attempted
                            if should_enqueue:
                                try:
                                    if getattr(self, "dns_worker", None) is not None:
                                        self.dns_worker.enqueue(public_ip)
                                except Exception:
                                    pass


                        with cache_lock:
                            cached_name = ip_cache.get(public_ip)
                            if cached_name:
                                dns_name = cached_name

                    # Get geolocation
                    lat = lng = None
                    try:
                        if ip_type == "IPv4" and self.reader_ipv4:
                            res = self.reader_ipv4.get(public_ip)
                            if res is not None:
                                lat = res.get('latitude') or res.get('location', {}).get('latitude')
                                lng = res.get('longitude') or res.get('location', {}).get('longitude')
                        elif ip_type == "IPv6" and self.reader_ipv6:
                            res = self.reader_ipv6.get(public_ip)
                            if res is not None:
                                lat = res.get('latitude') or res.get('location', {}).get('latitude')
                                lng = res.get('longitude') or res.get('location', {}).get('longitude')
                    except Exception:
                        pass

                    # Only add if we have geolocation
                    if lat is not None and lng is not None:
                        display_name = f"Public IP: {public_ip}"
                        if dns_name:
                            display_name = f"Public IP: {public_ip} ({dns_name})"

                        connection_data.append({
                            'process': 'Public IP',
                            'pid': '',
                            'suspect': '',
                            'local': '',
                            'localport': '',
                            'remote': display_name,
                            'remoteport': '',
                            'name': dns_name,
                            'ip_type': ip_type,
                            'lat': lat,
                            'lng': lng,
                            'icon': 'redCircle',
                            'hostname': LOCAL_HOSTNAME,
                        })
            except Exception:
                pass

        # Server mode: add circle entries for each connected agent's exit point.
        # Build the ordered z-layer stack: foreground agent on top, then others
        # in reverse-registration order, localhost always last (lowest z).
        if enable_server_mode:
            foreground_host = getattr(self, '_foreground_hostname', LOCAL_HOSTNAME)
            # Collect all known agent hostnames in registration order
            all_known_agents = list(getattr(self, '_agent_colors', {}).keys())
            # Build z-layer order: foreground first, then others, localhost last
            layer_order = [foreground_host]
            for h in all_known_agents:
                if h != foreground_host and h != LOCAL_HOSTNAME:
                    layer_order.append(h)
            if LOCAL_HOSTNAME not in layer_order:
                layer_order.append(LOCAL_HOSTNAME)
            # Base z-index for the top agent pane (below publicIpPane=650, above pinnedPane=640)
            _AGENT_PANE_Z_TOP = 635

            # Collect unique agent origins from the connection data
            # Iterate over a snapshot to avoid modifying list during iteration
            seen_agent_origins = set()
            hidden_agents = getattr(self, '_agent_hidden', {})
            # Remove connections belonging to hidden agents
            if hidden_agents:
                connection_data = [c for c in connection_data
                                   if not hidden_agents.get(c.get('origin_hostname') or c.get('hostname'), False)]
            for conn in list(connection_data):
                origin_hostname = conn.get('origin_hostname')
                origin_lat = conn.get('origin_lat')
                origin_lng = conn.get('origin_lng')
                if origin_hostname and origin_lat is not None and origin_lng is not None:
                    # Skip hidden agents — no exit-point circle on the map
                    if hidden_agents.get(origin_hostname, False):
                        continue
                    key = origin_hostname
                    if key not in seen_agent_origins:
                        seen_agent_origins.add(key)
                        origin_ip = conn.get('origin_public_ip', '')
                        agent_color = self._agent_colors.get(origin_hostname, 'orange')
                        # Demote localhost circle colour when not foreground
                        if origin_hostname == LOCAL_HOSTNAME and foreground_host != LOCAL_HOSTNAME:
                            agent_color = 'grey'
                        agent_label = f"Agent: {origin_hostname}"
                        if origin_ip:
                            agent_label += f" ({origin_ip})"
                        # Assign z-index based on layer order
                        try:
                            rank = layer_order.index(origin_hostname)
                        except ValueError:
                            rank = len(layer_order)
                        pane_z = max(600, _AGENT_PANE_Z_TOP - rank)
                        connection_data.append({
                            'process': 'Agent Exit Point',
                            'pid': '',
                            'suspect': '',
                            'local': '',
                            'localport': '',
                            'remote': agent_label,
                            'remoteport': '',
                            'name': origin_hostname,
                            'ip_type': '',
                            'lat': origin_lat,
                            'lng': origin_lng,
                            'icon': 'agentCircle',
                            'agent_color': agent_color,
                            'origin_hostname': origin_hostname,
                            'pane_z': pane_z,
                        })

        # --- Apply visual overrides (pinned connection, click focus, foreground remap) ---
        # Work on shallow copies of the dicts we mutate so the caller's originals
        # (and the _last_map_connections cache) are never contaminated.
        # We only copy dicts that actually need changes to keep the cost minimal.

        # Yellow icon override for the pinned (double-clicked) connection
        if self._pinned_connection is not None:
            for i, conn in enumerate(connection_data):
                if self._is_pinned_connection(conn):
                    conn = dict(conn)
                    connection_data[i] = conn
                    # Only override non-suspect connections (red stays red)
                    if conn.get('icon') != 'redIcon':
                        conn['icon'] = 'yellowIcon'
                    # Auto-open popup only once (the first refresh after pinning).
                    if self._pinned_popup_open:
                        conn['autoPopup'] = True
                        conn['popupGeneration'] = self._pinned_popup_generation
                        # Consume the flag so subsequent timer refreshes do not
                        # force-reopen the popup the user just closed.
                        self._pinned_popup_open = False
                    break

        # Single-click focus: auto-open popup for the clicked connection (one-shot)
        focus = getattr(self, '_click_focus_conn', None)
        if focus is not None:
            self._click_focus_conn = None  # consume immediately
            for i, conn in enumerate(connection_data):
                if (conn.get('process') == focus.get('process') and
                    conn.get('remote') == focus.get('remote') and
                    conn.get('remoteport') == focus.get('remoteport') and
                    conn.get('local') == focus.get('local') and
                    conn.get('localport') == focus.get('localport') and
                    conn.get('protocol') == focus.get('protocol')):
                    conn = dict(conn)
                    connection_data[i] = conn
                    conn['autoPopup'] = True
                    conn.setdefault('popupGeneration', 0)
                    break

        # Foreground / z-layer icon remapping.
        foreground = getattr(self, '_foreground_hostname', LOCAL_HOSTNAME)
        if foreground != LOCAL_HOSTNAME:
            for i, conn in enumerate(connection_data):
                hostname = conn.get('hostname', '')
                icon = conn.get('icon', '')
                if icon in ('redIcon', 'yellowIcon', 'agentCircle', 'redCircle', ''):
                    continue  # never remap suspect/pinned/circle markers
                if hostname == LOCAL_HOSTNAME:
                    conn = dict(conn)
                    connection_data[i] = conn
                    conn['icon'] = 'greyIcon'
                elif hostname == foreground:
                    agent_color = conn.get('agent_color', '')
                    if icon == agent_color + 'Icon':
                        conn = dict(conn)
                        connection_data[i] = conn
                        conn['icon'] = 'greenIcon'
                elif hostname:
                    pass  # other agents keep their assigned palette colour

        data_json = json.dumps(connection_data)
        # DEBUG: Log gauge-relevant data flow
        _n_total = len(connection_data)
        _n_with_bytes = sum(1 for c in connection_data if (c.get('bytes_sent') or 0) > 0 or (c.get('bytes_recv') or 0) > 0)
        _n_with_coords = sum(1 for c in connection_data if c.get('lat') and c.get('lng'))
        logging.debug(f"update_map: total={_n_total}, with_bytes={_n_with_bytes}, with_coords={_n_with_coords}, show_gauge={do_show_traffic_gauge}, skip_hist={skip_histogram}")
        # Determine if we should draw lines from public IP to markers

        draw_lines = do_resolve_public_ip and do_drawlines_between_local_and_remote
        if display_name:
            if stats_text:
                stats_text += f" - {display_name}"
            else:
                stats_text = f"{display_name}"

        # Determine if we should show recording indicator (only in live mode with screenshots enabled)
        # Live mode is when datetime_text starts with "Live:"
        is_recording = do_capture_screenshots and datetime_text.startswith("Live:")

        # Build server/agent mode indicator text
        mode_indicator_text = ''
        if enable_server_mode:
            agent_count = getattr(self, '_last_agent_count', 0)
            foreground = getattr(self, '_foreground_hostname', LOCAL_HOSTNAME)
            mode_indicator_text = (
                f'Server mode ({agent_count} agent{"s" if agent_count != 1 else ""}) '
                f'| Top layer: {foreground}'
            )
        elif enable_agent_mode:
            mode_indicator_text = f'Agent mode: {agent_server_host}:{FLASK_AGENT_PORT}'

        # Determine whether the 429-rejected overlay should be visible
        show_rejected = 'true' if getattr(self, '_agent_rejected_429', False) else 'false'

        # Build agent-server-unreachable status text (shown next to pulse indicator)
        agent_status_text = ''
        if enable_agent_mode and getattr(self, '_agent_server_unreachable', False):
            agent_status_text = f'\u26a0 Server unreachable: {agent_server_host}:{FLASK_AGENT_PORT}'

        # Compute total bytes sent/received across all connections for the traffic histogram.
        # The per-connection bytes_sent/bytes_recv values represent traffic observed during
        # the most recent collection interval (reset to 0 between cycles by the Scapy
        # collector, or re-parsed from a static pcap file).  The histogram receives these
        # per-interval totals directly.
        # skip_histogram is set for secondary calls (e.g. filter re-renders) that must not
        # push histogram data — only the primary timer-driven call should advance it.
        if skip_histogram:
            delta_sent = 0
            delta_recv = 0
        else:
            delta_sent = 0
            delta_recv = 0
            for c in connection_data:
                delta_sent += c.get('bytes_sent', 0) or 0
                delta_recv += c.get('bytes_recv', 0) or 0

        # Send stats_text, datetime_text, recording indicator, mode indicator, rejected overlay,
        # agent status, traffic histogram AND pulse to JS in a single runJavaScript call.
        # Batching everything into one evaluation avoids intermediate browser repaints
        # that cause visible blinking between the map update and the overlay updates.
        # Each call is wrapped in its own try/catch so that a failure in one (e.g. updateConnections
        # throwing on bad data) does not prevent the subsequent status/overlay calls from executing.
        histogram_js = '' if skip_histogram else (
            f"try{{updateTrafficHistogram({delta_sent},{delta_recv},{str(do_show_traffic_histogram).lower()})}}catch(e){{}};"
        )
        js = (
            f"try{{updateConnections({data_json}, {str(force_show_tooltip).lower()}, {str(draw_lines).lower()}, {str(do_show_traffic_gauge).lower()}, {str(do_pulse_exit_points).lower()})}}catch(e){{console.error('updateConnections error',e)}};"
            f"try{{setStats({json.dumps(stats_text)})}}catch(e){{}};"
            f"try{{setDateTime({json.dumps(datetime_text)})}}catch(e){{}};"
            f"try{{setRecordingIndicator({str(is_recording).lower()})}}catch(e){{}};"
            f"try{{setModeIndicator({json.dumps(mode_indicator_text)})}}catch(e){{}};"
            f"try{{setRejectedOverlay({show_rejected})}}catch(e){{}};"
            f"try{{setAgentStatus({json.dumps(agent_status_text)})}}catch(e){{}};"
            f"{histogram_js}"
            f"try{{triggerPulse()}}catch(e){{}}"
        )

        # Check reload attempt limit to prevent infinite loops
        if not getattr(self, "map_initialized", False):
            # If a load is already in flight, skip this call silently —
            # the pending loadFinished handler will invoke the JS updater.
            if getattr(self, "_map_loading_in_progress", False):
                return

            # Prevent infinite reload loop
            if getattr(self, "_map_reload_attempts", 0) >= 3:
                logging.error("Max map reload attempts (3) reached. Stopping to prevent infinite loop.")
                return

            try:
                self._map_reload_attempts += 1
                logging.debug(f"Map load attempt {self._map_reload_attempts}/3")
            except Exception:
                self._map_reload_attempts = 1

        # If not initialized, load the full HTML and wait for loadFinished before calling JS
        if not getattr(self, "map_initialized", False):
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <!-- QWebChannel for JavaScript-to-Python communication -->
                <script src="qrc:///qtwebchannel/qwebchannel.js"></script>
                <!-- Try CDN first; if it fails we inject a local fallback (resources/leaflet/) -->
                <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
                      onerror="try{injectLocalLeaflet(true)}catch(e){}" />
                <style> html, body { height:100%; margin:0; } #map { height:100%; width:100%; }
                       /* stats overlay at top center */ 
                       #map-stats { position:absolute; top:8px; left:50%; transform:translateX(-50%); z-index:1000; 
                                    background:rgba(255,255,255,0.85); padding:6px 10px; border-radius:6px; 
                                    font-family:Arial, sans-serif; font-size:14px; pointer-events:none; }
                       /* datetime overlay at bottom center */
                       #map-datetime { position:absolute; bottom:25px; left:50%; transform:translateX(-50%); z-index:1000;
                                       background:rgba(255,255,255,0.85); padding:6px 10px 6px 6px; border-radius:6px;
                                       font-family:Arial, sans-serif; font-size:12px; pointer-events:none; 
                                       display:flex; align-items:center; gap:8px; }
                       /* red recording pulse indicator */
                       #recording-indicator { width:10px; height:10px; background-color:#ff0000; border-radius:50%; 
                                              display:none; animation:pulse-red 1.5s ease-in-out infinite; }
                       @keyframes pulse-red {
                           0%, 100% { opacity:1; transform:scale(1); }
                           50% { opacity:0.3; transform:scale(0.85); }
                       }
                       /* green refresh pulse indicator (top-right) */
                       #refresh-pulse { position:absolute; top:12px; right:12px; z-index:1000;
                                        width:14px; height:14px; background-color:#33cc33; border-radius:50%;
                                        pointer-events:none; opacity:0; transition:opacity 0.1s ease-in; }
                       #refresh-pulse.active { animation:pulse-green 0.8s ease-in-out; }
                       @keyframes pulse-green {
                           0% { opacity:0; transform:scale(0.9); }
                           12% { opacity:1; transform:scale(1); }
                           88% { opacity:1; transform:scale(1); }
                           100% { opacity:0; transform:scale(0.9); }
                       }
                       /* agent server status label (to the left of the pulse dot) */
                       #agent-status { display:none; position:absolute; top:10px; right:32px; z-index:1000;
                                       font-family:Arial,sans-serif; font-size:11px; color:#cc0000; font-weight:bold;
                                       background:rgba(255,255,255,0.92); padding:3px 8px; border-radius:4px;
                                       border:1px solid #cc0000; pointer-events:none; white-space:nowrap; }
                       #agent-status.active { display:block; }
                       /* loading overlay centered on map */
                       #map-loading-overlay { position:absolute; top:0; left:0; width:100%; height:100%; z-index:2000;
                                              display:flex; flex-direction:column; align-items:center; justify-content:center;
                                              background:rgba(255,255,255,0.92); pointer-events:none;
                                              font-family:Arial, sans-serif; text-align:center; }
                       #map-loading-overlay .loading-text { font-size:18px; color:#333; }
                       #map-loading-overlay .loading-error { font-size:14px; color:#cc0000; margin-top:10px; white-space:pre-wrap; max-width:80%; }
                       @keyframes spin-loader { 0%{transform:rotate(0deg)} 100%{transform:rotate(360deg)} }
                       #map-loading-overlay .spinner { width:36px; height:36px; border:4px solid #ccc; border-top:4px solid #333;
                                                       border-radius:50%; animation:spin-loader 1s linear infinite; margin-bottom:14px; }
                       /* Fit-all / reset-view control button */
                       .leaflet-control-fitall a { font-size:18px; font-weight:bold; line-height:26px; text-align:center;
                                                   text-decoration:none; color:#333; }
                       .leaflet-control-fitall a:hover { background-color:#f4f4f4; }
                       /* Server/Agent mode indicator (bottom-left, next to fit-all) */
                       .leaflet-control-modeinfo { pointer-events:none; }
                       .leaflet-control-modeinfo .mode-label {
                           display:none; background:rgba(255,255,255,0.9); padding:4px 8px; border-radius:4px;
                           font-family:Arial, sans-serif; font-size:11px; color:#333; white-space:nowrap;
                           border:1px solid #ccc; }
                       .leaflet-control-modeinfo .mode-label.active { display:block; }
                       /* Traffic histogram overlay (left side, below zoom controls) */
                       #traffic-histogram {
                           position:absolute; top:80px; left:10px; z-index:1000;
                           width:120px; pointer-events:none;
                           font-family:Arial, sans-serif; font-size:9px;
                       }
                       #traffic-histogram.th-hidden { display:none; }
                       #traffic-histogram .th-digits {
                           text-align:left; margin-bottom:2px; line-height:1.15;
                           background:rgba(255,255,255,0.85); border-radius:4px;
                           padding:2px 4px; white-space:nowrap;
                       }
                       #traffic-histogram .th-digits .th-sent { color:#d32f2f; }
                       #traffic-histogram .th-digits .th-recv { color:#388e3c; }
                       #traffic-histogram .th-bars {
                           display:flex; flex-direction:column; align-items:stretch;
                           width:100%; box-sizing:border-box; gap:1px;
                           background:rgba(255,255,255,0.65); border-radius:4px;
                           padding:2px;
                       }
                       #traffic-histogram .th-bar-row {
                           display:flex; flex-direction:row; align-items:center;
                           height:4px; gap:0;
                       }
                       #traffic-histogram .th-bar-row .th-s {
                           background:#d32f2f; height:100%; border-radius:1px 0 0 1px;
                           transition:width 0.4s ease;
                       }
                       #traffic-histogram .th-bar-row .th-r {
                           background:#388e3c; height:100%; border-radius:0 1px 1px 0;
                           transition:width 0.4s ease;
                       }
                       /* Agent rejected (429) overlay centered on map */
                       #agent-rejected-overlay { display:none; position:absolute; top:0; left:0; width:100%; height:100%;
                           z-index:1500; background:rgba(0,0,0,0.55); justify-content:center; align-items:center; pointer-events:none; }
                       #agent-rejected-overlay.active { display:flex; }
                       #agent-rejected-overlay .rejected-box { background:#fff3f3; border:2px solid #cc0000; border-radius:10px;
                           padding:24px 36px; max-width:70%; text-align:center; pointer-events:auto; box-shadow:0 4px 24px rgba(0,0,0,0.3); }
                       #agent-rejected-overlay .rejected-title { font-size:20px; font-weight:bold; color:#cc0000; margin-bottom:8px; }
                       #agent-rejected-overlay .rejected-msg { font-size:14px; color:#333; }
                       /* Traffic gauge styles */
                       .traffic-gauge-icon { background:transparent !important; border:none !important; }
                       .traffic-gauge {
                           display:flex; flex-direction:column; width:10px;
                           border:1px solid rgba(0,0,0,0.35); border-radius:2px; overflow:hidden;
                           background:#eee; box-shadow:0 0 3px rgba(0,0,0,0.25);
                       }
                       .tg-empty { width:100%; }
                       .tg-recv { background:#4caf50; width:100%; }
                       .tg-sent { background:#f44336; width:100%; }
                       /* exit-point pulse ring for agent circles and red server circle */
                       .exit-pulse-icon { background:transparent !important; border:none !important; pointer-events:none !important; }
                       .exit-pulse-ring {
                           width:24px; height:24px; border-radius:50%;
                           border:3px solid currentColor;
                           position:absolute; top:50%; left:50%;
                           transform:translate(-50%,-50%) scale(1);
                           animation: exit-pulse-anim 2s ease-out infinite;
                           pointer-events:none;
                       }
                       @keyframes exit-pulse-anim {
                           0%   { transform:translate(-50%,-50%) scale(1);   opacity:0.8; }
                           100% { transform:translate(-50%,-50%) scale(3.5); opacity:0;   }
                       }
                 </style>
            </head>
            <body>
                <div id="map"></div>
                <div id="map-loading-overlay">
                    <div class="spinner"></div>
                    <div class="loading-text">Loading OpenStreetMap from the internet, please wait...</div>
                    <div class="loading-error" id="map-loading-error"></div>
                </div>
                <div id="refresh-pulse"></div>
                <div id="agent-status"></div>
                <div id="agent-rejected-overlay">
                    <div class="rejected-box">
                        <div class="rejected-title">&#9888; Server Rejected Submission (HTTP 429)</div>
                        <div class="rejected-msg">The server has reached its maximum agent limit.<br>
                        Ask the server administrator to increase <b>MAX_SERVER_AGENTS</b> and try again.</div>
                    </div>
                </div>
                <div id="map-stats"></div>
                <div id="traffic-histogram">
                    <div class="th-digits">
                        <span class="th-sent" id="th-sent-val">&#9650; 0 B</span><br>
                        <span class="th-recv" id="th-recv-val">&#9660; 0 B</span>
                    </div>
                    <div class="th-bars" id="th-bars"></div>
                </div>
                <div id="map-datetime">
                    <span id="recording-indicator"></span>
                    <span id="datetime-text"></span>
                </div>

                <script>
                    // injectLocalLeaflet(true) => also try local CSS + set marker resources path
                    function injectLocalLeaflet(includeCss) {
                        try {
                            if (includeCss) {
                                if (!document.getElementById('leaflet-local-css')) {
                                    var link = document.createElement('link');
                                    link.rel = 'stylesheet';
                                    link.href = 'resources/leaflet/leaflet.css';
                                    link.id = 'leaflet-local-css';
                                    document.head.appendChild(link);
                                }
                            }
                            if (!document.getElementById('leaflet-local-js')) {
                                var s = document.createElement('script');
                                s.src = 'resources/leaflet/leaflet.js';
                                s.id = 'leaflet-local-js';
                                document.head.appendChild(s);
                            }
                            // expose local resource base for marker fallbacks
                            window._local_leaflet_resources = 'resources/leaflet/';
                        } catch(e) {
                            // ignore: waitForLeaflet will show message if nothing loads
                        }
                    }
                </script>

                <!-- CDN script with onerror fallback to local bundle -->
                <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
                        onerror="try{injectLocalLeaflet(true);}catch(e){}"></script>

                <script>
                    // Try local file first, fall back to remote CDN if local unavailable
                    function resolveImageUrl(remoteUrl, localUrl, cb, timeoutMs) {
                        timeoutMs = timeoutMs || 1000;
                        try {
                            var img = new Image();
                            var done = false;
                            // Try LOCAL first
                            var t = setTimeout(function(){
                                if (done) return;
                                done = true;
                                // Local timed out, try remote
                                tryRemote();
                            }, timeoutMs);
                            img.onload = function(){ 
                                if (done) return; 
                                done = true; 
                                clearTimeout(t); 
                                cb(localUrl);  // Local succeeded!
                            };
                            img.onerror = function(){ 
                                if (done) return; 
                                done = true; 
                                clearTimeout(t); 
                                tryRemote();  // Local failed, try remote
                            };
                            img.src = localUrl;  // Try LOCAL first

                            function tryRemote() {
                                try {
                                    var remoteImg = new Image();
                                    var remoteDone = false;
                                    var remoteTimeout = setTimeout(function(){
                                        if (remoteDone) return;
                                        remoteDone = true;
                                        cb(localUrl);  // Remote also failed, use local path anyway
                                    }, 3000);
                                    remoteImg.onload = function(){
                                        if (remoteDone) return;
                                        remoteDone = true;
                                        clearTimeout(remoteTimeout);
                                        cb(remoteUrl);
                                    };
                                    remoteImg.onerror = function(){
                                        if (remoteDone) return;
                                        remoteDone = true;
                                        clearTimeout(remoteTimeout);
                                        cb(localUrl);  // Both failed, use local path
                                    };
                                    remoteImg.src = remoteUrl;
                                } catch(e) {
                                    cb(localUrl);
                                }
                            }
                        } catch(e) {
                            try { cb(localUrl); } catch(_) {}
                        }
                    }

                    // Wait for Leaflet (L) to be available before initializing map code.
                    // Increased retries/delay for slow/blocked networks and clearer error messages.
                    function waitForLeaflet(cb, retries=200, delay=200) {
                        try {
                            if (typeof L !== 'undefined') { cb(); return; }
                            if (retries <= 0) {
                                var errMsg = 'Leaflet library did not load. Check network or ensure local files exist at resources/leaflet/';
                                try {
                                    var el = document.getElementById('map-stats');
                                    if (el) {
                                        el.innerText = 'Error: ' + errMsg;
                                    }
                                } catch(e){}
                                // Also update loading overlay with failure message
                                try {
                                    var errEl = document.getElementById('map-loading-error');
                                    if (errEl) {
                                        errEl.innerText = 'Failed connecting to the internet and initialize OpenStreetMap with error: ' + errMsg;
                                    }
                                    // Stop the spinner since we know it failed
                                    var spinners = document.querySelectorAll('#map-loading-overlay .spinner');
                                    for (var i = 0; i < spinners.length; i++) { spinners[i].style.display = 'none'; }
                                } catch(e){}
                                return;
                            }
                            setTimeout(function(){ waitForLeaflet(cb, retries-1, delay); }, delay);
                        } catch(e){}
                    }

                    waitForLeaflet(function() {
                        // Initialize QWebChannel for marker click callbacks to Python (async, non-blocking)
                        var mapBridge = null;

                        // Attempt to initialize QWebChannel asynchronously (don't block map initialization)
                        setTimeout(function() {
                            try {
                                if (typeof qt !== 'undefined' && qt.webChannelTransport) {
                                    new QWebChannel(qt.webChannelTransport, function(channel) {
                                        mapBridge = channel.objects.mapBridge;
                                        console.log('[QWebChannel] mapBridge initialized successfully');
                                    });
                                } else {
                                    console.warn('[QWebChannel] qt.webChannelTransport not available - marker clicks will not work');
                                }
                            } catch(e) {
                                console.error('[QWebChannel] Failed to initialize:', e);
                            }
                        }, 100);  // Delay to allow webChannelTransport to become available

                        // Prepare remote and local icon URLs
                        // Determine the script directory for local resources
                        var localBase = 'resources/leaflet/';

                        // Debug: log the local base path
                        console.log('Local resource base:', localBase);

                        var iconsToResolve = {
                            red: {
                                remote: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png',
                                local: localBase + 'marker-icon-2x-red.png'
                            },
                            green: {
                                remote: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png',
                                local: localBase + 'marker-icon-2x-green.png'
                            },
                            blue: {
                                remote: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-blue.png',
                                local: localBase + 'marker-icon-2x-blue.png'
                            },
                            yellow: {
                                remote: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-yellow.png',
                                local: localBase + 'marker-icon-2x-yellow.png'
                            },
                            orange: {
                                remote: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-orange.png',
                                local: localBase + 'marker-icon-2x-orange.png'
                            },
                            violet: {
                                remote: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-violet.png',
                                local: localBase + 'marker-icon-2x-violet.png'
                            },
                            grey: {
                                remote: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-grey.png',
                                local: localBase + 'marker-icon-2x-grey.png'
                            },
                            black: {
                                remote: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-black.png',
                                local: localBase + 'marker-icon-2x-black.png'
                            },
                            gold: {
                                remote: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-gold.png',
                                local: localBase + 'marker-icon-2x-gold.png'
                            }
                        };

                        // Resolve all icon URLs in parallel, then init map
                        var resolved = {};
                        var remaining = Object.keys(iconsToResolve).length;
                        Object.keys(iconsToResolve).forEach(function(k){
                            var info = iconsToResolve[k];
                            resolveImageUrl(info.remote, info.local, function(finalUrl){
                                    resolved[k] = finalUrl;
                                remaining--;
                                if (remaining === 0) {
                                    // create icon definitions using resolved URLs
                                    const iconDefinitions = {
                                        'redIcon':    new L.Icon({iconUrl: resolved.red,    iconSize:[25,41], iconAnchor:[12,41]}),
                                        'greenIcon':  new L.Icon({iconUrl: resolved.green,  iconSize:[25,41], iconAnchor:[12,41]}),
                                        'blueIcon':   new L.Icon({iconUrl: resolved.blue,   iconSize:[25,41], iconAnchor:[12,41]}),
                                        'yellowIcon': new L.Icon({iconUrl: resolved.yellow, iconSize:[25,41], iconAnchor:[12,41]}),
                                        'orangeIcon': new L.Icon({iconUrl: resolved.orange, iconSize:[25,41], iconAnchor:[12,41]}),
                                        'violetIcon': new L.Icon({iconUrl: resolved.violet, iconSize:[25,41], iconAnchor:[12,41]}),
                                        'greyIcon':   new L.Icon({iconUrl: resolved.grey,   iconSize:[25,41], iconAnchor:[12,41]}),
                                        'blackIcon':  new L.Icon({iconUrl: resolved.black,  iconSize:[25,41], iconAnchor:[12,41]}),
                                        'goldIcon':   new L.Icon({iconUrl: resolved.gold,   iconSize:[25,41], iconAnchor:[12,41]}),
                                        'listenIcon': new L.Icon({iconUrl: resolved.orange, iconSize:[25,41], iconAnchor:[12,41]}),
                                    };

                                    // initialize map AFTER icons resolved
                                    console.log('Initializing map with icons:', resolved);

                                    // Use saved map position and zoom if available (injected by Python)
                                    var initialLat = 20;  // Default latitude
                                    var initialLng = 0;   // Default longitude
                                    var initialZoom = 2;  // Default zoom

                                    // Check if saved state was injected
                                    if (typeof window._saved_map_lat !== 'undefined' && 
                                        typeof window._saved_map_lng !== 'undefined' && 
                                        typeof window._saved_map_zoom !== 'undefined') {
                                        // Validate that the values are valid numbers
                                        if (!isNaN(window._saved_map_lat) && !isNaN(window._saved_map_lng) && !isNaN(window._saved_map_zoom)) {
                                            initialLat = window._saved_map_lat;
                                            initialLng = window._saved_map_lng;
                                            initialZoom = window._saved_map_zoom;
                                            console.log('[Map Restore] Restoring saved position:', initialLat, initialLng, 'zoom:', initialZoom);
                                        } else {
                                            console.warn('[Map Restore] Saved values are invalid (NaN), using defaults');
                                        }
                                    } else {
                                        console.log('[Map Restore] No saved position found, using defaults:', initialLat, initialLng, 'zoom:', initialZoom);
                                    }

                                    // Create map instance as global (window.map) so get_map_state() can access it
                                    // Disable double-click zoom so marker double-clicks don't zoom the map
                                    window.map = L.map('map', {doubleClickZoom: false}).setView([initialLat, initialLng], initialZoom);
                                    var map = window.map;  // Local reference for convenience
                                    console.log('Map created successfully at position:', initialLat, initialLng, 'zoom:', initialZoom);

                                    // Create custom pane for public IP circle with high z-index (above markers)
                                    map.createPane('publicIpPane');
                                    map.getPane('publicIpPane').style.zIndex = 650;  // Above markers (600) but below tooltips (700)

                                    // Create custom pane for pinned (yellow) marker so it renders above normal markers
                                    map.createPane('pinnedPane');
                                    map.getPane('pinnedPane').style.zIndex = 640;  // Above markers (600) but below public IP (650)

                                    // Create custom pane for traffic gauges so they render below markers
                                    map.createPane('gaugePane');
                                    map.getPane('gaugePane').style.zIndex = 590;  // Below markers (600)

                                    // Fit-all / reset-view control (bottom-left) — fits map to all markers or resets to world view
                                    var FitAllControl = L.Control.extend({
                                        options: { position: 'bottomleft' },
                                        onAdd: function(map) {
                                            var container = L.DomUtil.create('div', 'leaflet-control-fitall leaflet-bar');
                                            var link = L.DomUtil.create('a', '', container);
                                            link.href = '#';
                                            link.title = 'Fit all markers';
                                            link.innerHTML = '&#x26F6;';  // ⛶  (square four corners)
                                            link.setAttribute('role', 'button');
                                            link.setAttribute('aria-label', 'Fit all markers');
                                            L.DomEvent.disableClickPropagation(container);
                                            L.DomEvent.on(link, 'click', function(e) {
                                                L.DomEvent.preventDefault(e);
                                                try { window._fitAllMarkers(); } catch(ex) { console.error('[FitAll]', ex); }
                                            });
                                            return container;
                                        }
                                    });
                                    map.addControl(new FitAllControl());

                                    // Server/Agent mode indicator control (bottom-left, right of fit-all)
                                    var ModeIndicatorControl = L.Control.extend({
                                        options: { position: 'bottomleft' },
                                        onAdd: function(map) {
                                            var container = L.DomUtil.create('div', 'leaflet-control-modeinfo');
                                            var label = L.DomUtil.create('span', 'mode-label', container);
                                            label.id = 'mode-indicator-label';
                                            return container;
                                        }
                                    });
                                    map.addControl(new ModeIndicatorControl());

                                    // Global helper called by the fit-all button
                                    window._fitAllMarkers = function() {
                                        var bounds = [];
                                        // Iterate over the differential marker map (primary source)
                                        Object.keys(_markerMap).forEach(function(key) {
                                            try {
                                                var m = _markerMap[key].marker;
                                                if (typeof m.getLatLng === 'function') {
                                                    bounds.push(m.getLatLng());
                                                } else if (typeof m.getBounds === 'function') {
                                                    bounds.push(m.getBounds().getCenter());
                                                }
                                            } catch(ex) {}
                                        });
                                        if (bounds.length > 0) {
                                            map.fitBounds(L.latLngBounds(bounds).pad(0.15));
                                        } else {
                                            // No markers — reset to default world view
                                            map.setView([20, 0], 2);
                                        }
                                    };

                                    // Track tile loading success/failure for overlay logic
                                    window._tileHadError = false;
                                    window._tileHadSuccess = false;

                                    L.tileLayer('https://{s}.""" + TILE_OPENSTREETMAP_SERVER + """/{z}/{x}/{y}.png', {
                                        attribution: '&copy; OpenStreetMap contributors'
                                    }).addTo(map)
                                      .on('tileload', function() {
                                          // At least one tile loaded successfully
                                          window._tileHadSuccess = true;
                                      })
                                      .on('load', function() {
                                          // Tile loading queue is empty.
                                          // Only remove overlay if at least one tile succeeded
                                          // and no errors were recorded.
                                          if (window._tileHadSuccess && !window._tileHadError) {
                                              var ov = document.getElementById('map-loading-overlay');
                                              if (ov) { ov.style.display = 'none'; }
                                          }
                                      })
                                      .on('tileerror', function(err) {
                                          window._tileHadError = true;
                                          // A tile failed to load - build a human-readable error message
                                          var msg = 'Could not load map tiles (no internet connection or server unreachable)';
                                          try {
                                              var tileUrl = (err && err.tile && err.tile.src) ? err.tile.src : '';
                                              // Extract just the hostname from the tile URL for a cleaner message
                                              var host = '';
                                              try { host = new URL(tileUrl).hostname; } catch(_) {}
                                              // err.error is a DOM Event, not a JS Error; check its type
                                              var evtType = (err && err.error && err.error.type) ? err.error.type : '';
                                              if (evtType === 'error' && host) {
                                                  msg = 'Could not connect to tile server "' + host + '" (no internet connection or server unreachable)';
                                              } else if (host) {
                                                  msg = 'Failed to load map tile from "' + host + '"' + (evtType ? ' (' + evtType + ')' : '');
                                              }
                                          } catch(e) { /* keep default msg */ }
                                          // Store for the watchdog timer
                                          try { if (window._tileErrorMessages && window._tileErrorMessages.length < 5) { window._tileErrorMessages.push(msg); } } catch(e){}
                                          // Show error on the overlay immediately and keep it visible
                                          var ov = document.getElementById('map-loading-overlay');
                                          if (ov) { ov.style.display = ''; }
                                          var errEl = document.getElementById('map-loading-error');
                                          if (errEl) {
                                              errEl.innerText = 'Failed connecting to the internet and initialize OpenStreetMap with error: ' + msg;
                                          }
                                          // Stop spinner on first error
                                          try {
                                              var spinners = document.querySelectorAll('#map-loading-overlay .spinner');
                                              for (var i = 0; i < spinners.length; i++) { spinners[i].style.display = 'none'; }
                                          } catch(e){}
                                      });
                                    console.log('Tile layer added successfully');

                                    var liveMarkers = [];
                                    // Differential update state: keyed marker map for in-place updates
                                    // Key: stable connection identifier string
                                    // Value: { marker, gaugeMarker, conn (last data), iconName }
                                    var _markerMap = {};
                                    // Separate array for polylines (cheap to rebuild each cycle)
                                    var _liveLines = [];
                                    var _liveLinesFP = '';  // fingerprint of last polyline set; skip rebuild when unchanged

                                    // Helper: format byte count to human-readable string
                                    function _formatBytes(bytes) {
                                        if (bytes === 0) return '0 B';
                                        var k = 1024;
                                        var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                                        var i = Math.floor(Math.log(bytes) / Math.log(k));
                                        if (i >= sizes.length) i = sizes.length - 1;
                                        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
                                    }

                                    // Build a stable unique key for a connection object.
                                    // For special markers (redCircle, agentCircle) use their type + coords.
                                    // For regular markers use process+pid+protocol+local+localport+remote_raw+remoteport.
                                    function _connKey(conn) {
                                        var icon = conn.icon || 'greenIcon';
                                        if (icon === 'redCircle') {
                                            return '_publicip_' + conn.lat + '_' + conn.lng;
                                        }
                                        if (icon === 'agentCircle') {
                                            return '_agent_' + (conn.origin_hostname || conn.name || '') + '_' + conn.lat + '_' + conn.lng;
                                        }
                                        // Strip DNS enrichment from remote for stable keying
                                        var rawRemote = (conn.remote || '').split(' (')[0];
                                        return (conn.process || '') + '|' + (conn.pid || '') + '|' +
                                               (conn.protocol || 'TCP') + '|' + (conn.local || '') + '|' +
                                               (conn.localport || '') + '|' + rawRemote + '|' +
                                               (conn.remoteport || '') + '|' + (conn.origin_hostname || '');
                                    }

                                    // Build popup HTML for a regular marker
                                    function _buildPopupHtml(conn) {
                                        var isListen = (conn.state === 'LISTEN');
                                        var isInbound = !!conn.inbound;
                                        var html = "<b>" + (conn.process || '') + "</b><br>";
                                        if (isListen) {
                                            html += "<span style='background:#ff9800;color:#fff;padding:1px 6px;border-radius:4px;font-size:11px'>&#128266; Listening Socket</span><br>";
                                        }
                                        if (isInbound) {
                                            html += "<span style='background:#d32f2f;color:#fff;padding:1px 6px;border-radius:4px;font-size:11px'>&#8592; Inbound Connection</span><br>";
                                        }
                                        html += "Protocol: " + (conn.protocol || 'TCP') + "<br>" +
                                                   "PID: " + (conn.pid || '') + "<br>" +
                                                   "Remote: " + (conn.remote || '') + "<br>" +
                                                   "Local: " + (conn.local || '') + ":" + (conn.localport || '') + "<br>" +
                                                   (conn.name ? "Name: " + conn.name + "<br>" : "") +
                                                   (conn.origin_hostname ? "Source: " + conn.origin_hostname + "<br>" : "");
                                        var bSent = conn.bytes_sent || 0;
                                        var bRecv = conn.bytes_recv || 0;
                                        if (bSent > 0 || bRecv > 0) {
                                            html += "<hr style='margin:4px 0'>" +
                                                    "<span style='color:#d32f2f'>&#9650; Sent:</span> " + _formatBytes(bSent) + "<br>" +
                                                    "<span style='color:#388e3c'>&#9660; Recv:</span> " + _formatBytes(bRecv) + "<br>";
                                        }
                                        return html;
                                    }

                                    function updateConnections(conns, showTooltip, drawLines, showGauge, pulseExitPoints) {
                                        if (!conns || !Array.isArray(conns)) {
                                            // No data — remove everything
                                            window._removingMarkers = true;
                                            Object.keys(_markerMap).forEach(function(k) {
                                                var entry = _markerMap[k];
                                                try { entry.marker.off('popupclose'); } catch(e) {}
                                                try { map.removeLayer(entry.marker); } catch(e) {}
                                                if (entry.gaugeMarker) { try { map.removeLayer(entry.gaugeMarker); } catch(e) {} }
                                                if (entry.pulseMarker) { try { map.removeLayer(entry.pulseMarker); } catch(e) {} }
                                            });
                                            _markerMap = {};
                                            window._removingMarkers = false;
                                            // Also clear legacy liveMarkers for any leftover refs
                                            for (var i=0; i<liveMarkers.length; i++) {
                                                try { map.removeLayer(liveMarkers[i]); } catch(e) {}
                                            }
                                            liveMarkers = [];
                                            for (var j=0; j<_liveLines.length; j++) {
                                                try { map.removeLayer(_liveLines[j]); } catch(e) {}
                                            }
                                            _liveLines = [];
                                            _liveLinesFP = '';
                                            return;
                                        }

                                        // Pre-compute maximum sent and received bytes across all connections for gauge scaling
                                        var maxSent = 1;
                                        var maxRecv = 1;
                                        if (showGauge) {
                                            conns.forEach(function(c) {
                                                var s = c.bytes_sent || 0;
                                                var r = c.bytes_recv || 0;
                                                if (s > maxSent) maxSent = s;
                                                if (r > maxRecv) maxRecv = r;
                                            });
                                        }

                                        // --- Phase 1: Build incoming key set and index ---
                                        var incomingKeys = {};
                                        conns.forEach(function(conn) {
                                            if (conn.lat && conn.lng) {
                                                var key = _connKey(conn);
                                                incomingKeys[key] = conn;
                                            }
                                        });

                                        // --- Phase 2: Remove markers no longer present ---
                                        window._removingMarkers = true;
                                        Object.keys(_markerMap).forEach(function(key) {
                                            if (!incomingKeys[key]) {
                                                var entry = _markerMap[key];
                                                try { entry.marker.off('popupclose'); } catch(e) {}
                                                try { map.removeLayer(entry.marker); } catch(e) {}
                                                 if (entry.gaugeMarker) { try { map.removeLayer(entry.gaugeMarker); } catch(e) {} }
                                                 if (entry.pulseMarker) { try { map.removeLayer(entry.pulseMarker); } catch(e) {} }
                                                 delete _markerMap[key];
                                            }
                                        });
                                        window._removingMarkers = false;

                                        // --- Phase 3: Defer polyline removal (see Phase 5) ---
                                        // Also clear any legacy liveMarkers that were polylines from before the diff upgrade
                                        for (var lmi = 0; lmi < liveMarkers.length; lmi++) {
                                            try { map.removeLayer(liveMarkers[lmi]); } catch(e) {}
                                        }
                                        liveMarkers = [];

                                        var publicIpCoords = null;
                                        var agentOriginCoords = {};
                                        var agentOriginColors = {};
                                        var serverMarkerCoords = [];
                                        var agentMarkerCoords = {};

                                        // --- Phase 4: Add new markers / update existing ones ---
                                        Object.keys(incomingKeys).forEach(function(key) {
                                            var conn = incomingKeys[key];
                                            var iconName = conn.icon || 'greenIcon';
                                            var existing = _markerMap[key];

                                            if (iconName === 'redCircle') {
                                                publicIpCoords = [conn.lat, conn.lng];
                                                if (existing) {
                                                     // Already on map — update tooltip if remote changed
                                                     try {
                                                         existing.marker.unbindTooltip();
                                                         existing.marker.bindTooltip(conn.remote || 'Public IP', { permanent: !!showTooltip, opacity: 0.9, direction: 'auto' });
                                                     } catch(e) {}
                                                     if (pulseExitPoints) {
                                                         existing.pulseMarker = _applyExitPulse(existing.marker, 'red', 'publicIpPane', existing.pulseMarker || null);
                                                     } else if (existing.pulseMarker) {
                                                         try { map.removeLayer(existing.pulseMarker); } catch(e) {}
                                                         existing.pulseMarker = null;
                                                     }
                                                     existing.conn = conn;
                                                } else {
                                                    var circle = L.circle([conn.lat, conn.lng], {
                                                        color: 'red', fillColor: '#f03', fillOpacity: 0.5,
                                                        radius: 100000, pane: 'publicIpPane'
                                                    }).addTo(map);
                                                    circle.bindTooltip(conn.remote || 'Public IP', { permanent: !!showTooltip, opacity: 0.9, direction: 'auto' });
                                                    circle.bindPopup("<b>Server Public IP</b><br>IP: " + (conn.remote || '') + "<br>", {autoClose: false, closeOnClick: false});
                                                    try { circle.off('click', circle._openPopup); } catch(e) {}
                                                    (function(c) {
                                                        c.on('click', function(e) {
                                                            try {
                                                                if (c.isPopupOpen()) { c.closePopup(); }
                                                                else { c.openPopup(); }
                                                            } catch(ex) {}
                                                        });
                                                    })(circle);
                                                     var rPulse = pulseExitPoints ? _applyExitPulse(circle, 'red', 'publicIpPane', null) : null;
                                                     _markerMap[key] = { marker: circle, gaugeMarker: null, conn: conn, iconName: iconName, pulseMarker: rPulse };
                                                }

                                            } else if (iconName === 'agentCircle') {
                                                var agentColor = conn.agent_color || 'orange';
                                                var agentFillColors = {
                                                    orange: '#ff8c00', violet: '#9c2bcb',
                                                    grey: '#7b7b7b', black: '#3d3d3d', gold: '#ffd326'
                                                };
                                                var fillColor = agentFillColors[agentColor] || agentColor;
                                                var agentHostname = conn.origin_hostname || conn.name || '';
                                                var agentPaneName = agentHostname
                                                    ? 'agentPane_' + agentHostname.replace(/[^a-zA-Z0-9]/g, '_')
                                                    : 'publicIpPane';
                                                var agentPaneZ = (typeof conn.pane_z === 'number') ? conn.pane_z : 620;
                                                if (agentHostname && !map.getPane(agentPaneName)) {
                                                    map.createPane(agentPaneName);
                                                    map.getPane(agentPaneName).style.zIndex = agentPaneZ;
                                                }

                                                if (existing) {
                                                     // Update color if changed
                                                     try {
                                                         existing.marker.setStyle({ color: agentColor, fillColor: fillColor });
                                                         existing.marker.unbindTooltip();
                                                         existing.marker.bindTooltip(conn.remote || 'Agent', { permanent: !!showTooltip, opacity: 0.9, direction: 'auto' });
                                                         if (pulseExitPoints) {
                                                             existing.pulseMarker = _applyExitPulse(existing.marker, agentColor, agentHostname ? agentPaneName : 'publicIpPane', existing.pulseMarker || null);
                                                         } else if (existing.pulseMarker) {
                                                             try { map.removeLayer(existing.pulseMarker); } catch(e) {}
                                                             existing.pulseMarker = null;
                                                         }
                                                     } catch(e) {}
                                                     // Update pane z-index if changed
                                                    try {
                                                        var pane = map.getPane(agentPaneName);
                                                        if (pane) pane.style.zIndex = agentPaneZ;
                                                    } catch(e) {}
                                                    existing.conn = conn;
                                                } else {
                                                    var agentCircle = L.circle([conn.lat, conn.lng], {
                                                         color: agentColor, fillColor: fillColor, fillOpacity: 0.5,
                                                         radius: 80000, pane: agentHostname ? agentPaneName : 'publicIpPane'
                                                     }).addTo(map);
                                                     var agPulse = pulseExitPoints ? _applyExitPulse(agentCircle, agentColor, agentHostname ? agentPaneName : 'publicIpPane', null) : null;
                                                     agentCircle.bindTooltip(conn.remote || 'Agent', { permanent: !!showTooltip, opacity: 0.9, direction: 'auto' });
                                                    var agPopupHtml = "<b>Agent Exit Point</b><br>" +
                                                                      (conn.remote || '') + "<br>" +
                                                                      "Hostname: " + (conn.name || '') + "<br>" +
                                                                      "<i style='font-size:11px;color:#555'>Click to bring to foreground</i>";
                                                    agentCircle.bindPopup(agPopupHtml, {autoClose: false, closeOnClick: false});
                                                    try { agentCircle.off('click', agentCircle._openPopup); } catch(e) {}
                                                    (function(hostName, ac) {
                                                        ac.on('click', function(e) {
                                                            try {
                                                                if (ac.isPopupOpen()) { ac.closePopup(); }
                                                                else { ac.openPopup(); }
                                                                if (mapBridge && typeof mapBridge.setForegroundHost === 'function') {
                                                                    mapBridge.setForegroundHost(hostName);
                                                                }
                                                            } catch(ex) {}
                                                        });
                                                    })(agentHostname, agentCircle);
                                                    _markerMap[key] = { marker: agentCircle, gaugeMarker: null, conn: conn, iconName: iconName, pulseMarker: agPulse };
                                                }

                                                if (agentHostname) {
                                                    agentOriginCoords[agentHostname] = [conn.lat, conn.lng];
                                                    agentOriginColors[agentHostname] = agentColor;
                                                }

                                            } else {
                                                // --- Regular marker ---
                                                var isNewConn = (iconName === 'blueIcon');
                                                var tooltipText = (conn.process || '') + ' [' + (conn.protocol || 'TCP') + ']';
                                                if (conn.origin_hostname) { tooltipText += ' @' + conn.origin_hostname; }

                                                if (existing) {
                                                    // --- UPDATE existing marker in-place ---
                                                    var m = existing.marker;

                                                    // Update icon if changed (e.g. green→blue→yellow→grey)
                                                    if (existing.iconName !== iconName) {
                                                        var newIcon = iconDefinitions[iconName] || iconDefinitions['greenIcon'];
                                                        try { m.setIcon(newIcon); } catch(e) {}
                                                        // Move to/from pinned pane if needed
                                                        if (iconName === 'yellowIcon' && m.options.pane !== 'pinnedPane') {
                                                            // Leaflet doesn't support changing pane in-place; must re-add
                                                            try { map.removeLayer(m); } catch(e) {}
                                                            m.options.pane = 'pinnedPane';
                                                            m.addTo(map);
                                                        } else if (existing.iconName === 'yellowIcon' && iconName !== 'yellowIcon') {
                                                            try { map.removeLayer(m); } catch(e) {}
                                                            delete m.options.pane;
                                                            m.addTo(map);
                                                        }
                                                        existing.iconName = iconName;
                                                    }

                                                    // Update tooltip (permanent state may change with showTooltip or new-conn)
                                                    try {
                                                        m.unbindTooltip();
                                                        m.bindTooltip(tooltipText, { permanent: (!!showTooltip || isNewConn), opacity: 0.9, direction: 'auto' });
                                                    } catch(e) {}

                                                    // Update popup content (bytes change each cycle)
                                                    try {
                                                        m.setPopupContent(_buildPopupHtml(conn));
                                                    } catch(e) {
                                                        // If no popup bound yet, bind one
                                                        try { m.bindPopup(_buildPopupHtml(conn), {autoClose: false, closeOnClick: false}); } catch(e2) {}
                                                    }

                                                    // Update gauge marker in-place (setIcon avoids remove+add blink)
                                                    var bSent = conn.bytes_sent || 0;
                                                    var bRecv = conn.bytes_recv || 0;
                                                    if (showGauge && (bSent > 0 || bRecv > 0)) {
                                                        var gaugeHeight = 40;
                                                        var sentH = Math.round((bSent / maxSent) * (gaugeHeight / 2));
                                                        var recvH = Math.round((bRecv / maxRecv) * (gaugeHeight / 2));
                                                        var emptyH = gaugeHeight - sentH - recvH;
                                                        var gaugeHtml = '<div class="traffic-gauge" style="height:' + gaugeHeight + 'px" title="Sent: ' + _formatBytes(bSent) + ' / Recv: ' + _formatBytes(bRecv) + '">' +
                                                                        '<div class="tg-empty" style="height:' + emptyH + 'px;"></div>' +
                                                                        '<div class="tg-recv" style="height:' + recvH + 'px;"></div>' +
                                                                        '<div class="tg-sent" style="height:' + sentH + 'px;"></div>' +
                                                                        '</div>';
                                                        var gaugeIcon = L.divIcon({
                                                            className: 'traffic-gauge-icon', html: gaugeHtml,
                                                            iconSize: [12, gaugeHeight + 2], iconAnchor: [-8, gaugeHeight]
                                                        });
                                                        if (existing.gaugeMarker) {
                                                            existing.gaugeMarker.setIcon(gaugeIcon);
                                                        } else {
                                                            existing.gaugeMarker = L.marker([conn.lat, conn.lng], {
                                                                icon: gaugeIcon, interactive: false, pane: 'gaugePane'
                                                            }).addTo(map);
                                                        }
                                                    } else if (existing.gaugeMarker) {
                                                        try { map.removeLayer(existing.gaugeMarker); } catch(e) {}
                                                        existing.gaugeMarker = null;
                                                    }

                                                    // Handle autoPopup for pinned connection
                                                    if (conn.autoPopup) {
                                                        try { m.openPopup(); } catch(e) {}
                                                        (function(gen, mk) {
                                                            mk.off('popupclose');
                                                            mk.on('popupclose', function() {
                                                                if (!window._removingMarkers) {
                                                                    try {
                                                                        if (mapBridge && typeof mapBridge.notifyPopupClosed === 'function') {
                                                                            mapBridge.notifyPopupClosed(gen);
                                                                        }
                                                                    } catch(e) {}
                                                                }
                                                            });
                                                        })(conn.popupGeneration || 0, m);
                                                    }

                                                    existing.conn = conn;

                                                } else {
                                                    // --- CREATE new marker ---
                                                    var icon = iconDefinitions[iconName] || iconDefinitions['greenIcon'];
                                                    var markerOptions = { icon: icon };
                                                    if (iconName === 'yellowIcon') { markerOptions.pane = 'pinnedPane'; }
                                                    var marker = L.marker([conn.lat, conn.lng], markerOptions).addTo(map);
                                                    marker.bindTooltip(tooltipText, { permanent: (!!showTooltip || isNewConn), opacity: 0.9, direction: 'auto' });
                                                    marker.bindPopup(_buildPopupHtml(conn), {autoClose: false, closeOnClick: false});

                                                    // Traffic gauge
                                                    var gm = null;
                                                    var bSent2 = conn.bytes_sent || 0;
                                                    var bRecv2 = conn.bytes_recv || 0;
                                                    if (showGauge && (bSent2 > 0 || bRecv2 > 0)) {
                                                        var gh = 40;
                                                        var sH = Math.round((bSent2 / maxSent) * (gh / 2));
                                                        var rH = Math.round((bRecv2 / maxRecv) * (gh / 2));
                                                        var eH = gh - sH - rH;
                                                        var gHtml = '<div class="traffic-gauge" style="height:' + gh + 'px" title="Sent: ' + _formatBytes(bSent2) + ' / Recv: ' + _formatBytes(bRecv2) + '">' +
                                                                    '<div class="tg-empty" style="height:' + eH + 'px;"></div>' +
                                                                    '<div class="tg-recv" style="height:' + rH + 'px;"></div>' +
                                                                    '<div class="tg-sent" style="height:' + sH + 'px;"></div>' +
                                                                    '</div>';
                                                        var gIcon = L.divIcon({
                                                            className: 'traffic-gauge-icon', html: gHtml,
                                                            iconSize: [12, gh + 2], iconAnchor: [-8, gh]
                                                        });
                                                        gm = L.marker([conn.lat, conn.lng], {
                                                            icon: gIcon, interactive: false, pane: 'gaugePane'
                                                        }).addTo(map);
                                                    }

                                                    // Click handler
                                                    (function(connection, m) {
                                                        m.on('click', function(e) {
                                                            try {
                                                                m.closePopup();
                                                                m.off('popupclose');
                                                                if (mapBridge && typeof mapBridge.pinConnection === 'function') {
                                                                    mapBridge.pinConnection(
                                                                        connection.process || '', connection.pid || '',
                                                                        connection.protocol || 'TCP', connection.local || '',
                                                                        connection.localport || '', connection.remote || '',
                                                                        connection.remoteport || '', connection.ip_type || ''
                                                                    );
                                                                }
                                                                var markerHost = connection.origin_hostname || connection.hostname || '';
                                                                if (markerHost && mapBridge && typeof mapBridge.setForegroundHost === 'function') {
                                                                    mapBridge.setForegroundHost(markerHost);
                                                                }
                                                            } catch(e) {}
                                                        });
                                                    })(conn, marker);

                                                    // Auto-open popup for pinned connection
                                                    if (conn.autoPopup) {
                                                        marker.openPopup();
                                                        (function(gen) {
                                                            marker.on('popupclose', function() {
                                                                if (!window._removingMarkers) {
                                                                    try {
                                                                        if (mapBridge && typeof mapBridge.notifyPopupClosed === 'function') {
                                                                            mapBridge.notifyPopupClosed(gen);
                                                                        }
                                                                    } catch(e) {}
                                                                }
                                                            });
                                                        })(conn.popupGeneration || 0);
                                                    }

                                                    _markerMap[key] = { marker: marker, gaugeMarker: gm, conn: conn, iconName: iconName };
                                                }

                                                // Classify for line drawing
                                                var connOrigin = conn.origin_hostname || '';
                                                if (connOrigin) {
                                                    if (!agentMarkerCoords[connOrigin]) { agentMarkerCoords[connOrigin] = []; }
                                                    agentMarkerCoords[connOrigin].push([conn.lat, conn.lng]);
                                                } else {
                                                    serverMarkerCoords.push({coords: [conn.lat, conn.lng], isListen: (conn.state === 'LISTEN'), isInbound: !!conn.inbound});
                                                }
                                            }
                                        });

                                        // --- Phase 5: Draw lines only when endpoints change ---
                                        // Build a fingerprint of the line endpoints so we can skip
                                        // the expensive remove-all / add-all cycle when nothing moved.
                                        var newFP = '';
                                        if (drawLines) {
                                            var fpParts = [];
                                            if (publicIpCoords) fpParts.push('P' + publicIpCoords[0] + ',' + publicIpCoords[1]);
                                            serverMarkerCoords.forEach(function(s) { fpParts.push('S' + s.coords[0] + ',' + s.coords[1] + (s.isListen ? 'L' : '') + (s.isInbound ? 'I' : '')); });
                                            Object.keys(agentOriginCoords).sort().forEach(function(h) {
                                                var o = agentOriginCoords[h];
                                                fpParts.push('A' + h + ':' + o[0] + ',' + o[1]);
                                                (agentMarkerCoords[h] || []).forEach(function(c) { fpParts.push('M' + h + ':' + c[0] + ',' + c[1]); });
                                            });
                                            newFP = fpParts.join('|');
                                        }
                                        if (newFP !== _liveLinesFP) {
                                            // Fingerprint changed — tear down old lines and rebuild
                                            for (var li = 0; li < _liveLines.length; li++) {
                                                try { map.removeLayer(_liveLines[li]); } catch(e) {}
                                            }
                                            _liveLines = [];
                                            _liveLinesFP = newFP;
                                            if (drawLines) {
                                                if (publicIpCoords && serverMarkerCoords.length > 0) {
                                                    serverMarkerCoords.forEach(function(s) {
                                                        var lineColor = (s.isListen || s.isInbound) ? 'red' : 'blue';
                                                        var polyline = L.polyline([publicIpCoords, s.coords], {
                                                            color: lineColor, weight: 2, opacity: 0.6, dashArray: '5, 10'
                                                        }).addTo(map);
                                                        _liveLines.push(polyline);
                                                    });
                                                }
                                                Object.keys(agentOriginCoords).forEach(function(hostname) {
                                                    var originCoords = agentOriginCoords[hostname];
                                                    var lineColor = agentOriginColors[hostname] || 'orange';
                                                    var markers = agentMarkerCoords[hostname] || [];
                                                    markers.forEach(function(markerCoords) {
                                                        var polyline = L.polyline([originCoords, markerCoords], {
                                                            color: lineColor, weight: 2, opacity: 0.6, dashArray: '5, 10'
                                                        }).addTo(map);
                                                        _liveLines.push(polyline);
                                                    });
                                                });
                                                if (publicIpCoords) {
                                                    Object.keys(agentMarkerCoords).forEach(function(hostname) {
                                                        if (!agentOriginCoords[hostname]) {
                                                            agentMarkerCoords[hostname].forEach(function(markerCoords) {
                                                                var polyline = L.polyline([publicIpCoords, markerCoords], {
                                                                    color: 'gray', weight: 1, opacity: 0.4, dashArray: '3, 8'
                                                                }).addTo(map);
                                                                _liveLines.push(polyline);
                                                            });
                                                        }
                                                    });
                                                }
                                            }
                                        }
                                    }

                                    function setStats(s) {
                                        try {
                                            var el = document.getElementById('map-stats');
                                            if (el) { el.innerText = s || ''; }
                                        } catch(e) {}
                                    }

                                    function setDateTime(dt) {
                                        try {
                                            var el = document.getElementById('datetime-text');
                                            if (el) { el.innerText = dt || ''; }
                                        } catch(e) {}
                                    }

                                    function setRecordingIndicator(isRecording) {
                                        try {
                                            var indicator = document.getElementById('recording-indicator');
                                            if (indicator) {
                                                indicator.style.display = isRecording ? 'block' : 'none';
                                            }
                                        } catch(e) {}
                                    }

                                    // Create / update a CSS-animated pulse ring overlay on top of an
                                     // L.circle exit-point marker.  Returns the L.marker so callers can
                                     // store it (e.g. in _markerMap.pulseMarker).
                                     // existingPulse: previous pulse L.marker to reuse (or null).
                                     function _applyExitPulse(leafletCircle, color, paneName, existingPulse) {
                                         try {
                                             var latlng = leafletCircle.getLatLng();
                                             var pulseHtml = '<div style="position:relative;width:0;height:0;">' +
                                                 '<div class="exit-pulse-ring" style="color:' + (color || 'red') + ';"></div></div>';
                                             var pulseIcon = L.divIcon({ className: 'exit-pulse-icon', html: pulseHtml, iconSize: [0, 0], iconAnchor: [0, 0] });
                                             if (existingPulse) {
                                                 existingPulse.setLatLng(latlng);
                                                 existingPulse.setIcon(pulseIcon);
                                                 return existingPulse;
                                             }
                                             var opts = { icon: pulseIcon, interactive: false };
                                             if (paneName) opts.pane = paneName;
                                             var pm = L.marker(latlng, opts).addTo(map);
                                             return pm;
                                         } catch(e) { console.warn('[exitPulse]', e); return existingPulse; }
                                     }

                                    function triggerPulse() {
                                        try {
                                            var pulse = document.getElementById('refresh-pulse');
                                            if (pulse) {
                                                // Remove class to reset animation if already running
                                                pulse.classList.remove('active');
                                                // Force reflow to restart animation
                                                void pulse.offsetWidth;
                                                // Add class to trigger animation
                                                pulse.classList.add('active');
                                                // Remove class after animation completes (800ms)
                                                setTimeout(function() {
                                                    pulse.classList.remove('active');
                                                }, 800);
                                            }
                                        } catch(e) {
                                            console.error('[Pulse] Error triggering pulse:', e);
                                        }
                                    }

                                    // expose to the host Python code
                                    window.updateConnections = updateConnections;
                                    window.setStats = setStats;
                                    window.setDateTime = setDateTime;
                                    window.setRecordingIndicator = setRecordingIndicator;

                                    function setModeIndicator(text) {
                                        try {
                                            var el = document.getElementById('mode-indicator-label');
                                            if (el) {
                                                if (text) {
                                                    el.innerText = text;
                                                    el.className = 'mode-label active';
                                                } else {
                                                    el.innerText = '';
                                                    el.className = 'mode-label';
                                                }
                                            }
                                        } catch(e) {}
                                    }
                                    window.setModeIndicator = setModeIndicator;

                                    function setRejectedOverlay(show) {
                                        try {
                                            var ov = document.getElementById('agent-rejected-overlay');
                                            if (ov) {
                                                ov.className = show ? 'active' : '';
                                            }
                                        } catch(e) {}
                                    }
                                    window.setRejectedOverlay = setRejectedOverlay;

                                    function setAgentStatus(text) {
                                        try {
                                            var el = document.getElementById('agent-status');
                                            if (el) {
                                                if (text) {
                                                    el.innerText = text;
                                                    el.className = 'active';
                                                } else {
                                                    el.innerText = '';
                                                    el.className = '';
                                                }
                                            }
                                        } catch(e) {}
                                    }
                                    window.setAgentStatus = setAgentStatus;

                                    // --- Traffic histogram (rolling horizontal bars, newest at top) ---
                                    var _thSentHistory = [];
                                    var _thRecvHistory = [];
                                    var _TH_MAX_BARS = """ + str(MAX_TRAFFIC_HISTOGRAM_BARS) + r""";

                                    function _thFormatBytes(b) {
                                        if (b <= 0) return '0 B';
                                        var units = ['B','KB','MB','GB','TB'];
                                        var i = 0;
                                        var v = b;
                                        while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
                                        return (i === 0 ? v : v.toFixed(1)) + ' ' + units[i];
                                    }

                                    function updateTrafficHistogram(totalSent, totalRecv, visible) {
                                        try {
                                            var wrapper = document.getElementById('traffic-histogram');
                                            if (!wrapper) return;
                                            if (!visible) { wrapper.classList.add('th-hidden'); return; }
                                            wrapper.classList.remove('th-hidden');

                                            // New bar at front (top); oldest popped from end (bottom)
                                            _thSentHistory.unshift(totalSent || 0);
                                            _thRecvHistory.unshift(totalRecv || 0);
                                            if (_thSentHistory.length > _TH_MAX_BARS) { _thSentHistory.pop(); _thRecvHistory.pop(); }

                                            // Update digit labels
                                            var sentEl = document.getElementById('th-sent-val');
                                            var recvEl = document.getElementById('th-recv-val');
                                            if (sentEl) sentEl.innerHTML = '&#9650; ' + _thFormatBytes(totalSent || 0);
                                            if (recvEl) recvEl.innerHTML = '&#9660; ' + _thFormatBytes(totalRecv || 0);

                                            // Find peak for scaling
                                            var peak = 1;
                                            for (var i = 0; i < _thSentHistory.length; i++) {
                                                var sum = _thSentHistory[i] + _thRecvHistory[i];
                                                if (sum > peak) peak = sum;
                                            }

                                            // Render horizontal bars (each row = one collection pass, newest first)
                                            var container = document.getElementById('th-bars');
                                            if (!container) return;
                                            // Use the fixed outer wrapper width minus th-bars padding (2px each side)
                                            // so barW never drifts as bars themselves change size.
                                            var thWrapper = document.getElementById('traffic-histogram');
                                            var barW = Math.max((thWrapper ? thWrapper.offsetWidth : 120) - 4, 20);
                                            var html = '';
                                            for (var j = 0; j < _thSentHistory.length; j++) {
                                                var s = _thSentHistory[j];
                                                var r = _thRecvHistory[j];
                                                var sPx = peak > 0 ? Math.max(Math.round((s / peak) * barW), (s > 0 ? 1 : 0)) : 0;
                                                var rPx = peak > 0 ? Math.max(Math.round((r / peak) * barW), (r > 0 ? 1 : 0)) : 0;
                                                html += '<div class="th-bar-row"><div class="th-s" style="width:' + sPx + 'px"></div><div class="th-r" style="width:' + rPx + 'px"></div></div>';
                                            }
                                            container.innerHTML = html;
                                        } catch(e) { console.error('[TrafficHistogram]', e); }
                                    }
                                    window.updateTrafficHistogram = updateTrafficHistogram;

                                    window.triggerPulse = triggerPulse;

                                    // Notify Python that map is fully initialized
                                    console.log('[Map Init] Notifying Python that map is ready');
                                    try {
                                        // Only remove overlay here if tiles loaded without errors
                                        // (tileerror handler keeps it visible when there are failures)
                                        if (!window._tileHadError) {
                                            var loadOv = document.getElementById('map-loading-overlay');
                                            if (loadOv) { loadOv.style.display = 'none'; }
                                        }

                                        // Call a Python-registered callback to signal map is ready
                                        if (typeof window.qt !== 'undefined' && window.qt.webChannelTransport) {
                                            // QWebChannel is available (not used here, but could be)
                                        }
                                        // Set a flag that Python can check
                                        window._map_ready = true;
                                        console.log('[Map Init] window._map_ready set to true');
                                    } catch(e) {
                                        console.error('[Map Init] Error notifying Python:', e);
                                    }
                                }
                            }, 3000);
                        });
                    });

                    // Watchdog: if the map has not initialized within 45 seconds, show error on overlay
                    window._tileErrorMessages = [];
                    setTimeout(function() {
                        try {
                            if (window._map_ready) { return; } // map loaded fine
                            var ov = document.getElementById('map-loading-overlay');
                            if (ov && ov.style.display !== 'none') {
                                var errEl = document.getElementById('map-loading-error');
                                if (errEl && !errEl.innerText) {
                                    var detail = 'Timed out waiting for map tiles to load (no internet connectivity?)';
                                    if (window._tileErrorMessages && window._tileErrorMessages.length > 0) {
                                        detail = window._tileErrorMessages[0];
                                    }
                                    errEl.innerText = 'Failed connecting to the internet and initialize OpenStreetMap with error: ' + detail;
                                }
                                // Stop spinner
                                var spinners = document.querySelectorAll('#map-loading-overlay .spinner');
                                for (var i = 0; i < spinners.length; i++) { spinners[i].style.display = 'none'; }
                            }
                        } catch(e) {}
                    }, 45000);
                </script>
            </body>
            </html>
            """
            # Inject the script directory path into the HTML so JS can build absolute file:// URLs
            # Use "about:blank" as base URL to allow external HTTPS resources (OSM tiles, CDN)
            import pathlib
            from PySide6.QtCore import QUrl

            script_dir = pathlib.Path(__file__).parent.resolve()
            # Convert Windows backslashes to forward slashes and build file:// URL
            local_resources_path = str(script_dir / "resources" / "leaflet").replace("\\", "/")

            # Debug: log the path being injected
            logging.debug(f"Injecting local resources path: file:///{local_resources_path}/")

            # Inject the local path into JavaScript (for both markers AND Leaflet library)
            html_with_path = html_content.replace(
                "var localBase = 'resources/leaflet/';",
                f"var localBase = 'file:///{local_resources_path}/';"
            )

            # Also inject absolute paths for Leaflet CSS and JS in injectLocalLeaflet function
            html_with_path = html_with_path.replace(
                "link.href = 'resources/leaflet/leaflet.css';",
                f"link.href = 'file:///{local_resources_path}/leaflet.css';"
            )
            html_with_path = html_with_path.replace(
                "s.src = 'resources/leaflet/leaflet.js';",
                f"s.src = 'file:///{local_resources_path}/leaflet.js';"
            )

            # Debug: verify the replacement worked
            if "file:///" in html_with_path:
                logging.debug("Path injection successful")
            else:
                logging.warning("Path injection may have failed!")

            # Inject saved map state into JavaScript as window variables (with validation)
            map_state_js = ""
            if (hasattr(self, 'saved_map_center_lat') and 
                hasattr(self, 'saved_map_center_lng') and 
                hasattr(self, 'saved_map_zoom') and
                self.saved_map_center_lat is not None and 
                self.saved_map_center_lng is not None and 
                self.saved_map_zoom is not None):
                try:
                    # Double-check values are valid numbers before injecting
                    lat_val = float(self.saved_map_center_lat)
                    lng_val = float(self.saved_map_center_lng)
                    zoom_val = float(self.saved_map_zoom)

                    map_state_js = f"""
                    <script>
                        // Inject saved map state for restoration
                        window._saved_map_lat = {lat_val};
                        window._saved_map_lng = {lng_val};
                        window._saved_map_zoom = {zoom_val};
                        console.log('[Map Restore] Using saved position:', window._saved_map_lat, window._saved_map_lng, 'zoom:', window._saved_map_zoom);
                    </script>
                    """
                    logging.info(f"Injecting map state into HTML: center=({lat_val}, {lng_val}), zoom={zoom_val}")
                except (ValueError, TypeError) as e:
                    logging.warning(f"Failed to inject map state: {e}")
                    map_state_js = ""
            else:
                logging.debug("No saved map state to inject (using default position)")

            # Try to read local Leaflet files for offline support
            leaflet_js_content = ""
            leaflet_css_content = ""

            try:
                # Read local Leaflet JavaScript
                leaflet_js_path = script_dir / "resources" / "leaflet" / "leaflet.js"
                if leaflet_js_path.exists():
                    with open(leaflet_js_path, 'r', encoding='utf-8') as f:
                        leaflet_js_content = f.read()
                    logging.debug("Loaded local leaflet.js successfully")
                else:
                    logging.warning(f"Local leaflet.js not found at {leaflet_js_path}")
            except Exception as e:
                logging.error(f"Failed to read local leaflet.js: {e}")

            try:
                # Read local Leaflet CSS
                leaflet_css_path = script_dir / "resources" / "leaflet" / "leaflet.css"
                if leaflet_css_path.exists():
                    with open(leaflet_css_path, 'r', encoding='utf-8') as f:
                        leaflet_css_content = f.read()
                    logging.debug("Loaded local leaflet.css successfully")
                else:
                    logging.warning(f"Local leaflet.css not found at {leaflet_css_path}")
            except Exception as e:
                logging.error(f"Failed to read local leaflet.css: {e}")

            # Inject local Leaflet library as inline fallback if available
            if leaflet_js_content:
                # Add inline script fallback after CDN script
                html_with_path = html_with_path.replace(
                    '<!-- CDN script with onerror fallback to local bundle -->',
                    f'''<!-- CDN script with onerror fallback to local bundle -->
                    <script id="leaflet-inline-fallback">
                    // If CDN fails, this inline version will be used
                    (function() {{
                        var cdnScript = document.querySelector('script[src*="unpkg.com/leaflet"]');
                        if (cdnScript) {{
                            cdnScript.onerror = function() {{
                                console.log('[OFFLINE] CDN failed, using inline Leaflet library');
                                try {{
                                    // Remove the failed CDN script
                                    cdnScript.parentNode.removeChild(cdnScript);
                                    // Inline Leaflet library will load after this
                                }} catch(e) {{
                                    console.error('[OFFLINE] Error handling CDN failure:', e);
                                }}
                            }};
                        }}
                    }})();
                    </script>
                    <!-- Inline Leaflet JS (loaded from local file) -->
                    <script id="leaflet-local-inline">
                    {leaflet_js_content}
                    </script>'''
                )

            if leaflet_css_content:
                # Add inline CSS fallback
                html_with_path = html_with_path.replace(
                    '</head>',
                    f'''<!-- Inline Leaflet CSS (loaded from local file) -->
                    <style id="leaflet-local-inline-css">
                    {leaflet_css_content}
                    </style>
                    </head>'''
                )

            # Insert map state script before closing </head> tag
            if map_state_js:
                html_with_path = html_with_path.replace('</head>', f'{map_state_js}</head>')

            # Use about:blank as base URL (doesn't block HTTPS requests)
            self._map_loading_in_progress = True
            self.map_view.setHtml(html_with_path, QUrl("about:blank"))

            def _on_loaded(ok):
                # Load is no longer in flight
                self._map_loading_in_progress = False
                # run update if the page loaded successfully
                if ok:
                    try:
                        # use safe caller that waits for the JS function to exist
                        self._call_update_js(js, connection_data, force_show_tooltip)
                    except Exception:
                        pass

                    # Schedule a check to verify map is actually ready and set flag
                    # Wait a bit for nested JS callbacks to complete
                    QTimer.singleShot(1000, self._verify_map_ready)

                try:
                    self.map_view.loadFinished.disconnect(_on_loaded)
                except Exception:
                    pass

            # connect a one-shot handler that will invoke the JS updater when ready
            self.map_view.loadFinished.connect(_on_loaded)
            return

        # If already initialized, call the JS updater using safe caller
        try:
            self._call_update_js(js, connection_data, force_show_tooltip)
        except Exception as e:
            # Log error but don't reload to prevent infinite loop
            logging.error(f"Exception when calling _call_update_js on initialized map: {e}")

    @Slot()
    def replay_connections(self):

        slider_position = self.slider.value()

        if len(self.connection_list) > 0:

            if slider_position >= self.connection_list_counter:
                slider_position = -1

            self.refresh_connections(slider_position)

            slider_position +=1
            self.slider.setValue(slider_position)

        else:
            self.refresh_connections(self, 0)
            self.timer_replay_connections.stop()

        self.slider.setValue(slider_position)    

    def stop_capture_connections(self):
        if self.timer.isActive():
            self.timer.stop()
            self.start_capture_btn.setVisible(True)
            self.stop_capture_btn.setVisible(False)
            self.toggle_button.setVisible(True)
            # Stop wave animation when capture stops
            self._stop_stop_button_wave()
            # Start flashing the start capture button to draw attention
            self._start_capture_button_flash()

    @Slot()
    def refresh_connections(self, slider_position=None):

        force_tooltip = show_tooltip

        if slider_position is False:
            slider_position=None
            if not self.timer.isActive():
                self.timer.start(map_refresh_interval)
                self.start_capture_btn.setVisible(False)
                self.toggle_button.setVisible(False)
                self.stop_capture_btn.setVisible(True)
                # Stop flashing when capture starts
                self._stop_capture_button_flash()
                # Start wave animation on stop button
                self._start_stop_button_wave()

        self._refresh_force_tooltip = force_tooltip
        self._refresh_number_of_previous_objects = self.map_objects

        if do_collect_connections_asynchronously:
            if self._async_collection_in_progress:
                # Previous collection still running — skip this tick
                logging.debug("refresh_connections: async collection already in progress, skipping tick")
                return
            self._async_collection_in_progress = True
            worker = ConnectionCollectorWorker(self.get_active_tcp_connections, slider_position)
            worker.signals.finished.connect(self._on_connections_ready)
            self._collector_worker = worker  # keep alive until slot fires
            QThreadPool.globalInstance().start(worker)
        else:
            # Synchronous path — runs entirely on the UI thread.
            # Skip if a stale async worker is still in-flight; it will clear
            # _async_collection_in_progress when it finishes (and its result
            # will be discarded by _on_connections_ready), so the next tick
            # will proceed normally.
            if self._async_collection_in_progress:
                logging.debug("refresh_connections: stale async worker still in flight, skipping sync tick")
                return
            # Defensive re-entrancy guard: Qt blocks the event loop while this
            # method runs synchronously, so true re-entrancy cannot happen, but
            # guard anyway in case a future code path calls processEvents().
            if self._sync_collection_in_progress:
                logging.debug("refresh_connections: sync collection already in progress, skipping tick")
                return
            self._sync_collection_in_progress = True
            try:
                connections = self.get_active_tcp_connections(slider_position)
                self._apply_connections(connections, slider_position)
            finally:
                self._sync_collection_in_progress = False

    @Slot(object, object)
    def _on_connections_ready(self, connections, slider_position):
        """Called on the UI thread when the async connection worker finishes."""
        self._async_collection_in_progress = False
        self._collector_worker = None  # release the worker reference
        # If the user switched to sync mode while the worker was in flight,
        # discard the stale result.  The sync path will collect fresh data on
        # the next timer tick now that _async_collection_in_progress is clear.
        if not do_collect_connections_asynchronously:
            logging.debug("_on_connections_ready: discarding stale async result (mode is now sync)")
            return
        self._apply_connections(connections, slider_position)

    @Slot()
    def _post_collection_ui_update(self):
        """UI-thread-only bookkeeping that was formerly inside get_active_tcp_connections.

        Touches QSlider, QLabel, QTimer, QPushButton — must never run on a pool thread.
        Called from _apply_connections() which is guaranteed to execute on the GUI thread.
        """
        try:
            # keep slider in sync
            self.slider.setMaximum(self.connection_list_counter)
            self.slider_value_label.setText(
                TIME_SLIDER_TEXT + str(self.slider.value()) + "/" + str(len(self.connection_list) - 1)
            )

            if self.timer.isActive():
                self.slider.valueChanged.disconnect(self.update_slider_value)
                self.slider.setValue(self.connection_list_counter)
                self.slider.valueChanged.connect(self.update_slider_value)

            # If Summary tab is active, refresh it with new data
            try:
                if hasattr(self, 'tab_widget') and self.tab_widget.currentIndex() == 1:
                    self.update_summary_table()
                    self._summary_needs_update = False
            except Exception:
                pass

            # Capture screenshot if enabled (only for live captures, not timeline replay)
            if do_capture_screenshots:
                try:
                    logging.debug(f"Scheduling screenshot capture (buffer counter={self.connection_list_counter})")
                    QTimer.singleShot(1500, self._capture_map_screenshot)
                except Exception as e:
                    logging.error(f"Failed to schedule screenshot capture: {e}")

            # Update video button visibility whenever connections are refreshed
            try:
                self._update_video_button_visibility()
            except Exception:
                pass
        except Exception as e:
            logging.error(f"_post_collection_ui_update error: {e}")

    @Slot(object, object)
    def _apply_connections(self, connections, slider_position):
        """Update the table and map with a freshly collected connection list.

        This method always executes on the UI thread, whether the connections
        were collected synchronously or by the background worker.
        """
        # Run the deferred UI bookkeeping (slider, summary, screenshots, video
        # button) that must happen on the GUI thread.
        self._post_collection_ui_update()

        force_tooltip = self._refresh_force_tooltip
        number_of_previous_objects = self._refresh_number_of_previous_objects

        self.connections = connections

        if len(self.connections) != number_of_previous_objects:
            self.map_objects = len(self.connections)

            self.left_panel.setTitle(f"Active TCP/UDP Connections - {self.map_objects} connections")

        # Save currently selected row before clearing table
        selected_connection = None
        try:
            selected_rows = self.connection_table.selectedItems()
            if selected_rows:
                selected_row = selected_rows[0].row()
                # Save the connection identifiers to restore selection later
                selected_connection = {
                    'process': self.connection_table.item(selected_row, PROCESS_ROW_INDEX).text() if self.connection_table.item(selected_row, PROCESS_ROW_INDEX) else '',
                    'pid': self.connection_table.item(selected_row, PID_ROW_INDEX).text() if self.connection_table.item(selected_row, PID_ROW_INDEX) else '',
                    'remote': self.connection_table.item(selected_row, REMOTE_ADDRESS_ROW_INDEX).text() if self.connection_table.item(selected_row, REMOTE_ADDRESS_ROW_INDEX) else '',
                    'local': self.connection_table.item(selected_row, LOCAL_ADDRESS_ROW_INDEX).text() if self.connection_table.item(selected_row, LOCAL_ADDRESS_ROW_INDEX) else ''
                }
        except Exception as e:
            logging.debug(f"No selection to preserve: {e}")
            selected_connection = None

        # Update table
        self.connection_table.setUpdatesEnabled(False)
        self.connection_table.setRowCount(0)

        connections_to_show_on_map = []

        resolved_addresses = 0
        unresolved_addresses = 0
        local_addresses = 0
        udp_no_remote = 0

        for conn in self.connections:
            # Add to table

            if not show_only_new_active_connections or (show_only_new_active_connections and conn['icon'] == 'blueIcon'):

                lat, lng = None, None

                # Get coordinates for map
                ip = _extract_remote_ip(conn['remote'], conn['ip_type'])

                row = self.connection_table.rowCount()

                if not (show_only_remote_connections and not is_routable(ip)):
                    self.connection_table.insertRow(row)

                    self.connection_table.setItem(row, PROCESS_ROW_INDEX, QTableWidgetItem(conn['process']))
                    self.connection_table.setItem(row, PID_ROW_INDEX , QTableWidgetItem(conn['pid']))
                    self.connection_table.setItem(row, SUSPECT_ROW_INDEX, QTableWidgetItem(conn['suspect']))
                    self.connection_table.setItem(row, PROTOCOL_ROW_INDEX, QTableWidgetItem(conn.get('protocol', 'TCP')))
                    self.connection_table.setItem(row, LOCAL_ADDRESS_ROW_INDEX, QTableWidgetItem(conn['local']))
                    self.connection_table.setItem(row, LOCAL_PORT_ROW_INDEX, QTableWidgetItem(conn['localport']))
                    self.connection_table.setItem(row, REMOTE_ADDRESS_ROW_INDEX, QTableWidgetItem(conn['remote']))
                    self.connection_table.setItem(row, REMOTE_PORT_ROW_INDEX, QTableWidgetItem(conn['remoteport']))
                    self.connection_table.setItem(row, NAME_ROW_INDEX, QTableWidgetItem(conn['name']))
                    self.connection_table.setItem(row, IP_TYPE_ROW_INDEX, QTableWidgetItem(conn['ip_type']))
                    _way = 'IN' if (conn.get('state', '') == 'LISTEN' or conn.get('inbound')) else 'OUT'
                    self.connection_table.setItem(row, WAY_ROW_INDEX, QTableWidgetItem(_way))
                    self.connection_table.setItem(row, HOSTNAME_ROW_INDEX, QTableWidgetItem(conn.get('hostname', '')))
                    self.connection_table.setItem(row, BYTES_SENT_ROW_INDEX, _make_bytes_item(conn.get('bytes_sent', 0)))
                    self.connection_table.setItem(row, BYTES_RECV_ROW_INDEX, _make_bytes_item(conn.get('bytes_recv', 0)))

                if ip in ('*', '0.0.0.0', '::', ''):
                    # UDP listener with no remote peer — not a real unresolved address
                    udp_no_remote += 1
                elif is_routable(ip):

                    lat, lng = self.get_coordinates(ip, conn['ip_type'])

                    if lat is not None and lng is not None:
                        self.connection_table.setItem(row, LOCATION_LAT_ROW_INDEX, QTableWidgetItem(f"{lat}"))
                        self.connection_table.setItem(row, LOCATION_LON_ROW_INDEX, QTableWidgetItem(f"{lng}"))
                        resolved_addresses+=1
                    else:
                        self.connection_table.setItem(row, LOCATION_LAT_ROW_INDEX, QTableWidgetItem(""))
                        self.connection_table.setItem(row, LOCATION_LON_ROW_INDEX, QTableWidgetItem(""))
                        unresolved_addresses+=1
                else:
                    local_addresses+=1
                
                if conn['suspect'] == "Yes":
                    for col in range(self.connection_table.columnCount()):
                        self.connection_table.item(row, col).setForeground(Qt.red)

                    self.setStyleSheet("border: 2px solid red;") # Set window border to red
                
                connections_to_show_on_map.append(conn)

        self.connection_table.setUpdatesEnabled(True)

        # NOTE: Pinned-connection (yellow icon) and foreground-remap overrides are now
        # applied inside update_map() so every render path (timer refresh, filter
        # re-render, single-click focus) gets consistent visual treatment.

        # Get datetime for the current view (live or timeline)
        datetime_text = ""
        if slider_position is None or slider_position is False:
            # Live mode - use current time
            datetime_text = f"Live: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        else:
            # Timeline mode - get datetime from connection_list
            if hasattr(self, 'connection_list') and self.connection_list:
                idx = min(slider_position, len(self.connection_list) - 1)
                if idx >= 0:
                    try:
                        dt = self.connection_list[idx].get('datetime')
                        if isinstance(dt, datetime.datetime):
                            datetime_text = f"Timeline: {dt.strftime('%Y-%m-%d %H:%M:%S')}"
                        else:
                            datetime_text = f"Timeline: {str(dt)}"
                    except Exception:
                        datetime_text = ""

        # Build single-line stats string and update map with it
        stats_line = f"Geo resolved locations: {resolved_addresses} - Unresolved locations: {unresolved_addresses} - Local connections: {local_addresses} - UDP *: {udp_no_remote}"
        # Cache for reuse when the filter changes without a full refresh
        self._last_stats_line = stats_line
        self._last_datetime_text = datetime_text

        # Apply active column filters to the map view as well
        active_filters = self._get_active_filters()
        if active_filters:
            map_conns = [c for c in connections_to_show_on_map
                         if self._conn_matches_filters(c, active_filters)]
            # Collect all agent origins from the full list and inject stubs for any
            # agent whose connections were entirely filtered out so their circle still shows
            all_agent_origins = {}
            for conn in connections_to_show_on_map:
                oh = conn.get('origin_hostname')
                if oh and oh not in all_agent_origins:
                    all_agent_origins[oh] = conn
            matched_origins = {c.get('origin_hostname') for c in map_conns if c.get('origin_hostname')}
            for hostname, ref_conn in all_agent_origins.items():
                if hostname not in matched_origins:
                    map_conns.append({
                        'process': '', 'pid': '', 'suspect': '', 'local': '', 'localport': '',
                        'remote': '', 'remoteport': '', 'name': '', 'ip_type': '',
                        'lat': None, 'lng': None, 'icon': '',
                        'origin_hostname': hostname,
                        'origin_lat':      ref_conn.get('origin_lat'),
                        'origin_lng':      ref_conn.get('origin_lng'),
                        'origin_public_ip': ref_conn.get('origin_public_ip', ''),
                        'agent_color':     self._agent_colors.get(hostname, ref_conn.get('agent_color', 'orange')),
                        'hostname':        hostname,
                    })
        else:
            map_conns = connections_to_show_on_map

        # Cache the fully-processed connection list so _update_map_with_filter can
        # re-render the map (including remote agent data) without a full refresh.
        self._last_map_connections = list(connections_to_show_on_map)

        self.update_map(map_conns, force_tooltip, stats_text=stats_line, datetime_text=datetime_text)

        if table_column_sort_index > -1 and not do_pause_table_sorting:
            self.column_resort(table_column_sort_index)

        # Restore selection if we had one before refresh
        if selected_connection:
            try:
                for row in range(self.connection_table.rowCount()):
                    row_process = self.connection_table.item(row, PROCESS_ROW_INDEX)
                    row_pid = self.connection_table.item(row, PID_ROW_INDEX)
                    row_remote = self.connection_table.item(row, REMOTE_ADDRESS_ROW_INDEX)
                    row_local = self.connection_table.item(row, LOCAL_ADDRESS_ROW_INDEX)

                    if (row_process and row_process.text() == selected_connection['process'] and
                        row_pid and row_pid.text() == selected_connection['pid'] and
                        row_remote and row_remote.text() == selected_connection['remote'] and
                        row_local and row_local.text() == selected_connection['local']):

                        # Found matching row - restore selection
                        self.connection_table.selectRow(row)
                        # Optionally scroll to keep it visible
                        self.connection_table.scrollToItem(row_process)
                        logging.debug(f"Restored selection to row {row}")
                        break
            except Exception as e:
                logging.debug(f"Could not restore selection: {e}")
        self.apply_connection_table_filter(update_map=False)

    @Slot(bool)
    def on_map_loaded(self, success):
        if not success:
            logging.error("Map failed to load!")
        else:
            logging.debug("Map page loaded successfully")

    def showEvent(self, event):
        """Apply pending fullscreen/maximize restore on first real show.

        This avoids races where windowHandle() or native windowing hasn't associated
        the QWindow with a QScreen yet. We perform a single-shot deferred apply
        to give the window system a moment to finish mapping.
        """
        try:
            super().showEvent(event)
        except Exception:
            pass

        # Sync filter bar widths once the layout geometry is finalised.
        # The earlier QTimer.singleShot(0) in init_ui fires before the window
        # is painted, so column widths may not yet reflect the real layout.
        QTimer.singleShot(50, self._sync_filter_widths)
        QTimer.singleShot(50, self._sync_summary_filter_widths)

        # Show first-run welcome message if this is the first time the app is launched
        if getattr(self, '_is_first_run', False):
            try:
                # Clear the flag so we only show this once
                self._is_first_run = False

                # Schedule the message to show after a short delay (after window is fully visible)
                QTimer.singleShot(500, self._show_first_run_message)
            except Exception:
                pass

        try:
            pr = getattr(self, '_pending_restore', None)
            if not pr:
                return

            # clear pending to avoid repeat
            self._pending_restore = None

            stype = pr.get('type')
            sname = pr.get('screen_name')

            target = None
            if sname:
                for s in QApplication.screens():
                    try:
                        if s.name() == sname:
                            target = s
                            break
                    except Exception:
                        continue

            # schedule shortly to ensure native mapping done
            if stype == 'fullscreen':
                if target:
                    QTimer.singleShot(50, lambda t=target: self._go_fullscreen_on_screen(t))
                else:
                    QTimer.singleShot(50, self.showFullScreen)

            elif stype == 'maximized':
                if target:
                    QTimer.singleShot(50, lambda t=target: self._go_maximized_on_screen(t))
                else:
                    QTimer.singleShot(50, self.showMaximized)
        except Exception:
            pass

    def _show_first_run_message(self):
        """Show welcome message for first-time users"""
        try:
            QMessageBox.about(
                self,
                "Welcome to TCP Geo Map",
                "By default ipify.com is enabled and your geo localization exit point will show on the map.\n\n"
                "To disable it navigate to the Settings tab on the top and check the "
                '"Resolve public internet IP using ipify.com" option.'
            )
        except Exception as e:
            logging.warning(f"Failed to show first run message: {e}")

    def _capture_map_screenshot(self):
        """Capture screenshot of the map widget and save to disk as JPG.

        When the window is minimized the WebEngine compositor stops rendering and
        grab() returns a blank image.  To avoid popping the window visibly we
        make it fully transparent, restore it off-screen, wait 500 ms for
        WebEngine to repaint, grab the frame, then re-minimize and restore the
        original opacity — all invisible to the user.
        """
        try:
            if not (hasattr(self, 'map_view') and self.map_view is not None):
                logging.warning("Cannot capture screenshot - map_view not available")
                return

            os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
            timestamp = datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
            filepath = os.path.join(SCREENSHOTS_DIR, f"tcp_geo_map_{timestamp}.jpg")

            is_minimized = self.isMinimized() or bool(self.windowState() & Qt.WindowMinimized)
            if is_minimized:
                # Make window fully transparent so the restore is invisible
                original_opacity = self.windowOpacity()
                self.setWindowOpacity(0.0)
                self.showNormal()
                QApplication.processEvents()
                QTimer.singleShot(500, lambda: self._finish_capture_screenshot(filepath, True, original_opacity))
            else:
                self._finish_capture_screenshot(filepath, False, None)

        except Exception as e:
            logging.error(f"Error capturing screenshot: {e}")

    def _finish_capture_screenshot(self, filepath, re_minimize, original_opacity):
        """Grab the map view, save to *filepath*, then re-minimize if requested."""
        try:
            pixmap = self.map_view.grab()

            if re_minimize:
                self.showMinimized()
                if original_opacity is not None:
                    self.setWindowOpacity(original_opacity)

            success = pixmap.save(filepath, 'JPG', 95)
            if success:
                logging.info(f"Screenshot saved: {filepath}")
                try:
                    self._cleanup_old_screenshots_async()
                except Exception as cleanup_error:
                    logging.error(f"Failed to cleanup after screenshot save: {cleanup_error}")
            else:
                logging.warning(f"Failed to save screenshot: {filepath}")
        except Exception as e:
            logging.error(f"Error finishing screenshot capture: {e}")

    @Slot()
    def generate_video_from_screenshots(self):
        """Generate MP4 video from all screenshots in the screen_captures folder (async)"""
        try:
            # Block if already generating
            if self._video_generating:
                return

            # Check if cv2 is available (quick check before starting worker)
            try:
                import cv2
            except ImportError:
                QMessageBox.critical(
                    self,
                    "Missing Dependency",
                    "OpenCV (cv2) is required to generate videos.\n\n"
                    "Please install it using:\n"
                    "pip install opencv-python\n\n"
                    "Then restart the application."
                )
                return

            # Quick validation before starting async operation
            if not os.path.exists(SCREENSHOTS_DIR):
                QMessageBox.warning(
                    self,
                    "No Screenshots",
                    f"Screenshot directory '{SCREENSHOTS_DIR}' does not exist.\n\n"
                    "Enable screenshot capture and capture some connections first."
                )
                return

            # Count screenshots
            screenshot_count = sum(
                1 for f in os.listdir(SCREENSHOTS_DIR)
                if f.startswith("tcp_geo_map_") and f.endswith(".jpg")
            )

            if screenshot_count < 2:
                QMessageBox.warning(
                    self,
                    "Not Enough Screenshots",
                    f"Found only {screenshot_count} screenshot(s).\n\n"
                    "At least 2 screenshots are required to generate a video.\n"
                    "Capture more connections with screenshot capture enabled."
                )
                return

            # Mark as generating and start flash animation
            self._video_generating = True
            self._start_video_button_flash()
            self.generate_video_btn.setText("Generating .mp4 video please wait...")
            logging.info(f"Starting async video generation with {screenshot_count} screenshots")

            # Create worker and connect signals
            worker = VideoGeneratorWorker(SCREENSHOTS_DIR)

            worker.signals.finished.connect(self._on_video_generation_finished)
            worker.signals.error.connect(self._on_video_generation_error)
            worker.signals.progress.connect(self._on_video_generation_progress)

            # Start the worker in the thread pool
            self.thread_pool.start(worker)

        except Exception as e:
            # Reset state on unexpected error
            self._video_generating = False
            self._stop_video_button_flash()

            QMessageBox.critical(
                self,
                "Video Generation Error",
                f"Failed to start video generation:\n{str(e)}"
            )
            logging.error(f"Error starting video generation: {e}")

    def _start_video_button_flash(self):
        """Start flashing animation for video button (high visibility in dark mode)"""
        try:
            # Create timer if it doesn't exist
            if self._video_btn_flash_timer is None:
                self._video_btn_flash_timer = QTimer(self)
                self._video_btn_flash_timer.timeout.connect(self._toggle_video_button_flash)

            # Start flashing at 500ms intervals
            self._video_btn_flash_state = False
            self._video_btn_flash_timer.start(500)

        except Exception as e:
            logging.error(f"Error starting video button flash: {e}")

    def _stop_video_button_flash(self):
        """Stop flashing animation and restore normal button style"""
        try:
            if self._video_btn_flash_timer is not None:
                self._video_btn_flash_timer.stop()

            # Restore normal button style
            self.generate_video_btn.setStyleSheet("")

        except Exception as e:
            logging.error(f"Error stopping video button flash: {e}")

    @Slot()
    def _toggle_video_button_flash(self):
        """Toggle button appearance for flashing effect"""
        try:
            self._video_btn_flash_state = not self._video_btn_flash_state

            if self._video_btn_flash_state:
                # Bright state - highly visible in both light and dark modes
                self.generate_video_btn.setStyleSheet(
                    "QPushButton { "
                    "background-color: #2196F3; "  # Bright blue
                    "color: white; "
                    "font-weight: bold; "
                    "border: 2px solid #1976D2; "
                    "}"
                )
            else:
                # Normal state with subtle highlight
                self.generate_video_btn.setStyleSheet(
                    "QPushButton { "
                    "background-color: #1565C0; "  # Darker blue
                    "color: white; "
                    "font-weight: bold; "
                    "}"
                )

        except Exception as e:
            logging.error(f"Error toggling video button flash: {e}")

    def _start_capture_button_flash(self):
        """Start flashing animation for start capture button to draw attention"""
        try:
            # Create timer if it doesn't exist
            if self._start_capture_flash_timer is None:
                self._start_capture_flash_timer = QTimer(self)
                self._start_capture_flash_timer.timeout.connect(self._toggle_start_capture_flash)

            # Start flashing at 600ms intervals (slightly slower than video button)
            self._start_capture_flash_state = False
            self._start_capture_flash_timer.start(600)

            # Create auto-stop timer to stop flashing after 10 seconds
            if self._start_capture_flash_stop_timer is None:
                self._start_capture_flash_stop_timer = QTimer(self)
                self._start_capture_flash_stop_timer.setSingleShot(True)
                self._start_capture_flash_stop_timer.timeout.connect(self._auto_stop_capture_flash)

            # Schedule auto-stop after 10 seconds (10000 milliseconds)
            self._start_capture_flash_stop_timer.start(10000)
            logging.debug("Start capture button flash scheduled to auto-stop after 20 seconds")

        except Exception as e:
            logging.error(f"Error starting start capture button flash: {e}")

    def _stop_capture_button_flash(self):
        """Stop flashing animation and restore normal button style"""
        try:
            if self._start_capture_flash_timer is not None:
                self._start_capture_flash_timer.stop()

            # Also stop the auto-stop timer if it's running
            if self._start_capture_flash_stop_timer is not None:
                self._start_capture_flash_stop_timer.stop()

            # Restore normal button style
            self.start_capture_btn.setStyleSheet("")

        except Exception as e:
            logging.error(f"Error stopping start capture button flash: {e}")

    @Slot()
    def _auto_stop_capture_flash(self):
        """Automatically stop flashing after timeout (called by timer)"""
        try:
            logging.debug("Auto-stopping start capture button flash after 20 seconds")
            self._stop_capture_button_flash()
        except Exception as e:
            logging.error(f"Error in auto-stop capture flash: {e}")

    @Slot()
    def _toggle_start_capture_flash(self):
        """Toggle start capture button appearance for flashing effect"""
        try:
            self._start_capture_flash_state = not self._start_capture_flash_state

            if self._start_capture_flash_state:
                # Bright state - green highlight to indicate "ready to start"
                self.start_capture_btn.setStyleSheet(
                    "QToolButton { "
                    "background-color: #4CAF50; "  # Bright green
                    "color: white; "
                    "font-weight: bold; "
                    "border: 2px solid #45a049; "
                    "}"
                )
            else:
                # Normal state with subtle highlight
                self.start_capture_btn.setStyleSheet(
                    "QToolButton { "
                    "background-color: #388E3C; "  # Darker green
                    "color: white; "
                    "font-weight: bold; "
                    "}"
                )

        except Exception as e:
            logging.error(f"Error toggling start capture button flash: {e}")

    def _start_stop_button_wave(self):
        """Start wave animation for stop capture button text"""
        try:
            # Create timer if it doesn't exist
            if self._stop_btn_wave_timer is None:
                self._stop_btn_wave_timer = QTimer(self)
                self._stop_btn_wave_timer.timeout.connect(self._update_stop_button_wave)

            # Reset wave to first pattern and start
            self._stop_btn_wave_index = 0
            self._stop_btn_wave_timer.start(300)  # Update every 300ms for smooth wave

        except Exception as e:
            logging.error(f"Error starting stop button wave: {e}")

    def _stop_stop_button_wave(self):
        """Stop wave animation and restore normal button text"""
        try:
            if self._stop_btn_wave_timer is not None:
                self._stop_btn_wave_timer.stop()

            # Restore normal button text (without wave)
            self.stop_capture_btn.setText(STOP_CAPTURE_BUTTON_TEXT)

        except Exception as e:
            logging.error(f"Error stopping stop button wave: {e}")

    @Slot()
    def _update_stop_button_wave(self):
        """Update stop button text with next wave pattern"""
        try:
            # Get current wave pattern
            wave_pattern = self._stop_btn_wave_patterns[self._stop_btn_wave_index]

            # Update button text with wave suffix
            self.stop_capture_btn.setText(f"{STOP_CAPTURE_BUTTON_TEXT} {wave_pattern}")

            # Move to next pattern (cycle through)
            self._stop_btn_wave_index = (self._stop_btn_wave_index + 1) % len(self._stop_btn_wave_patterns)

        except Exception as e:
            logging.error(f"Error updating stop button wave: {e}")

    @Slot(bool, str, dict)
    def _on_video_generation_finished(self, success, message, stats):
        """Called when video generation completes successfully"""
        try:
            # Stop flashing and reset state
            self._video_generating = False
            self._stop_video_button_flash()

            # Re-enable button and restore text
            screenshot_count = sum(
                1 for f in os.listdir(SCREENSHOTS_DIR)
                if f.startswith("tcp_geo_map_") and f.endswith(".jpg")
            )

            if screenshot_count >= 2:
                self.generate_video_btn.setText(f"Generate .mp4 video file ({screenshot_count} frames)")
            else:
                self.generate_video_btn.setText("Generate .mp4 video file")

            # Show success message
            if success:
                QMessageBox.information(
                    self,
                    "Video Generated",
                    message
                )
        except Exception as e:
            logging.error(f"Error in video generation finished handler: {e}")

    @Slot(str)
    def _on_video_generation_error(self, error_message):
        """Called when video generation fails"""
        try:
            # Stop flashing and reset state
            self._video_generating = False
            self._stop_video_button_flash()

            # Restore button text
            screenshot_count = sum(
                1 for f in os.listdir(SCREENSHOTS_DIR)
                if f.startswith("tcp_geo_map_") and f.endswith(".jpg")
            )

            if screenshot_count >= 2:
                self.generate_video_btn.setText(f"Generate .mp4 video file ({screenshot_count} frames)")
            else:
                self.generate_video_btn.setText("Generate .mp4 video file")

            # Show error message
            QMessageBox.critical(
                self,
                "Video Generation Error",
                error_message
            )
        except Exception as e:
            logging.error(f"Error in video generation error handler: {e}")

    @Slot(int, int)
    def _on_video_generation_progress(self, current_frame, total_frames):
        """Called when video generation makes progress"""
        try:
            # Update button text with progress (frame count)
            progress_text = f"Generating video... {current_frame}/{total_frames} frames"
            self.generate_video_btn.setText(progress_text)
            logging.debug(f"Video generation progress: {current_frame}/{total_frames}")
        except Exception as e:
            logging.error(f"Error updating video generation progress: {e}")

    def _cleanup_old_screenshots_async(self):
        """Run screenshot cleanup in background thread to avoid blocking UI"""
        def cleanup_worker():
            try:
                self._cleanup_old_screenshots()
            except Exception as e:
                logging.error(f"Async cleanup error: {e}")

        threading.Thread(target=cleanup_worker, daemon=True).start()

    def _cleanup_old_screenshots(self):
        """Delete old screenshot files to keep only the most recent max_connection_list_filo_buffer_size files"""
        global max_connection_list_filo_buffer_size

        try:
            # Ensure we have a valid buffer size (defensive)
            buffer_limit = max_connection_list_filo_buffer_size
            if not isinstance(buffer_limit, int) or buffer_limit <= 0:
                logging.warning(f"Invalid buffer size: {buffer_limit}, defaulting to 5")
                buffer_limit = 5

            logging.info(f"_cleanup_old_screenshots: Starting cleanup (buffer_limit={buffer_limit})")

            # Get all screenshot files in the directory
            if not os.path.exists(SCREENSHOTS_DIR):
                logging.debug(f"_cleanup_old_screenshots: Directory {SCREENSHOTS_DIR} does not exist")
                return

            # Find all jpg files matching our naming pattern (EXCLUDE .mp4 video files)
            screenshot_files = []
            for filename in os.listdir(SCREENSHOTS_DIR):
                # Only process .jpg screenshot files, NOT .mp4 video files
                if filename.startswith("tcp_geo_map_") and filename.endswith(".jpg"):
                    filepath = os.path.join(SCREENSHOTS_DIR, filename)
                    try:
                        # Get file modification time
                        mtime = os.path.getmtime(filepath)
                        screenshot_files.append((mtime, filepath, filename))
                    except Exception as e:
                        logging.warning(f"Failed to get mtime for {filename}: {e}")
                        continue

            logging.info(f"_cleanup_old_screenshots: Found {len(screenshot_files)} .jpg screenshot files (excluding .mp4 videos)")

            # Sort by modification time (oldest first)
            screenshot_files.sort(key=lambda x: x[0])

            # Calculate how many files to delete
            total_files = len(screenshot_files)
            files_to_keep = buffer_limit
            files_to_delete = total_files - files_to_keep

            logging.info(f"_cleanup_old_screenshots: Total={total_files}, Keep={files_to_keep}, Delete={files_to_delete}")

            if files_to_delete > 0:
                # Delete the oldest files
                deleted_count = 0
                for i in range(files_to_delete):
                    try:
                        _, filepath, filename = screenshot_files[i]
                        os.remove(filepath)
                        deleted_count += 1
                        logging.info(f"Deleted old screenshot: {filename}")
                    except Exception as e:
                        logging.warning(f"Failed to delete screenshot {filename}: {e}")

                if deleted_count > 0:
                    logging.info(f"Cleaned up {deleted_count} old screenshot(s). Kept {files_to_keep} most recent .jpg files.")
            else:
                logging.debug("_cleanup_old_screenshots: No files to delete")

            # Update video button visibility
            self._update_video_button_visibility()

        except Exception as e:
            logging.error(f"Error cleaning up old screenshots: {e}")

    def _update_video_button_visibility(self):
        """Show or hide the Generate Video button based on whether screenshots exist"""
        try:
            if not hasattr(self, 'generate_video_btn'):
                return

            screenshot_count = 0
            if os.path.exists(SCREENSHOTS_DIR):
                for filename in os.listdir(SCREENSHOTS_DIR):
                    if filename.startswith("tcp_geo_map_") and filename.endswith(".jpg"):
                        screenshot_count += 1

            # Show button only if we have at least 2 screenshots (need multiple frames for video)
            self.generate_video_btn.setVisible(screenshot_count >= 2)

            if screenshot_count >= 2:
                self.generate_video_btn.setText(f"Generate .mp4 video file ({screenshot_count} frames)")
            else:
                self.generate_video_btn.setText("Generate .mp4 video file")

        except Exception as e:
            logging.warning(f"Error updating video button visibility: {e}")

    @Slot(int)
    def on_tab_changed(self, index):
        """Called when user switches tabs - update Summary tab if selected (lazy loading)"""
        try:
            # Index 1 is the Summary tab (0=Main, 1=Summary, 2=Settings)
            if index == 1:
                # Only refresh if data has changed
                if self._summary_needs_update:
                    self.update_summary_table()
                    self._summary_needs_update = False
                # Always re-sync filter widths — columns may have been resized while the tab was hidden
                QTimer.singleShot(0, self._sync_summary_filter_widths)
            # Refresh Agent Management table whenever it is activated
            if hasattr(self, '_agent_mgmt_tab_index') and index == self._agent_mgmt_tab_index:
                self._refresh_agent_management_table(force_rebuild=True)
        except Exception as e:
            logging.error(f"Error updating tab: {e}")

    @Slot()
    def update_summary_table(self):
        """Kick off background aggregation of connection statistics.

        The heavy iteration over every timeline snapshot is done on a
        QThreadPool thread (``SummaryAggregationWorker``).  Only the
        final table population runs on the GUI thread via
        ``_on_summary_aggregation_ready``.
        """
        try:
            if not self.connection_list:
                self.summary_table.setUpdatesEnabled(False)
                self.summary_table.setRowCount(0)
                self.summary_table.setUpdatesEnabled(True)
                return

            # Snapshot the deque atomically so the worker iterates a stable copy
            snapshot = list(self.connection_list)

            worker = SummaryAggregationWorker(snapshot, show_only_remote_connections)
            # prevent the worker ref from being GC'd before the pool finishes
            self._summary_worker = worker
            worker.signals.finished.connect(self._on_summary_aggregation_ready)
            QThreadPool.globalInstance().start(worker)

        except Exception as e:
            logging.error(f"Error launching summary aggregation: {e}")

    @Slot(object, int, int)
    def _on_summary_aggregation_ready(self, sorted_stats, total_unique, total_connections):
        """Populate the summary QTableWidget from pre-aggregated stats (GUI thread)."""
        try:
            self.summary_table.setUpdatesEnabled(False)
            self.summary_table.setRowCount(0)

            for (hostname, process, pid, suspect, protocol, local, remote, ip_type, way, name), stats in sorted_stats:
                count = stats['count']
                row = self.summary_table.rowCount()
                self.summary_table.insertRow(row)

                self.summary_table.setItem(row, 0, QTableWidgetItem(hostname))
                self.summary_table.setItem(row, 1, QTableWidgetItem(process))
                self.summary_table.setItem(row, 2, QTableWidgetItem(pid))
                self.summary_table.setItem(row, 3, QTableWidgetItem(suspect))
                self.summary_table.setItem(row, 4, QTableWidgetItem(protocol))
                self.summary_table.setItem(row, 5, QTableWidgetItem(local))
                self.summary_table.setItem(row, 6, QTableWidgetItem(remote))
                self.summary_table.setItem(row, 7, QTableWidgetItem(ip_type))
                self.summary_table.setItem(row, 8, QTableWidgetItem(way))
                self.summary_table.setItem(row, 9, QTableWidgetItem(name))
                self.summary_table.setItem(row, 10, QTableWidgetItem(str(count)))
                self.summary_table.setItem(row, 11, _make_bytes_item(stats['bytes_sent']))
                self.summary_table.setItem(row, 12, _make_bytes_item(stats['bytes_recv']))

                # Highlight suspect connections in red
                if suspect == "Yes":
                    for col in range(self.summary_table.columnCount()):
                        self.summary_table.item(row, col).setForeground(Qt.red)

            self.summary_table.setUpdatesEnabled(True)

            # Update title with total count
            for i in range(self.tab_widget.widget(1).layout().count()):
                item = self.tab_widget.widget(1).layout().itemAt(i)
                if item and isinstance(item.widget(), QLabel):
                    label = item.widget()
                    if "Connection Summary" in label.text():
                        label.setText(f"Connection Summary Statistics - {total_unique} unique connections ({total_connections} total)")
                        break

            # Apply sorting if a column was previously sorted
            global summary_table_column_sort_index, summary_table_column_sort_reverse
            if summary_table_column_sort_index >= 0:
                self.sort_summary_table_by_column(summary_table_column_sort_index, summary_table_column_sort_reverse)
                self._update_sort_indicator(self.summary_table, self._summary_table_base_headers,
                                            summary_table_column_sort_index, summary_table_column_sort_reverse)

            # Re-apply any active per-column filters
            self.apply_summary_table_filter()

        except Exception as e:
            logging.error(f"Error populating summary table: {e}")

    def select_table_row_by_connection(self, process, pid, remote, local):
        """Find and select the table row matching the connection details (called from map marker click)"""
        try:
            # Search for matching row in the connection table
            for row in range(self.connection_table.rowCount()):
                # Match by process, pid, remote address, and local address
                row_process = self.connection_table.item(row, PROCESS_ROW_INDEX)
                row_pid = self.connection_table.item(row, PID_ROW_INDEX)
                row_remote = self.connection_table.item(row, REMOTE_ADDRESS_ROW_INDEX)
                row_local = self.connection_table.item(row, LOCAL_ADDRESS_ROW_INDEX)

                if (row_process and row_process.text() == process and
                    row_pid and row_pid.text() == pid and
                    row_remote and row_remote.text() == remote and
                    row_local and row_local.text() == local):

                    # Found matching row - select it and scroll to make it visible
                    self.connection_table.selectRow(row)
                    self.connection_table.scrollToItem(row_process)

                    # Switch to Main tab if not already there (table is on Main tab)
                    if hasattr(self, 'tab_widget') and self.tab_widget.currentIndex() != 0:
                        self.tab_widget.setCurrentIndex(0)

                    logging.debug(f"Selected table row {row} from map marker click")
                    break
        except Exception as e:
            logging.error(f"Error selecting table row from map: {e}")

    def pin_connection_from_map(self, process, pid, protocol, local, localport, remote, remoteport, ip_type):
        """Pin a connection as yellow marker when clicked on the map. Same logic as table double-click."""
        new_pinned = {
            'process': process,
            'pid': pid,
            'protocol': protocol,
            'local': local,
            'localport': localport,
            'remote': remote,
            'remoteport': remoteport,
            'ip_type': ip_type,
        }

        # If clicking the same pinned connection, unpin it
        if self._pinned_connection is not None and self._is_pinned_connection(new_pinned):
            self._pinned_connection = None
            self._pinned_popup_open = False
            logging.debug("Unpinned connection (clicked same marker on map)")
        else:
            self._pinned_connection = new_pinned
            self._pinned_popup_open = True
            self._pinned_popup_generation += 1
            logging.debug(f"Pinned connection from map: {process} {remote} (gen {self._pinned_popup_generation})")

        # Select the matching table row
        self.select_table_row_by_connection(process, pid, remote, local)

        # Refresh to apply yellow icon + persistent popup
        try:
            self.refresh_connections(slider_position=self.slider.value())
        except Exception:
            pass

    @Slot(int, int)
    def _on_table_cell_clicked_deferred(self, row, column):
        """Defer the single-click action briefly so a double-click can cancel it."""
        self._pending_click = (row, column)
        self._click_timer.start(300)  # ms — slightly above the OS double-click interval

    @Slot()
    def _execute_deferred_click(self):
        """Run the single-click handler after the double-click window has elapsed."""
        if self._pending_click is not None:
            row, column = self._pending_click
            self._pending_click = None
            self.on_table_cell_clicked(row, column)

    @Slot(int, int)
    def on_table_cell_double_clicked(self, row, column):
        """Pin a connection as yellow marker on double-click. Persists across refreshes."""
        # Cancel any pending single-click so the map isn't redrawn twice
        self._click_timer.stop()
        self._pending_click = None

        if row >= self.connection_table.rowCount():
            return

        # Build a connection identity dict from the table row
        process_name = self.connection_table.item(row, PROCESS_ROW_INDEX).text() if self.connection_table.item(row, PROCESS_ROW_INDEX) else ''
        pid = self.connection_table.item(row, PID_ROW_INDEX).text() if self.connection_table.item(row, PID_ROW_INDEX) else ''
        protocol = self.connection_table.item(row, PROTOCOL_ROW_INDEX).text() if self.connection_table.item(row, PROTOCOL_ROW_INDEX) else 'TCP'
        local_address = self.connection_table.item(row, LOCAL_ADDRESS_ROW_INDEX).text() if self.connection_table.item(row, LOCAL_ADDRESS_ROW_INDEX) else ''
        local_port = self.connection_table.item(row, LOCAL_PORT_ROW_INDEX).text() if self.connection_table.item(row, LOCAL_PORT_ROW_INDEX) else ''
        remote_address = self.connection_table.item(row, REMOTE_ADDRESS_ROW_INDEX).text() if self.connection_table.item(row, REMOTE_ADDRESS_ROW_INDEX) else ''
        remote_port = self.connection_table.item(row, REMOTE_PORT_ROW_INDEX).text() if self.connection_table.item(row, REMOTE_PORT_ROW_INDEX) else ''
        ip_type = self.connection_table.item(row, IP_TYPE_ROW_INDEX).text() if self.connection_table.item(row, IP_TYPE_ROW_INDEX) else ''

        new_pinned = {
            'process': process_name,
            'pid': pid,
            'protocol': protocol,
            'local': local_address,
            'localport': local_port,
            'remote': remote_address,
            'remoteport': remote_port,
            'ip_type': ip_type,
        }

        # If double-clicking the same pinned connection, unpin it
        if self._pinned_connection is not None and self._is_pinned_connection(new_pinned):
            self._pinned_connection = None
            self._pinned_popup_open = False
            logging.debug("Unpinned connection (double-clicked same row)")
        else:
            self._pinned_connection = new_pinned
            self._pinned_popup_open = True
            self._pinned_popup_generation += 1
            logging.debug(f"Pinned connection: {process_name} {remote_address} (gen {self._pinned_popup_generation})")

        # Trigger the single-click handler to show the marker immediately (with correct color and auto-open popup)
        self.on_table_cell_clicked(row, column, auto_popup=True)

    def on_table_cell_clicked(self, row, column, auto_popup=False):
        """Handle single-click on a table row.

        Instead of building a one-element connection list (which would destroy
        all other markers/gauges), we set a lightweight focus state and ask
        _update_map_with_filter to re-render the full cached connection list.
        update_map() then applies the focus popup automatically.
        """
        if row >= self.connection_table.rowCount():
            return

        try:
            process_name = self.connection_table.item(row, PROCESS_ROW_INDEX).text() if self.connection_table.item(row, PROCESS_ROW_INDEX) else ''
            remote_address = self.connection_table.item(row, REMOTE_ADDRESS_ROW_INDEX).text() if self.connection_table.item(row, REMOTE_ADDRESS_ROW_INDEX) else ''
            local_address = self.connection_table.item(row, LOCAL_ADDRESS_ROW_INDEX).text() if self.connection_table.item(row, LOCAL_ADDRESS_ROW_INDEX) else ''
            protocol = self.connection_table.item(row, PROTOCOL_ROW_INDEX).text() if self.connection_table.item(row, PROTOCOL_ROW_INDEX) else 'TCP'
            local_port = self.connection_table.item(row, LOCAL_PORT_ROW_INDEX).text() if self.connection_table.item(row, LOCAL_PORT_ROW_INDEX) else ''
            remote_port = self.connection_table.item(row, REMOTE_PORT_ROW_INDEX).text() if self.connection_table.item(row, REMOTE_PORT_ROW_INDEX) else ''

            # Set focus state so update_map opens the popup for this connection
            self._click_focus_conn = {
                'process': process_name,
                'protocol': protocol,
                'local': local_address,
                'localport': local_port,
                'remote': remote_address,
                'remoteport': remote_port,
            }

            # Re-render the full map using the cached connection list
            self._update_map_with_filter()
        except Exception as e:
            logging.error(f"on_table_cell_clicked error: {e}")

def main():
    app = QApplication(sys.argv)
    _app_font = QFont("Consolas")
    _app_font.setStyleHint(QFont.StyleHint.Monospace)
    app.setFont(_app_font)
    viewer = TCPConnectionViewer()

    # Allow Ctrl-C in the console to close the application.
    # Qt's event loop holds the GIL and never returns control to Python's
    # signal machinery unless we periodically interrupt it with a no-op timer.
    def _handle_sigint(*_):
        logging.info("Received SIGINT — shutting down.")
        app.quit()

    signal.signal(signal.SIGINT, _handle_sigint)
    _sigint_timer = QTimer()
    _sigint_timer.setInterval(200)   # ms — yields the GIL so Python can check signals
    _sigint_timer.timeout.connect(lambda: None)
    _sigint_timer.start()

    if agent_no_ui and enable_agent_mode:
        # Headless agent mode: keep the window completely off-screen and off the taskbar.
        # Qt.Tool removes the taskbar button; combining with FramelessWindowHint + hiding
        # ensures the window cannot be restored by the user via the taskbar or other means.
        viewer.setWindowFlags(
            Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnBottomHint
        )
        # Never call show() — the window stays hidden for the entire lifetime.
    else:
        viewer.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()

