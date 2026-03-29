#!/usr/bin/env python3

# R001D00rs tcp_geo_map https://github.com/jclauzel/R001D00rs/

# pip install psutil, maxminddb PySide6 opencv-python procmon-parser flask scapy

# using https://github.com/pointhi/leaflet-color-markers for colored map markers
# using https://github.com/sapics/ip-location-db/tree/main/geolite2-city this script is using the MaxMind GeoLite2 database and is attributed accordingly for its usage.
# using OpenStreetMap and leaflet for map display and location data

# Summary
# R001D00rs tcp_geo_map is a cross-platform desktop network visibility and threat-hunting tool built with Python and PySide6.
#
# Core features:
#   - Live capture: enumerates active TCP/UDP connections in real time using psutil, with a configurable refresh interval.
#   - Geolocation: resolves remote IP addresses (IPv4 and IPv6) to city/country using the MaxMind GeoLite2 database (.mmdb).
#   - Interactive map: displays connections on a Leaflet/OpenStreetMap map embedded in a QWebEngineView, with colored markers
#       (green = normal, red = suspect/C2), polylines between local and remote endpoints, and clickable popups per connection.
#       A loading overlay with spinner is shown on map startup and replaced with a human-readable error if tiles fail to load
#       (e.g. no internet connectivity).
#   - C2/threat intel: optional cross-reference of remote IPs against the C2-Tracker community IOC feed (Shodan/Censys-sourced).
#   - Reverse DNS: background resolution of remote hostnames via a persistent DNS worker thread with in-memory and optional
#       on-disk cache (ip_cache.json) to accelerate repeated lookups.
#   - Connection table: sortable, filterable table of active connections showing process, PID, protocol, local/remote address
#       and port, resolved hostname, IP type, geolocation, and suspect flag.
#   - Summary table: per-process/IP aggregation view for quick traffic profiling.
#   - Time-travel replay: a FILO buffer (up to 1000 snapshots) with a time slider to replay historical connection states.
#   - Database management: automatic expiration check (7-day TTL) at startup and every 10 minutes at runtime; expired or missing
#       databases trigger a guided download flow (with --accept_eula flag for unattended automation).
#   - Screenshot capture: periodic JPEG snapshots of the map view saved to screen_captures/ for later review.
#   - Video export: assembles captured screenshots into an .mp4 timelapse using OpenCV.
#   - CSV export: exports the current connection table or full snapshot history to CSV.
#   - Process tools (Windows): right-click a connection to open its process in Task Manager, launch ProcDump for memory dump,
#       or auto-generate and launch a Process Monitor (.pmc) filter configuration scoped to that PID/process name.
#   - Settings persistence: UI state (map position/zoom, toggles, sort order, window geometry) saved to settings.json on exit
#       and restored on next launch.
#   - Offline resilience: Leaflet JS/CSS and marker icons can be downloaded locally (resources/leaflet/) and are used as
#       automatic CDN fallback so the map renders without internet access.
#   - Main UI handler class: `TCPConnectionViewer`.

""" 

Warranty, Disclaimer of Warranty, Limitation of Liability.

THE SCRIPT SOFTWARE IS PROVIDED "AS IS." THE AUTHOR MAKES NO WARRANTIES OF ANY KIND WHATSOEVER WITH RESPECT TO SCRIPT SOFTWARE WHICH MAY CONTAIN THIRD PARTY COMMERCIAL SOFTWARE. 

IN NO EVENT WILL THE AUTHOR BE LIABLE FOR ANY LOST REVENUE, PROFIT OR DATA, OR FOR DIRECT, SPECIAL, INDIRECT, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY ARISING OUT OF THE USE OF OR INABILITY TO USE THE SCRIPT SOFTWARE, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

    Other Important Notices:

    - When starting the application will download icons from https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img so internet access is required.

    - Using this application requires that YOU FULLY AGREE AND ACCEPT:
    
            MaxMind / GeoLite, folium, leaflet, OpenStreetMap, pyside licensing terms.
        
                as well as licensing terms of all contributing libraries to this script even though you use the --accept_eula startup option.

    - This script will persist to disk by default the dns names ip cache file defined in IP_DNS_NAME_CACHE_FILE to speed up startup (when PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK is set to True).. 
        If you don't want any cache file to speed up the application startup then set PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK to False.

    - Settings are persisted on applicaton end in a file called by default settings.json (defined in SETTINGS_FILE_NAME) that will be loaded next time the application start up. To reset settings simply delete the generated settings.json file.

    (kali) linux install using venv:

    git clone https://github.com/jclauzel/R001D00rs
    python3 -m venv ./venv
    source venv/bin/activate
    pip3 install psutil pyside6 requests maxminddb opencv-python procmon-parser scapy
    python3 tcp_geo_map.py

    Windows:
    pip3 install pyside6 requests maxminddb opencv-python procmon-parser scapy
"""

import requests, datetime, sys, os, threading, time, socket, csv, psutil, maxminddb, json, queue, logging, platform, subprocess, signal, ipaddress
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress Qt WebEngine Chromium warnings (must be set before QApplication)
os.environ['QT_LOGGING_RULES'] = '*.debug=false;qt.webenginecontext.debug=false'
os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = '--disable-logging --log-level=3'

# Configure logging
logging.basicConfig(
    level=logging.WARNING,  # Changed to INFO to see cleanup diagnostic messages
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                             QWidget, QTableWidget, QTableWidgetItem, QLabel,
                             QPushButton, QComboBox, QGroupBox, QFrame, QMessageBox, QCheckBox, QSlider, QToolButton, QSplitter, QHeaderView, QTextEdit, QTabWidget, QMenu, QScrollArea, QLineEdit, QDialog, QDialogButtonBox, QFileDialog)
from PySide6.QtGui import QIcon, QAction, QPixmap, QColor
from PySide6.QtCore import Qt, QTimer, QByteArray, QUrl, QObject, Signal, QRunnable, QThreadPool, Slot, QPoint, QSize
from PySide6.QtWidgets import QStyle
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineScript, QWebEngineProfile, QWebEngineUrlRequestInterceptor
from PySide6.QtWebChannel import QWebChannel

from connection_collector_plugin import ConnectionCollectorPlugin

VERSION = "3.4.0" # Current script version

assert sys.version_info >= (3, 8) # minimum required version of python for PySide6, maxminddb, psutil...

DATABASE_EXPIRE_AFTER_DAYS = 7 # Databases expiration time in days from download date, default 7 days (1 week)
DATABASE_EXPIRE_TIME_CHECK_INTERVAL = 600000 # Check for database expiration every 10 minutes (600000 ms)
DB_DIR = "databases" # Database location are contained in this subdirectory under the main script directory
SCREENSHOTS_DIR = "screen_captures"  # Screenshot directory for captured map images

IPV4_DB_PATH = os.path.join(DB_DIR, "geolite2-city-ipv4.mmdb")
IPV6_DB_PATH = os.path.join(DB_DIR, "geolite2-city-ipv6.mmdb")
C2_TRACKER_DB_PATH = os.path.join(DB_DIR, "all.txt")
SETTINGS_FILE_NAME = "settings.json"

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
LEAFLET_MARKER_RED_URL = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png"
LEAFLET_MARKER_GREEN_URL = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png"
LEAFLET_MARKER_BLUE_URL = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-blue.png"
LEAFLET_MARKER_YELLOW_URL = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-yellow.png"
LEAFLET_MARKER_ORANGE_URL = "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-orange.png"

LEAFLET_CSS_PATH = os.path.join(LEAFLET_DIR, "leaflet.css")
LEAFLET_JS_PATH = os.path.join(LEAFLET_DIR, "leaflet.js")
LEAFLET_MARKER_RED_PATH = os.path.join(LEAFLET_DIR, "marker-icon-2x-red.png")
LEAFLET_MARKER_GREEN_PATH = os.path.join(LEAFLET_DIR, "marker-icon-2x-green.png")
LEAFLET_MARKER_BLUE_PATH = os.path.join(LEAFLET_DIR, "marker-icon-2x-blue.png")
LEAFLET_MARKER_YELLOW_PATH = os.path.join(LEAFLET_DIR, "marker-icon-2x-yellow.png")
LEAFLET_MARKER_ORANGE_PATH = os.path.join(LEAFLET_DIR, "marker-icon-2x-orange.png")

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
LOCATION_LAT_ROW_INDEX = 11   # Index of the 'Location' column in the table
LOCATION_LON_ROW_INDEX = 12  # Index of the 'Location' column in the table
BYTES_SENT_ROW_INDEX = 13    # Index of the 'Sent' column in the table
BYTES_RECV_ROW_INDEX = 14    # Index of the 'Recv' column in the table
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
map_refresh_interval = 2000  # Map refresh time in milliseconds
show_only_new_active_connections = False # Show only new connections in the table
show_only_remote_connections = False # Hide local connections (ie 127.0.0.1 ::1)
table_column_sort_index = -1  # Default column index to sort the table by the index
table_column_sort_reverse = False  # Default sort order
summary_table_column_sort_index = -1  # Default column index to sort the summary table by the index
summary_table_column_sort_reverse = False  # Default sort order for summary table
do_reverse_dns = True  # Set to False to disable reverse DNS lookups
do_resolve_public_ip = False  # Set to True to resolve public IP addresses to hostnames (may slow down refresh)
do_drawlines_between_local_and_remote = True  # Set to True to draw lines between local and remote endpoints on the map
do_c2_check = False    # Set to True to enable C2-TRACKER checks
do_capture_screenshots = False  # Set to True to capture screenshots of the map to disk
do_pause_table_sorting = False  # Set to True to pause table sorting without stopping updates
do_show_traffic_gauge = False   # Set to True to show sent/recv traffic gauges next to markers (requires Scapy/PCAP collector)
USE_LOCAL_LEAFLET_FALLBACK = True  # allow using local resources when CDN fails

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
        """
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

            # For TCP, only ESTABLISHED; for UDP, all
            if is_tcp and conn.status != psutil.CONN_ESTABLISHED:
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
                                process_cache[pid] = process_name
                            except Exception:
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
                    else:
                        remote_addr = ""
                        remote_port = ""

                # Determine IP type
                family = getattr(conn, "family", None)
                ip_type = "IPv4" if family == socket.AF_INET else ("IPv6" if family == socket.AF_INET6 else "")

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
    #   green  = local connections, blue = new connections,
    #   red    = suspect/C2,        yellow = pinned marker,
    #   gold   = too similar to yellow (both ~#FFD326 / #CAC428).
    _AGENT_COLOR_PALETTE = ['orange', 'violet', 'black']

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
        self.connections = []

        # Pinned (double-clicked) connection — persists across refreshes, shown as yellow marker
        self._pinned_connection = None
        self._pinned_popup_open = False  # True while the pinned popup should stay open
        self._pinned_popup_generation = 0  # Monotonic counter — stale JS close events are ignored

        # Deferred single-click timer — allows double-click to cancel the single-click action
        self._click_timer = QTimer()
        self._click_timer.setSingleShot(True)
        self._click_timer.timeout.connect(self._execute_deferred_click)
        self._pending_click = None  # (row, column) awaiting execution

        # HTTP session for public IP checks (connection pooling)
        self._http_session = requests.Session()
        self._public_ip_cache = ""
        self._public_ip_cache_time = 0.0

        # --- Server / Agent mode runtime state ---
        # Server mode: cache of latest submissions from each agent
        # Key = hostname (str), Value = dict with keys:
        #   hostname, ip_addresses, lat, lng, connections (list of connection dicts)
        self._agent_cache = {}          # protected by _agent_cache_lock
        self._agent_cache_lock = threading.Lock()
        self._last_agent_count = 0      # number of agents collected in last cycle
        self._flask_thread = None       # daemon thread running Flask
        self._werkzeug_server = None    # werkzeug BaseServer instance (stoppable)
        # Per-agent color assignment: hostname -> color name (e.g. 'violet')
        # Colors are drawn round-robin from the agent palette (excludes colors
        # reserved for the UI: green=local, red=suspect, blue=new, yellow=pinned).
        self._agent_colors = {}         # hostname -> color name
        self._agent_color_index = 0     # next index into _AGENT_COLOR_PALETTE
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
        self._agent_post_thread.start()
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

        def _dns_notify(ip, hostname):
            # worker thread -> schedule debounced UI update on main thread
            try:
                QTimer.singleShot(0, lambda: self._on_dns_resolved(ip, hostname))
            except Exception:
                # fallback: no UI notification available
                pass

        self.dns_worker = DNSWorker(ip_cache, cache_lock, on_resolve=_dns_notify)
        self.dns_worker.start()

        # Initialize thread pool for async operations (video generation, etc.)
        self.thread_pool = QThreadPool()
        self.thread_pool.setMaxThreadCount(2)  # Limit concurrent background tasks

        # --- Connection collector plugin system ---
        self._collector_plugins = _discover_collector_plugins()
        self._active_collector = self._collector_plugins[0]  # default: PsutilCollector

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

        # Start Flask server if server mode was enabled (via CLI or settings)
        if enable_server_mode:
            self._start_flask_server()

        # Set up timer to refresh connections periodically

        self.timer.timeout.connect(self.refresh_connections)
        self.timer.start(map_refresh_interval)  # Refresh every 5 seconds
        self.timer_replay_connections.timeout.connect(self.replay_connections)

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

    def save_settings(self):
        """Save current settings to a JSON file"""

        # Apply loaded settings
        global max_connection_list_filo_buffer_size,do_c2_check, show_only_new_active_connections, show_only_remote_connections, do_reverse_dns, map_refresh_interval, table_column_sort_index, table_column_sort_reverse, summary_table_column_sort_index, summary_table_column_sort_reverse, do_resolve_public_ip, do_capture_screenshots, do_pause_table_sorting, do_show_traffic_gauge, agent_no_ui, agent_server_host, FLASK_SERVER_PORT, FLASK_AGENT_PORT, MAX_SERVER_AGENTS

        settings = {
            'max_connection_list_filo_buffer_size' : max_connection_list_filo_buffer_size,
            'do_c2_check' : do_c2_check,
            'show_only_new_active_connections': show_only_new_active_connections,
            'show_only_remote_connections': show_only_remote_connections,
            'do_reverse_dns': do_reverse_dns,
            'do_resolve_public_ip': do_resolve_public_ip,
            'do_capture_screenshots': do_capture_screenshots,
            'do_pause_table_sorting': do_pause_table_sorting,
            'do_show_traffic_gauge': do_show_traffic_gauge,
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
            'active_collector_plugin': self._active_collector.name,
            'pcap_file_path': getattr(self, '_pcap_file_path', ''),
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
                global summary_table_column_sort_index, summary_table_column_sort_reverse, do_resolve_public_ip, do_capture_screenshots, do_pause_table_sorting, do_show_traffic_gauge

                max_connection_list_filo_buffer_size = settings.get('max_connection_list_filo_buffer_size', max_connection_list_filo_buffer_size)

                do_c2_check = settings.get('do_c2_check', do_c2_check)
                show_only_new_active_connections = settings.get('show_only_new_active_connections', show_only_new_active_connections)
                show_only_remote_connections = settings.get('show_only_remote_connections', show_only_remote_connections)
                do_reverse_dns = settings.get('do_reverse_dns', do_reverse_dns)
                do_resolve_public_ip = settings.get('do_resolve_public_ip', do_resolve_public_ip)
                do_capture_screenshots = settings.get('do_capture_screenshots', do_capture_screenshots)
                do_pause_table_sorting = settings.get('do_pause_table_sorting', do_pause_table_sorting)
                do_show_traffic_gauge = settings.get('do_show_traffic_gauge', do_show_traffic_gauge)
                map_refresh_interval = settings.get('map_refresh_interval', map_refresh_interval)
                table_column_sort_index = settings.get('table_column_sort_index', table_column_sort_index)
                table_column_sort_reverse = settings.get('table_column_sort_reverse', table_column_sort_reverse)
                summary_table_column_sort_index = settings.get('summary_table_column_sort_index', summary_table_column_sort_index)
                summary_table_column_sort_reverse = settings.get('summary_table_column_sort_reverse', summary_table_column_sort_reverse)

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
                    # Advance color index past already-claimed colors so new agents
                    # don't collide with persisted assignments.
                    used_colors = list(self._agent_colors.values())
                    for _color in self._AGENT_COLOR_PALETTE:
                        if _color not in used_colors:
                            break
                        self._agent_color_index += 1

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
                self.refresh_interval_combo_box.setCurrentText(f"{map_refresh_interval_val}")

                self.only_show_new_connections.setChecked(show_only_new_active_connections)
                self.only_show_remote_connections.setChecked(show_only_remote_connections)
                self.reverse_dns_check.setChecked(do_reverse_dns)
                self.c2_check.setChecked(do_c2_check)
                self.resolve_public_ip.setChecked(do_resolve_public_ip)
                self.capture_screenshots_check.setChecked(do_capture_screenshots)
                self.pause_table_sorting_check.setChecked(do_pause_table_sorting)
                self.show_traffic_gauge_check.setChecked(do_show_traffic_gauge)

                # Update buffer size input field
                if hasattr(self, 'buffer_size_input'):
                    self.buffer_size_input.setText(str(max_connection_list_filo_buffer_size))

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
                    self._refresh_agent_management_table()

                # Restore active collector plugin in combo box
                if hasattr(self, '_collector_combo'):
                    for i in range(self._collector_combo.count()):
                        if self._collector_combo.itemText(i) == self._active_collector.name:
                            self._collector_combo.setCurrentIndex(i)
                            break

                # Restore pcap file path input
                if hasattr(self, '_pcap_path_input'):
                    self._pcap_path_input.setText(getattr(self, '_pcap_file_path', ''))
                if hasattr(self, '_pcap_path_row'):
                    self._pcap_path_row.setVisible(self._active_collector.name == "PCAP File Collector")

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
                self._refresh_agent_management_table()
        logging.info(f"Server mode {'enabled' if enable_server_mode else 'disabled'}")

    def _refresh_agent_management_table(self):
        """Rebuild the Agent Management table from the current agent registry."""
        if not hasattr(self, 'agent_mgmt_table'):
            return
        try:
            # Collect all known hostnames: from color map and from live cache
            known_hosts = set(self._agent_colors.keys())
            with self._agent_cache_lock:
                known_hosts.update(self._agent_cache.keys())
            known_hosts = sorted(known_hosts)

            self.agent_mgmt_table.setRowCount(0)

            for hostname in known_hosts:
                row = self.agent_mgmt_table.rowCount()
                self.agent_mgmt_table.insertRow(row)

                # Column 0 — hostname
                host_item = QTableWidgetItem(hostname)
                host_item.setFlags(Qt.ItemIsEnabled)
                self.agent_mgmt_table.setItem(row, 0, host_item)

                # Column 1 — color combo box with swatch + label per item
                color_combo = QComboBox()
                color_combo.setIconSize(QSize(16, 16))

                for color in self._AGENT_COLOR_PALETTE:
                    # Build a solid 16×16 swatch icon for each palette entry
                    pix = QPixmap(16, 16)
                    pix.fill(QColor(color))
                    color_combo.addItem(QIcon(pix), color)

                current_color = self._agent_colors.get(hostname)
                if current_color and current_color in self._AGENT_COLOR_PALETTE:
                    color_combo.setCurrentText(current_color)

                # Style the combo's display button to reflect the chosen color
                def _apply_combo_style(combo, chosen):
                    fg = 'white' if chosen in ('black', 'violet') else 'black'
                    combo.setStyleSheet(
                        f"QComboBox {{ background-color: {chosen}; color: {fg}; }}"
                        f"QComboBox QAbstractItemView {{ background-color: white; color: black; }}"
                    )

                if current_color and current_color in self._AGENT_COLOR_PALETTE:
                    _apply_combo_style(color_combo, current_color)

                # Capture hostname in closure
                def make_color_changed(hn, combo):
                    def _on_color_changed(_index):
                        chosen = combo.currentText()
                        self._agent_colors[hn] = chosen
                        _apply_combo_style(combo, chosen)
                        self.save_settings()
                        self._update_map_with_filter()
                    return _on_color_changed

                color_combo.currentIndexChanged.connect(make_color_changed(hostname, color_combo))
                self.agent_mgmt_table.setCellWidget(row, 1, color_combo)

                # Column 2 — Clear button
                clear_btn = QPushButton("Clear")
                clear_btn.setToolTip(f"Remove all saved settings for {hostname}")

                def make_clear_handler(hn):
                    def _on_clear():
                        self._agent_colors.pop(hn, None)
                        with self._agent_cache_lock:
                            self._agent_cache.pop(hn, None)
                        self.save_settings()
                        self._refresh_agent_management_table()
                        self._update_map_with_filter()
                    return _on_clear

                clear_btn.clicked.connect(make_clear_handler(hostname))
                self.agent_mgmt_table.setCellWidget(row, 2, clear_btn)

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
            self.save_settings()

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

        class _ConnCheckWorker(QRunnable):
            def run(self):
                url = f"http://{host}:{port}/submit_connections"
                try:
                    resp = requests.get(
                        f"http://{host}:{port}/",
                        timeout=4,
                        allow_redirects=False
                    )
                    # Any HTTP response means the server is reachable
                    QTimer.singleShot(0, lambda: viewer._on_conn_check_success())
                except requests.exceptions.ConnectionError:
                    msg = f"Connection refused — is the server running on {host}:{port}?"
                    QTimer.singleShot(0, lambda m=msg: viewer._on_conn_check_failure(m))
                except requests.exceptions.Timeout:
                    msg = f"Connection timed out reaching {host}:{port}."
                    QTimer.singleShot(0, lambda m=msg: viewer._on_conn_check_failure(m))
                except Exception as exc:
                    msg = str(exc)
                    QTimer.singleShot(0, lambda m=msg: viewer._on_conn_check_failure(m))

        self.thread_pool.start(_ConnCheckWorker())

    @Slot()
    def _on_conn_check_success(self):
        if not hasattr(self, 'agent_conn_status_label'):
            return
        self.agent_conn_status_label.setText("✔ Reachable")
        self.agent_conn_status_label.setStyleSheet("color: green; font-weight: bold;")

    @Slot(str)
    def _on_conn_check_failure(self, error_msg: str):
        if not hasattr(self, 'agent_conn_status_label'):
            return
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
            try:
                self.status_label.setText("Server mode requires Flask (pip install flask)")
            except Exception:
                pass
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
        self._last_agent_count = len(snapshot)

        # If any hostname in the snapshot is new (not yet in the table),
        # schedule a table refresh on the main thread.
        new_hosts = set(snapshot.keys()) - set(self._agent_colors.keys())
        if new_hosts and hasattr(self, 'agent_mgmt_table'):
            QTimer.singleShot(0, self._refresh_agent_management_table)

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
            # Fail silently (do not break startup). Optionally log to status_label if available.
            try:
                self.status_label.setText("Warning: failed to load ip_cache (continuing).")
            except Exception:
                pass

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
            try:
                self.status_label.setText("Warning: failed to save ip_cache.")
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

        chosen = menu.exec(self.connection_table.viewport().mapToGlobal(pos))
        if chosen is None:
            return

        if chosen == action_copy:
            QApplication.clipboard().setText(cell_text)
            return

        if chosen == action_bring_to_top:
            if row_hostname:
                self.bring_to_top_layer(row_hostname)
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
                                [procmon_exe, "/LoadConfig", abs_pmc],
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
                                [procmon_exe, "/LoadConfig", abs_pmc],
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

    def _sync_filter_widths(self):
        """Resize filter bar inputs to match the current connection table column widths."""
        try:
            vh_width = self.connection_table.verticalHeader().width()
            self._connection_filter_vheader_spacer.setFixedWidth(vh_width)
            total_width = vh_width
            for i, le in enumerate(self._connection_filter_inputs):
                col_width = self.connection_table.columnWidth(i)
                le.setFixedWidth(col_width)
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
        # Map column index -> connection dict key (mirrors the table setItem calls)
        col_to_key = {
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
        }
        for col, f in filters:
            getter = col_to_key.get(col)
            value = getter(conn).lower() if getter else ''
            if f not in value:
                return False
        return True

    @Slot()
    def apply_connection_table_filter(self):
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
        try:
            if hasattr(self, 'connections') and self.connections is not None:
                self._update_map_with_filter()
        except Exception:
            pass

    def _sync_summary_filter_widths(self):
        """Resize summary filter bar inputs to match the current summary table column widths."""
        try:
            vh_width = self.summary_table.verticalHeader().width()
            self._summary_filter_vheader_spacer.setFixedWidth(vh_width)
            total_width = vh_width
            for i, le in enumerate(self._summary_filter_inputs):
                col_width = self.summary_table.columnWidth(i)
                le.setFixedWidth(col_width)
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
            if table_column_sort_reverse:
                table_column_sort_reverse = False
            else:
                table_column_sort_reverse = True

        table_column_sort_index = index

        self.sort_table_by_column(index, table_column_sort_reverse)
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
        """Re-render the map using the current connections list filtered by the active
        column filters.  Agent exit-point circles are always rendered for every known
        agent regardless of whether any of their connections survive the filter."""
        try:
            if not hasattr(self, 'connections') or self.connections is None:
                return

            active_filters = self._get_active_filters()

            if not active_filters:
                # No filter — the last full render (from refresh_connections) is already correct
                return

            filtered = []
            # Collect the set of agent origin-hostnames that appear in the *full* connection
            # list so we can inject stub entries for any agent that has no matched connections
            # (their exit-point circle must still appear on the map).
            all_agent_origins = {}   # hostname -> first conn that carries origin info
            for conn in self.connections:
                oh = conn.get('origin_hostname')
                if oh and oh not in all_agent_origins:
                    all_agent_origins[oh] = conn

            matched_agent_origins = set()
            for conn in self.connections:
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
                        'agent_color':     ref_conn.get('agent_color', 'orange'),
                        'hostname':        hostname,
                    })

            # Re-use the last stats / datetime text from the most recent full render
            stats_line = getattr(self, '_last_stats_line', '')
            datetime_text = getattr(self, '_last_datetime_text', '')
            force_tooltip = show_tooltip
            self.update_map(filtered, force_tooltip,
                            stats_text=stats_line, datetime_text=datetime_text)
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

    def sort_table_by_column(self, column_index, reverse=False):
        """
        Sort the connection_table robustly.

        - Snapshot every row as a list of strings.
        - Detect numeric values for numeric sort (ints/floats).
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
            row_values = []
            for c in range(col_count):
                item = self.connection_table.item(r, c)
                row_values.append(item.text() if item is not None else "")
            # determine key from the sort column
            raw_key = row_values[column_index] if column_index < len(row_values) else ""
            # Build a (type_rank, value) tuple so mixed types never compare directly.
            # type_rank: 0 = numeric, 1 = non-empty string, 2 = empty (always last)
            if raw_key == "":
                sort_key = (2, "")
            else:
                try:
                    if raw_key.isdigit():
                        sort_key = (0, int(raw_key))
                    else:
                        normalized = raw_key.replace(",", "")
                        sort_key = (0, float(normalized))
                except Exception:
                    sort_key = (1, raw_key.lower())
            rows.append((sort_key, row_values))

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
        for _, row_values in rows:
            new_row = self.connection_table.rowCount()
            self.connection_table.insertRow(new_row)
            for c, text in enumerate(row_values):
                self.connection_table.setItem(new_row, c, QTableWidgetItem(text))
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
            if summary_table_column_sort_reverse:
                summary_table_column_sort_reverse = False
            else:
                summary_table_column_sort_reverse = True

        summary_table_column_sort_index = index

        self.sort_summary_table_by_column(index, summary_table_column_sort_reverse)

    def sort_summary_table_by_column(self, column_index, reverse=False):
        """
        Sort the summary_table robustly.

        - Snapshot every row as a list of strings.
        - Detect numeric values for numeric sort (ints/floats).
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
            row_values = []
            row_colors = []
            for c in range(col_count):
                item = self.summary_table.item(r, c)
                row_values.append(item.text() if item is not None else "")
                # Store the foreground color to preserve red highlighting
                row_colors.append(item.foreground() if item is not None else None)

            # determine key from the sort column
            raw_key = row_values[column_index] if column_index < len(row_values) else ""
            # Build a (type_rank, value) tuple so mixed types never compare directly.
            # type_rank: 0 = numeric, 1 = non-empty string, 2 = empty (always last)
            if raw_key == "":
                sort_key = (2, "")
            else:
                try:
                    if raw_key.isdigit():
                        sort_key = (0, int(raw_key))
                    else:
                        normalized = raw_key.replace(",", "")
                        sort_key = (0, float(normalized))
                except Exception:
                    sort_key = (1, raw_key.lower())
            rows.append((sort_key, row_values, row_colors))

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
        for _, row_values, row_colors in rows:
            new_row = self.summary_table.rowCount()
            self.summary_table.insertRow(new_row)
            for c, text in enumerate(row_values):
                item = QTableWidgetItem(text)
                # Restore original color if it was saved
                if c < len(row_colors) and row_colors[c] is not None:
                    item.setForeground(row_colors[c])
                self.summary_table.setItem(new_row, c, item)
        self.summary_table.setUpdatesEnabled(True)

     # Update connection list when slider changes
    @Slot(int)
    def update_slider_value(self, value):

        # Update your connection list 
        self.slider.setMaximum(self.connection_list_counter)

        self.timer.stop()
        self.status_label.setText("Auto-refresh paused. Click 'Start Capture' to resume.")

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
                    if hasattr(self, 'status_label'):
                        self.status_label.setText("Auto-refreshing connections.")

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
                f"Connection list timeline {timeline_index} data saved to {full_path}"
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
            except Exception:
                pass

            self.status_label.setText("Replaying connections.")

            # Start refresh timer or process here
            self.timer_replay_connections.start(map_refresh_interval)

            self.start_capture_btn.setVisible(False)
            self.stop_capture_btn.setVisible(False)
            # Stop wave animation when replay starts
            self._stop_stop_button_wave()
            # Stop flashing when replay starts
            self._stop_capture_button_flash()

        else:
            try:
                self.toggle_action.setIcon(self._toggle_play_icon)
            except Exception:
                pass

            self.status_label.setText("Connection replay paused.")

            # Stop refresh timer or process here
            self.timer_replay_connections.stop()
            self.start_capture_btn.setVisible(True)
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
        self.stop_capture_btn.setStyleSheet("font-family: 'Consolas', 'Courier New', monospace;")
        
        # Connection table
        self.connection_table = QTableWidget(0, BYTES_RECV_ROW_INDEX+1)
        self.connection_table.setHorizontalHeaderLabels([
            "Hostname", "Process", "PID", "C2", "Protocol", "Local Addr", "Local Port", "Remote Addr", "Remote Port", "Name", "IP Type", "Loc lat", "Loc lon", "Sent", "Recv"
        ])

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

        self.connection_table.horizontalHeader().setMinimumSectionSize(SUSPECT_COLUMN_SIZE)

        # Per-column filter bar — one QLineEdit per column, scrolls in sync with the table
        _filter_placeholders = [
            "Hostname", "Process", "PID", "C2", "Protocol", "Local Addr", "Local Port",
            "Remote Addr", "Remote Port", "Name", "IP Type", "Lat", "Lon", "Sent", "Recv"
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

        self.right_splitter = QSplitter(Qt.Vertical)
        self.right_splitter.setHandleWidth(6)

        # Controls container placed below the map in the vertical splitter
        self.controls_widget = QWidget()
        self.controls_layout = QVBoxLayout(self.controls_widget)
        self.controls_layout.setContentsMargins(0, 0, 0, 0)
        self.controls_layout.setSpacing(6)

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
        self.controls_layout.addWidget(self.toggle_button)      

        self.refresh_interval_combo_box = QComboBox()
        self.refresh_interval_combo_box.setToolTip("Select map refresh interval in milliseconds")
        self.refresh_interval_combo_box.addItems(["2000", "5000", "10000", "20000", "30000", "40000", "50000", "120000", "300000", "600000", "1200000", "180000000"])
        self.refresh_interval_combo_box.currentIndexChanged.connect(self.update_refresh_interval)
        self.update_refresh_interval()
        self.controls_layout.addWidget(self.refresh_interval_combo_box)

        # Status label
        self.status_label = QLabel("Auto-refreshing connections.")
        self.status_label.setAlignment(Qt.AlignTop)
        self.controls_layout.addWidget(self.status_label)

        # Generate video button (shown only when screenshots exist)
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
        self.summary_table = QTableWidget(0, 12)
        self.summary_table.setHorizontalHeaderLabels([
            "Hostname", "Process", "PID", "C2", "Protocol", "Local Address", "Remote Address", "Type", "Name", "Count", "Sent", "Recv"
        ])
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
            "Hostname", "Process", "PID", "C2", "Protocol", "Local Address", "Remote Address", "Type", "Name", "Count", "Sent", "Recv"
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
        self.only_show_remote_connections = QCheckBox("Hide local connections on tables")
        self.only_show_remote_connections.setChecked(False)
        settings_tab_layout.addWidget(self.only_show_remote_connections)    
        self.only_show_remote_connections.stateChanged.connect(self.only_show_remote_connections_changed)

        # Resolve public IP using ipfy checkbox
        self.resolve_public_ip = QCheckBox("Resolve public internet IP using ipfy.com")
        self.resolve_public_ip.setChecked(False)
        settings_tab_layout.addWidget(self.resolve_public_ip)    
        self.resolve_public_ip.stateChanged.connect(self.update_resolve_public_ip)

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

        # Pause table sorting checkbox
        self.pause_table_sorting_check = QCheckBox("Pause main tab connection table sorting")
        self.pause_table_sorting_check.setChecked(False)
        self.pause_table_sorting_check.stateChanged.connect(self.update_pause_table_sorrting)
        settings_tab_layout.addWidget(self.pause_table_sorting_check)

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
            self._collector_combo.addItem(plugin.name)
            idx = self._collector_combo.count() - 1
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

        self.agent_mgmt_table = QTableWidget(0, 3)
        self.agent_mgmt_table.setHorizontalHeaderLabels(["Hostname", "Color", "Action"])
        self.agent_mgmt_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.agent_mgmt_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.agent_mgmt_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.agent_mgmt_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.agent_mgmt_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
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
                elif db_path == IPV6_DB_PATH:
                    if self.reader_ipv6 is not None:
                        self.reader_ipv6.close()
                    self.reader_ipv6 = maxminddb.open_database(IPV6_DB_PATH)
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
                (LEAFLET_MARKER_RED_PATH, LEAFLET_MARKER_RED_URL, "Red marker icon"),
                (LEAFLET_MARKER_GREEN_PATH, LEAFLET_MARKER_GREEN_URL, "Green marker icon"),
                (LEAFLET_MARKER_BLUE_PATH, LEAFLET_MARKER_BLUE_URL, "Blue marker icon"),
                (LEAFLET_MARKER_YELLOW_PATH, LEAFLET_MARKER_YELLOW_URL, "Yellow marker icon"),
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

            connections = []
            
            for conn in psutil.net_connections(kind='inet4'):
                if conn.status == psutil.CONN_ESTABLISHED:
                    try:
                        # Get process information
                        process = psutil.Process(conn.pid) if conn.pid else None
                        process_name = process.name() if process else "Unknown"
                        
                        # Get local and remote addresses
                        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                        
                        # Determine IP type
                        ip_type = ""
                        if conn.family == socket.AF_INET:
                            ip_type = "IPv4"
                        elif conn.family == socket.AF_INET6:
                            ip_type = "IPv6"
                        
                        connections.append({
                            'process': process_name,
                            'pid': str(conn.pid) if conn.pid else "",
                            'suspect': '',
                            'local': local_addr,
                            'remote': remote_addr,
                            'name': 'N/A',
                            'ip_type': ip_type,
                            'connection': conn,
                            'icon': 'greenIcon'
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        # Skip connections that can't be accessed
                        continue
                        
            return connections
        
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
        _prev_conn_keys = set()
        if self.connection_list:
            try:
                for _pc in self.connection_list[-1]['connection_list']:
                    _prev_conn_keys.add((
                        _pc.get('process', ''), _pc.get('pid', ''),
                        _pc.get('protocol', ''), _pc.get('local', ''),
                        _pc.get('localport', ''), _pc.get('remote', ''),
                        _pc.get('remoteport', ''), _pc.get('ip_type', ''),
                    ))
            except Exception:
                pass

        # --- Phase 3: Enrich each raw connection with geo/DNS/C2/icons -------
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
                            remote_addr = f"{remote_addr} ({resolved})"
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
                    'icon': 'greenIcon',
                    'hostname': hostname,
                    'bytes_sent': bytes_sent,
                    'bytes_recv': bytes_recv,
                })

                # New connection detection — O(1) set lookup
                if _prev_conn_keys:
                    _key = (process_name, pid, protocol, local_addr, local_port,
                            remote_addr, remote_port, ip_type)
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
            another_connection = {
                "datetime": datetime.datetime.now(),
                "connection_list": connections,
                "agent_data": agent_snapshot if enable_server_mode and agent_snapshot else None,
            }

            # append — deque with maxlen auto-evicts the oldest entry
            self.connection_list.append(another_connection)
            self.connection_list_counter = len(self.connection_list)

            # keep slider in sync
            self.slider.setMaximum(self.connection_list_counter)
            self.slider_value_label.setText(TIME_SLIDER_TEXT + str(self.slider.value()) + "/" + str(len(self.connection_list)-1))

            if self.timer.isActive():
                self.slider.valueChanged.disconnect(self.update_slider_value)
                self.slider.setValue(self.connection_list_counter)
                self.slider.valueChanged.connect(self.update_slider_value)

            # If Summary tab is active, refresh it with new data
            try:
                if hasattr(self, 'tab_widget') and self.tab_widget.currentIndex() == 1:
                    self.update_summary_table()
            except Exception:
                pass

            # Capture screenshot if enabled (only for live captures, not timeline replay)

            if do_capture_screenshots:
                try:
                    logging.debug(f"Scheduling screenshot capture (buffer counter={self.connection_list_counter})")
                    # Schedule screenshot capture after a short delay to ensure map is fully rendered
                    QTimer.singleShot(1500, self._capture_map_screenshot)
                except Exception as e:
                    logging.error(f"Failed to schedule screenshot capture: {e}")

            # Update video button visibility whenever connections are refreshed
            try:
                self._update_video_button_visibility()
            except Exception:
                pass

            # Mark summary as needing update
            self._summary_needs_update = True

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
        """Get coordinates for an IP address"""

        if ip_type == "IPv4":
            try:
                # Get coordinates from the database
                result = self.reader_ipv4.get(ip_address)
                if result is not None:
                    lat = result.get('latitude') or result.get('location', {}).get('latitude')
                    lng = result.get('longitude') or result.get('location', {}).get('longitude')
                    if lat is not None and lng is not None:
                        return lat, lng
            except:
                pass

            return None, None

        elif ip_type == "IPv6":
            try:
                # Get coordinates from the database
                result = self.reader_ipv6.get(ip_address)
                if result is not None:
                    lat = result.get('latitude') or result.get('location', {}).get('latitude')
                    lng = result.get('longitude') or result.get('location', {}).get('longitude')
                    if lat is not None and lng is not None:
                        return lat, lng
            except:
                pass

            return None, None

        else:
            return None, None
            
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
                        self._pulse_map_indicator()
                        # Reset reload counter on successful call
                        try:
                            self._map_reload_attempts = 0
                        except Exception:
                            pass
                    except Exception as e:
                        # Log error but don't reload to prevent infinite loop
                        logging.error(f"Failed to execute map update JS: {e}")
                        try:
                            self.status_label.setText("Map update failed. Try refreshing manually.")
                        except Exception:
                            pass
                else:
                    # Decrement retries
                    retries_remaining[0] -= 1

                    if retries_remaining[0] <= 0:
                        # Give up - show error instead of reloading
                        logging.warning("Map initialization failed - updateConnections function not found (exhausted retries)")
                        try:
                            self.status_label.setText("Map failed to initialize. Check network connection or local resources.")
                        except Exception:
                            pass
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
            try:
                self.status_label.setText("Map error occurred.")
            except Exception:
                pass

    _PUBLIC_IP_TTL = 60  # seconds between external IP lookups

    def get_public_ip(self):
        """Get public IP address using ipify API with connection pooling and TTL cache.

        The result is cached for ``_PUBLIC_IP_TTL`` seconds so that the
        blocking HTTP call is not repeated on every 2-second refresh cycle.
        Returns empty string on error.
        """
        now = time.time()
        if self._public_ip_cache and (now - self._public_ip_cache_time) < self._PUBLIC_IP_TTL:
            return self._public_ip_cache
        try:
            response = self._http_session.get('https://api.ipify.org', timeout=5)
            if response.status_code == 200:
                result = response.text.strip()
                self._public_ip_cache = result
                self._public_ip_cache_time = now
                return result
            else:
                return self._public_ip_cache or ""
        except Exception:
            return self._public_ip_cache or ""

    def update_map(self, connection_data, force_show_tooltip=False, stats_text="", datetime_text=""):
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
                            'icon': 'redCircle'
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
            for conn in list(connection_data):
                origin_hostname = conn.get('origin_hostname')
                origin_lat = conn.get('origin_lat')
                origin_lng = conn.get('origin_lng')
                if origin_hostname and origin_lat is not None and origin_lng is not None:
                    key = origin_hostname
                    if key not in seen_agent_origins:
                        seen_agent_origins.add(key)
                        origin_ip = conn.get('origin_public_ip', '')
                        agent_color = conn.get('agent_color', 'orange')
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

        data_json = json.dumps(connection_data)
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

        # Send stats_text, datetime_text, recording indicator, mode indicator, rejected overlay, and agent status to JS.
        # Each call is wrapped in its own try/catch so that a failure in one (e.g. updateConnections
        # throwing on bad data) does not prevent the subsequent status/overlay calls from executing.
        js = (
            f"try{{updateConnections({data_json}, {str(force_show_tooltip).lower()}, {str(draw_lines).lower()}, {str(do_show_traffic_gauge).lower()})}}catch(e){{console.error('updateConnections error',e)}};"
            f"try{{setStats({json.dumps(stats_text)})}}catch(e){{}};"
            f"try{{setDateTime({json.dumps(datetime_text)})}}catch(e){{}};"
            f"try{{setRecordingIndicator({str(is_recording).lower()})}}catch(e){{}};"
            f"try{{setModeIndicator({json.dumps(mode_indicator_text)})}}catch(e){{}};"
            f"try{{setRejectedOverlay({show_rejected})}}catch(e){{}};"
            f"try{{setAgentStatus({json.dumps(agent_status_text)})}}catch(e){{}}"
        )

        # Check reload attempt limit to prevent infinite loops
        if not getattr(self, "map_initialized", False):
            # Prevent infinite reload loop
            if getattr(self, "_map_reload_attempts", 0) >= 3:
                logging.error("Max map reload attempts (3) reached. Stopping to prevent infinite loop.")
                try:
                    self.status_label.setText("Map failed to load after 3 attempts. Try restarting the application.")
                except Exception:
                    pass
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
                                        for (var i = 0; i < liveMarkers.length; i++) {
                                            try {
                                                var m = liveMarkers[i];
                                                if (typeof m.getLatLng === 'function') {
                                                    bounds.push(m.getLatLng());
                                                } else if (typeof m.getBounds === 'function') {
                                                    bounds.push(m.getBounds().getCenter());
                                                }
                                            } catch(ex) {}
                                        }
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

                                    // Helper: format byte count to human-readable string
                                    function _formatBytes(bytes) {
                                        if (bytes === 0) return '0 B';
                                        var k = 1024;
                                        var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                                        var i = Math.floor(Math.log(bytes) / Math.log(k));
                                        if (i >= sizes.length) i = sizes.length - 1;
                                        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
                                    }

                                    function updateConnections(conns, showTooltip, drawLines, showGauge) {
                                        // Guard: suppress popupclose handlers during programmatic marker removal
                                        // Unbind popupclose on all markers BEFORE removing them to avoid
                                        // async events falsely setting _pinnedPopupDismissed.
                                        window._removingMarkers = true;
                                        for (var i=0; i<liveMarkers.length; i++) {
                                            try { liveMarkers[i].off('popupclose'); } catch(e) {}
                                            try { map.removeLayer(liveMarkers[i]); } catch(e) {}
                                        }
                                        window._removingMarkers = false;
                                        liveMarkers = [];

                                        if (!conns || !Array.isArray(conns)) { return; }

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

                                        var publicIpCoords = null;
                                        // Per-agent origin coordinates: { hostname: [lat, lng] }
                                        var agentOriginCoords = {};
                                        // Per-agent color: { hostname: colorName }
                                        var agentOriginColors = {};
                                        // Markers originating from server (no origin_hostname)
                                        var serverMarkerCoords = [];
                                        // Markers originating from agents: { hostname: [[lat,lng], ...] }
                                        var agentMarkerCoords = {};

                                        conns.forEach(function(conn) {
                                            if (conn.lat && conn.lng) {
                                                var iconName = conn.icon || 'greenIcon';

                                                if (iconName === 'redCircle') {
                                                    // Create a red circle for server public IP - ON TOP OF ALL MARKERS
                                                    var circle = L.circle([conn.lat, conn.lng], {
                                                        color: 'red',
                                                        fillColor: '#f03',
                                                        fillOpacity: 0.5,
                                                        radius: 100000,
                                                        pane: 'publicIpPane'  // Use custom pane with higher z-index
                                                    }).addTo(map);

                                                    var tooltipOptions = { permanent: !!showTooltip, opacity: 0.9, direction: 'auto' };
                                                    circle.bindTooltip(conn.remote || 'Public IP', tooltipOptions);

                                                    var popupHtml = "<b>Server Public IP</b><br>" +
                                                                    "IP: " + (conn.remote || '') + "<br>";
                                                    circle.bindPopup(popupHtml);
                                                    liveMarkers.push(circle);

                                                    // Save server public IP coordinates for line drawing
                                                    publicIpCoords = [conn.lat, conn.lng];

                                                } else if (iconName === 'agentCircle') {
                                                                     // Create a colored circle for agent exit point using the agent's assigned color
                                                                     var agentColor = conn.agent_color || 'orange';
                                                                     // Map palette names to CSS fill colors
                                                                     var agentFillColors = {
                                                                         orange: '#ff8c00', violet: '#9c2bcb',
                                                                         grey:   '#7b7b7b', black:  '#3d3d3d',
                                                                         gold:   '#ffd326'
                                                                     };
                                                                     var fillColor = agentFillColors[agentColor] || agentColor;

                                                                     // Create a dedicated pane for this agent if it doesn't exist yet,
                                                                     // using the z-index provided by Python for z-layer ordering.
                                                                     var agentHostname = conn.origin_hostname || conn.name || '';
                                                                     var agentPaneName = agentHostname
                                                                         ? 'agentPane_' + agentHostname.replace(/[^a-zA-Z0-9]/g, '_')
                                                                         : 'publicIpPane';
                                                                     var agentPaneZ = (typeof conn.pane_z === 'number') ? conn.pane_z : 620;
                                                                     if (agentHostname && !map.getPane(agentPaneName)) {
                                                                         map.createPane(agentPaneName);
                                                                         map.getPane(agentPaneName).style.zIndex = agentPaneZ;
                                                                     }

                                                                     var agentCircle = L.circle([conn.lat, conn.lng], {
                                                                         color: agentColor,
                                                                         fillColor: fillColor,
                                                                         fillOpacity: 0.5,
                                                                         radius: 80000,
                                                                         pane: agentHostname ? agentPaneName : 'publicIpPane'
                                                                     }).addTo(map);

                                                                     var tooltipOptions = { permanent: !!showTooltip, opacity: 0.9, direction: 'auto' };
                                                                     agentCircle.bindTooltip(conn.remote || 'Agent', tooltipOptions);

                                                                     var popupHtml = "<b>Agent Exit Point</b><br>" +
                                                                                     (conn.remote || '') + "<br>" +
                                                                                     "Hostname: " + (conn.name || '') + "<br>" +
                                                                                     "<i style='font-size:11px;color:#555'>Click to bring to foreground</i>";
                                                                     agentCircle.bindPopup(popupHtml);

                                                                     // Click on agent circle → promote that agent to foreground
                                                                     (function(hostName) {
                                                                         agentCircle.on('click', function(e) {
                                                                             try {
                                                                                 if (mapBridge && typeof mapBridge.setForegroundHost === 'function') {
                                                                                     console.log('[AgentCircle Click] Bringing to foreground:', hostName);
                                                                                     mapBridge.setForegroundHost(hostName);
                                                                                 }
                                                                             } catch(ex) {
                                                                                 console.error('[AgentCircle Click] Error:', ex);
                                                                             }
                                                                         });
                                                                     })(agentHostname);

                                                                     liveMarkers.push(agentCircle);

                                                                     // Track agent origin coordinates and color for line drawing
                                                                     if (agentHostname) {
                                                                         agentOriginCoords[agentHostname] = [conn.lat, conn.lng];
                                                                         agentOriginColors[agentHostname] = agentColor;
                                                                     }

                                                } else {
                                                    // Regular marker
                                                    var icon = iconDefinitions[iconName] || iconDefinitions['greenIcon'];
                                                    var markerOptions = { icon: icon };
                                                    // Pinned (yellow) markers render on a higher pane so they stay on top
                                                    if (iconName === 'yellowIcon') {
                                                        markerOptions.pane = 'pinnedPane';
                                                    }
                                                    var marker = L.marker([conn.lat, conn.lng], markerOptions).addTo(map);
                                                    var tooltipOptions = { permanent: !!showTooltip, opacity: 0.9, direction: 'auto' };

                                                    // Include protocol and hostname in tooltip for agent connections
                                                    var tooltipText = (conn.process || '') + ' [' + (conn.protocol || 'TCP') + ']';
                                                    if (conn.origin_hostname) {
                                                        tooltipText += ' @' + conn.origin_hostname;
                                                    }
                                                    marker.bindTooltip(tooltipText, tooltipOptions);

                                                    // Build popup HTML — include byte stats when available
                                                    var popupHtml = "<b>" + (conn.process || '') + "</b><br>" +
                                                                    "Protocol: " + (conn.protocol || 'TCP') + "<br>" +
                                                                    "PID: " + (conn.pid || '') + "<br>" +
                                                                    "Remote: " + (conn.remote || '') + "<br>" +
                                                                    "Local: " + (conn.local || '') + "<br>" +
                                                                    (conn.name ? "Name: " + conn.name + "<br>" : "") +
                                                                    (conn.origin_hostname ? "Source: " + conn.origin_hostname + "<br>" : "");
                                                    var bSent = conn.bytes_sent || 0;
                                                    var bRecv = conn.bytes_recv || 0;
                                                    if (bSent > 0 || bRecv > 0) {
                                                        popupHtml += "<hr style='margin:4px 0'>" +
                                                                     "<span style='color:#d32f2f'>&#9650; Sent:</span> " + _formatBytes(bSent) + "<br>" +
                                                                     "<span style='color:#388e3c'>&#9660; Recv:</span> " + _formatBytes(bRecv) + "<br>";
                                                    }
                                                    marker.bindPopup(popupHtml, {autoClose: false, closeOnClick: false});

                                                    // --- Traffic gauge (DivIcon marker beside the main marker) ---
                                                    if (showGauge && (bSent > 0 || bRecv > 0)) {
                                                        var gaugeHeight = 40; // px — fixed total height
                                                        // Each portion's height is proportional to the global max
                                                        var sentH = Math.round((bSent / maxSent) * (gaugeHeight / 2));
                                                        var recvH = Math.round((bRecv / maxRecv) * (gaugeHeight / 2));
                                                        var emptyH = gaugeHeight - sentH - recvH;
                                                        var gaugeHtml = '<div class="traffic-gauge" style="height:' + gaugeHeight + 'px" title="Sent: ' + _formatBytes(bSent) + ' / Recv: ' + _formatBytes(bRecv) + '">' +
                                                                        '<div class="tg-empty" style="height:' + emptyH + 'px;"></div>' +
                                                                        '<div class="tg-recv" style="height:' + recvH + 'px;"></div>' +
                                                                        '<div class="tg-sent" style="height:' + sentH + 'px;"></div>' +
                                                                        '</div>';
                                                        var gaugeIcon = L.divIcon({
                                                            className: 'traffic-gauge-icon',
                                                            html: gaugeHtml,
                                                            iconSize: [12, gaugeHeight + 2],
                                                            iconAnchor: [-8, gaugeHeight]
                                                        });
                                                        var gaugeMarker = L.marker([conn.lat, conn.lng], {
                                                            icon: gaugeIcon,
                                                            interactive: false,
                                                            pane: 'gaugePane'
                                                        }).addTo(map);
                                                        liveMarkers.push(gaugeMarker);
                                                    }

                                                    // Add click handler to select corresponding table row in Python.
                                                     // We unbind the popup before calling pinConnection so that
                                                     // Leaflet's internal click-to-open-popup path doesn't fire
                                                     // a popup that will immediately be destroyed by the refresh.
                                                     (function(connection, m) {
                                                         m.on('click', function(e) {
                                                             try {
                                                                 // Prevent Leaflet from opening / re-opening the popup
                                                                 // on this click — the refresh will handle it.
                                                                 m.closePopup();
                                                                 m.off('popupclose');
                                                                 if (mapBridge && typeof mapBridge.pinConnection === 'function') {
                                                                     console.log('[Marker Click] Calling Python pinConnection:', connection.process, connection.pid, connection.remote, connection.local);
                                                                     mapBridge.pinConnection(
                                                                         connection.process || '',
                                                                         connection.pid || '',
                                                                         connection.protocol || 'TCP',
                                                                         connection.local || '',
                                                                         connection.localport || '',
                                                                         connection.remote || '',
                                                                         connection.remoteport || '',
                                                                         connection.ip_type || ''
                                                                     );
                                                                 } else {
                                                                     console.warn('[Marker Click] mapBridge not ready yet');
                                                                 }
                                                                 // Bring the marker's agent to the foreground layer
                                                                 var markerHost = connection.origin_hostname || connection.hostname || '';
                                                                 if (markerHost && mapBridge && typeof mapBridge.setForegroundHost === 'function') {
                                                                     mapBridge.setForegroundHost(markerHost);
                                                                 }
                                                             } catch(e) {
                                                                 console.error('[Marker Click] Error calling pinConnection:', e);
                                                             }
                                                         });
                                                     })(conn, marker);

                                                    // Auto-open popup when triggered by pinned connection
                                                    if (conn.autoPopup) {
                                                        marker.openPopup();
                                                        // Notify Python when the user manually closes the popup.
                                                        // Pass the generation counter so Python can ignore stale events.
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

                                                    liveMarkers.push(marker);

                                                    // Classify marker for line drawing based on origin
                                                    var connOrigin = conn.origin_hostname || '';
                                                    if (connOrigin) {
                                                        // Agent connection — group under its agent origin
                                                        if (!agentMarkerCoords[connOrigin]) {
                                                            agentMarkerCoords[connOrigin] = [];
                                                        }
                                                        agentMarkerCoords[connOrigin].push([conn.lat, conn.lng]);
                                                    } else {
                                                        // Server (local) connection
                                                        serverMarkerCoords.push([conn.lat, conn.lng]);
                                                    }
                                                }
                                            }
                                        });

                                        // Draw lines if enabled
                                        if (drawLines) {
                                            // Draw blue dashed lines from server public IP to server connections
                                            if (publicIpCoords && serverMarkerCoords.length > 0) {
                                                serverMarkerCoords.forEach(function(markerCoords) {
                                                    var polyline = L.polyline([publicIpCoords, markerCoords], {
                                                        color: 'blue',
                                                        weight: 2,
                                                        opacity: 0.6,
                                                        dashArray: '5, 10'
                                                    }).addTo(map);
                                                    liveMarkers.push(polyline);
                                                });
                                            }

                                            // Draw colored dashed lines from each agent's exit point to its connections
                                            Object.keys(agentOriginCoords).forEach(function(hostname) {
                                                var originCoords = agentOriginCoords[hostname];
                                                var lineColor = agentOriginColors[hostname] || 'orange';
                                                var markers = agentMarkerCoords[hostname] || [];
                                                markers.forEach(function(markerCoords) {
                                                    var polyline = L.polyline([originCoords, markerCoords], {
                                                        color: lineColor,
                                                        weight: 2,
                                                        opacity: 0.6,
                                                        dashArray: '5, 10'
                                                    }).addTo(map);
                                                    liveMarkers.push(polyline);
                                                });
                                            });

                                            // For agent connections whose origin has no geolocation,
                                            // fall back to drawing from server public IP if available
                                            if (publicIpCoords) {
                                                Object.keys(agentMarkerCoords).forEach(function(hostname) {
                                                    if (!agentOriginCoords[hostname]) {
                                                        agentMarkerCoords[hostname].forEach(function(markerCoords) {
                                                            var polyline = L.polyline([publicIpCoords, markerCoords], {
                                                                color: 'gray',
                                                                weight: 1,
                                                                opacity: 0.4,
                                                                dashArray: '3, 8'
                                                            }).addTo(map);
                                                            liveMarkers.push(polyline);
                                                        });
                                                    }
                                                });
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
            self.map_view.setHtml(html_with_path, QUrl("about:blank"))

            def _on_loaded(ok):
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
            try:
                self.status_label.setText("Map update error occurred.")
            except Exception:
                pass

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
            self.status_label.setText("Auto-refresh paused. Click 'Start Capture' to resume.")
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
                self.status_label.setText("")
                self.toggle_button.setVisible(False)
                self.stop_capture_btn.setVisible(True)
                # Stop flashing when capture starts
                self._stop_capture_button_flash()
                # Start wave animation on stop button
                self._start_stop_button_wave()

        if self.timer_replay_connections.isActive():
            self.status_label.setText("Replaying connections.")

        number_of_previous_objects = self.map_objects

        self.connections = self.get_active_tcp_connections(slider_position)


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
                if conn['icon'] == 'blueIcon':
                    force_tooltip = True

                lat, lng = None, None

                # Get coordinates for map
                if conn['ip_type'] == 'IPv4':
                    ip = conn['remote'].split(':')[0]# if ':' in conn['remote'] else conn['remote']
                    ip = ip.split(' (')[0]  # Remove any appended hostname
                else:
                    ip = conn['remote']

                row = self.connection_table.rowCount()

                if not (show_only_remote_connections and ip in ('127.0.0.1','::1')):
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
                    self.connection_table.setItem(row, HOSTNAME_ROW_INDEX, QTableWidgetItem(conn.get('hostname', '')))
                    self.connection_table.setItem(row, BYTES_SENT_ROW_INDEX, QTableWidgetItem(_format_bytes(conn.get('bytes_sent', 0))))
                    self.connection_table.setItem(row, BYTES_RECV_ROW_INDEX, QTableWidgetItem(_format_bytes(conn.get('bytes_recv', 0))))

                if ip in ('*', '0.0.0.0', '::', ''):
                    # UDP listener with no remote peer — not a real unresolved address
                    udp_no_remote += 1
                elif ip not in ('127.0.0.1','::1'):

                    ip = conn['remote'].split(' ')[0]
                    ip = ip.split(' (')[0]  # Remove any appended hostname                    

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
                    self.status_label.setText("Warning: Suspect C2 connections detected!")
                
                connections_to_show_on_map.append(conn)

        self.connection_table.setUpdatesEnabled(True)

        # Apply yellow icon override for the pinned (double-clicked) connection
        if self._pinned_connection is not None:
            for conn in connections_to_show_on_map:
                if self._is_pinned_connection(conn):
                    # Only override non-suspect connections (red stays red)
                    if conn['icon'] != 'redIcon':
                        conn['icon'] = 'yellowIcon'
                    # Re-open popup only if user hasn't manually closed it
                    if self._pinned_popup_open:
                        conn['autoPopup'] = True
                        conn['popupGeneration'] = self._pinned_popup_generation
                    break

        # Apply foreground / z-layer icon remapping.
        # The foreground agent uses the standard localhost colour scheme
        # (green=normal / blue=new / red=C2 / yellow=pinned).
        # Localhost, when demoted, uses grey.  Other agents keep their palette
        # colour regardless of layer position.
        foreground = getattr(self, '_foreground_hostname', LOCAL_HOSTNAME)
        if foreground != LOCAL_HOSTNAME:
            for conn in connections_to_show_on_map:
                hostname = conn.get('hostname', '')
                icon = conn.get('icon', '')
                if icon in ('redIcon', 'yellowIcon', 'agentCircle', 'redCircle', ''):
                    continue  # never remap suspect/pinned/circle markers
                if hostname == LOCAL_HOSTNAME:
                    # Demote localhost to grey
                    conn['icon'] = 'greyIcon'
                elif hostname == foreground:
                    # Promote foreground agent to standard colour scheme
                    agent_color = conn.get('agent_color', '')
                    if icon == agent_color + 'Icon':
                        # Was agent-coloured; switch to green (normal) or blue (new)
                        conn['icon'] = 'greenIcon'
                elif hostname:
                    pass  # other agents keep their assigned palette colour

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
                        'agent_color':     ref_conn.get('agent_color', 'orange'),
                        'hostname':        hostname,
                    })
        else:
            map_conns = connections_to_show_on_map

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
        self.apply_connection_table_filter()

    @Slot(bool)
    def on_map_loaded(self, success):
        if not success:
            self.status_label.setText("Error loading map")
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
                "By default ipify.com is disabled and your geo localization exit point will not show on the map.\n\n"
                "To enable it navigate to the Settings tab on the top and check the "
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
                self._refresh_agent_management_table()
        except Exception as e:
            logging.error(f"Error updating tab: {e}")

    def update_summary_table(self):
        """Populate the summary table with aggregated connection statistics"""
        try:
            # Clear existing rows
            self.summary_table.setUpdatesEnabled(False)
            self.summary_table.setRowCount(0)

            if not self.connection_list:
                self.summary_table.setUpdatesEnabled(True)
                return

            # Dictionary to track unique connections: key -> { 'count': int, 'bytes_sent': int, 'bytes_recv': int }
            connection_stats = {}

            # Get current setting for filtering local connections
            global show_only_remote_connections

            # Iterate through all timeline snapshots in connection_list
            for timeline_entry in self.connection_list:
                connection_list = timeline_entry.get('connection_list', [])

                for conn in connection_list:
                    # Create a unique key from connection attributes
                    process = conn.get('process', '')
                    pid = conn.get('pid', '')
                    suspect = conn.get('suspect', '')
                    protocol = conn.get('protocol', '')
                    local = conn.get('local', '')
                    remote = conn.get('remote', '')
                    ip_type = conn.get('ip_type', '')
                    name = conn.get('name', '')

                    # Filter out local connections if show_only_remote_connections is enabled
                    if show_only_remote_connections:
                        # Extract IP address (before any hostname in parentheses)
                        remote_ip = remote.split(' (')[0].split(':')[0]
                        # Skip local connections
                        if remote_ip in ('127.0.0.1', '::1'):
                            continue

                    hostname = conn.get('hostname', '')

                    # Use tuple as dictionary key for grouping
                    key = (hostname, process, pid, suspect, protocol, local, remote, ip_type, name)

                    b_sent = conn.get('bytes_sent', 0) or 0
                    b_recv = conn.get('bytes_recv', 0) or 0

                    # Increment count and accumulate bytes for this unique connection
                    if key in connection_stats:
                        connection_stats[key]['count'] += 1
                        connection_stats[key]['bytes_sent'] = max(connection_stats[key]['bytes_sent'], b_sent)
                        connection_stats[key]['bytes_recv'] = max(connection_stats[key]['bytes_recv'], b_recv)
                    else:
                        connection_stats[key] = {'count': 1, 'bytes_sent': b_sent, 'bytes_recv': b_recv}

            # Sort by count descending (highest first)
            sorted_stats = sorted(connection_stats.items(), key=lambda x: x[1]['count'], reverse=True)

            # Populate table with sorted results
            for (hostname, process, pid, suspect, protocol, local, remote, ip_type, name), stats in sorted_stats:
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
                self.summary_table.setItem(row, 8, QTableWidgetItem(name))
                self.summary_table.setItem(row, 9, QTableWidgetItem(str(count)))
                self.summary_table.setItem(row, 10, QTableWidgetItem(_format_bytes(stats['bytes_sent'])))
                self.summary_table.setItem(row, 11, QTableWidgetItem(_format_bytes(stats['bytes_recv'])))

                # Highlight suspect connections in red
                if suspect == "Yes":
                    for col in range(self.summary_table.columnCount()):
                        self.summary_table.item(row, col).setForeground(Qt.red)

            self.summary_table.setUpdatesEnabled(True)

            # Update title with total count
            total_unique = len(sorted_stats)
            total_connections = sum(s['count'] for _, s in sorted_stats)

            # Find the title label and update it
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
        # Get the connection data for the clicked row
        lat, lng = None, None

        if row < self.connection_table.rowCount():
            ip_hostnames = {}
            name = ""

            # Extract data from table cells based on predefined columns
            remote_address = self.connection_table.item(row, REMOTE_ADDRESS_ROW_INDEX).text()
            process_name = self.connection_table.item(row, PROCESS_ROW_INDEX).text()
            pid = self.connection_table.item(row, PID_ROW_INDEX).text()
            local_address = self.connection_table.item(row, LOCAL_ADDRESS_ROW_INDEX).text()
            protocol = self.connection_table.item(row, PROTOCOL_ROW_INDEX).text() if self.connection_table.item(row, PROTOCOL_ROW_INDEX) else 'TCP'
            local_port = self.connection_table.item(row, LOCAL_PORT_ROW_INDEX).text() if self.connection_table.item(row, LOCAL_PORT_ROW_INDEX) else ''
            remote_port = self.connection_table.item(row, REMOTE_PORT_ROW_INDEX).text() if self.connection_table.item(row, REMOTE_PORT_ROW_INDEX) else ''
            ip_type = self.connection_table.item(row, IP_TYPE_ROW_INDEX).text() if self.connection_table.item(row, IP_TYPE_ROW_INDEX) else ''

            # Process IP and hostname
            ip = remote_address
            ip = ip.split(' (')[0]  # Remove any appended hostname
            if ip not in ('127.0.0.1','::1'):

                lat = self.connection_table.item(row, LOCATION_LAT_ROW_INDEX).text()
                lng = self.connection_table.item(row, LOCATION_LON_ROW_INDEX).text()                

                # If table cells are empty, try a live geolocation lookup
                if not lat or not lng:
                    ip_for_geo = remote_address.split(' ')[0].split('(')[0].strip()
                    if ip_for_geo and ip_for_geo not in ('*', '0.0.0.0', '::', 'N/A'):
                        geo_lat, geo_lng = self.get_coordinates(ip_for_geo, ip_type)
                        if geo_lat is not None and geo_lng is not None:
                            lat = str(geo_lat)
                            lng = str(geo_lng)

                if do_reverse_dns:
                    name = self.connection_table.item(row, NAME_ROW_INDEX).text() if self.connection_table.item(row, NAME_ROW_INDEX) else ''

            # Check if the connection is marked as suspect
            suspect = (self.connection_table.item(row, SUSPECT_ROW_INDEX).text() == 'Yes')

            if suspect:
                icon = 'redIcon'
            elif self._pinned_connection is not None and self._is_pinned_connection(
                    {'process': process_name, 'pid': pid, 'protocol': protocol,
                     'local': local_address, 'localport': local_port,
                     'remote': remote_address, 'remoteport': remote_port,
                     'ip_type': ip_type}):
                icon = 'yellowIcon'
            else:
                icon = 'greenIcon'

            # Prepare focused data for map update
            focused_data = [{
                'process': process_name,
                'pid': pid,
                'suspect': suspect,
                'protocol': protocol,
                'local': local_address,
                'localport': local_port,
                'remote': remote_address,
                'remoteport': remote_port,
                'name': name,
                'ip_type': ip_type,
                'lat': lat,
                'lng': lng,
                'icon': icon,  # default icon; change as needed based on conditions
                'autoPopup': auto_popup,
                'popupGeneration': self._pinned_popup_generation if auto_popup else 0
            }]

            if lat and lng:
                self.update_map(focused_data)

def main():
    app = QApplication(sys.argv)
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

