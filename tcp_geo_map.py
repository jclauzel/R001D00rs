#!/usr/bin/env python3

# R001D00rs tcp_geo_map

"""
(kali) linux install using venv:

git clone https://github.com/jclauzel/R001D00rs
python3 -m venv ./venv
source venv/bin/activate
pip3 install pyside6 requests maxminddb pandas 
python3 tcp_geo_map.py

Windows:
pip3 install pyside6 requests maxminddb pandas 
"""

# pip install psutil, maxminddb, PySide6, folium, pandas

# using https://github.com/pointhi/leaflet-color-markers for colored map markers
# using https://github.com/sapics/ip-location-db/tree/main/geolite2-city this script is using the MaxMind GeoLite2 database and is attributed accordingly for its usage.
# using OpenStreetMap and leaflet for map display and location data

# Summary
# - Desktop tool that enumerates active TCP connections (via `psutil`), resolves geolocation using (MaxMind GeoLite2) and optional reverse DNS/C2 checks. 
#   Displays results in a Qt GUI (`PySide6`) with a Leaflet map embedded in `QWebEngineView` using OpenStreetMap.
# - Main UI handler class: `TCPConnectionViewer`.

""" 

Warranty, Disclaimer of Warranty, Limitation of Liability.

THE SCRIPT SOFTWARE IS PROVIDED "AS IS." THE AUTHOR MAKES NO WARRANTIES OF ANY KIND WHATSOEVER WITH RESPECT TO SCRIPT SOFTWARE WHICH MAY CONTAIN THIRD PARTY COMMERCIAL SOFTWARE. 

IN NO EVENT WILL THE AUTHOR BE LIABLE FOR ANY LOST REVENUE, PROFIT OR DATA, OR FOR DIRECT, SPECIAL, INDIRECT, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY ARISING OUT OF THE USE OF OR INABILITY TO USE THE SCRIPT SOFTWARE, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

    Other Important Notices:

    - When starting the application will download icons from https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img so internet access is required.

    - Using this application requires that YOU FULLY AGREE AND ACCEPT:
    
            MaxMind / GeoLite, folium, leaflet, OpenStreetMap, pandas, pyside licensing terms.
        
                as well as licensing terms of all contributing libraries to this script even though you use the --accept_eula startup option.

    - This script will persist to disk by default the dns names ip cache file defined in IP_DNS_NAME_CACHE_FILE to speed up startup (when PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK is set to True).. 
        If you don't want any cache file to speed up the application startup then set PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK to False.

    - Settings are persisted on applicaton end in a file called by default settings.json (defined in SETTINGS_FILE_NAME) that will be loaded next time the application start up. To reset settings simply delete the generated settings.json file.

"""


# gptc

import requests, datetime, sys, os, concurrent, threading, time, socket, csv, psutil, maxminddb, json, queue, pandas as pd
from concurrent.futures import ThreadPoolExecutor
from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QWidget, QTableWidget, QTableWidgetItem, QLabel, 
                             QPushButton, QComboBox, QGroupBox, QFrame, QMessageBox, QCheckBox,QSlider, QToolButton, QGraphicsOpacityEffect, QGridLayout, QSplitter, QHeaderView) 
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation
from PySide6.QtWebEngineWidgets import QWebEngineView

VERSION = "2.7.5" # Current script version

assert sys.version_info >= (3, 8) # minimum required version of python for PySide6, pandas, maxminddb, psutil...

DATABASE_EXPIRE_AFTER_DAYS = 7 # Databases expiration time in days from download date, default 7 days (1 week)
DB_DIR = "databases" # Database location are contained in this subdirectory under the main script directory

IPV4_DB_PATH = os.path.join(DB_DIR, "geolite2-city-ipv4.mmdb")
IPV6_DB_PATH = os.path.join(DB_DIR, "geolite2-city-ipv6.mmdb")
C2_TRACKER_DB_PATH = os.path.join(DB_DIR, "all.txt")
SETTINGS_FILE_NAME = "settings.json"

""" 
You can pass --accept_eula as a startup parametter to the script to automate download and refresh 
the Geolite and c2 tracker databases howver this means you fully agree to their licensing terms
"""
ACCEPT_EULA = "--accept_eula" in sys.argv


PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK = True # set to True to turn on and speedup application start time, False to disable. However this will keep track on disk to what IP addresses machine was connected to.
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

PROCESS_ROW_INDEX = 0     # Index of the 'Process' column in the table
PID_ROW_INDEX = 1         # Index of the 'PID' column in the table
SUSPECT_ROW_INDEX = 2     # Index of the 'Suspect' column in the table
LOCAL_ADDRESS_ROW_INDEX = 3    # Index of the 'Local Address' column in the table
LOCAL_PORT_ROW_INDEX = 4      # Index of the 'Local Port' column in the table
REMOTE_ADDRESS_ROW_INDEX = 5  # Index of the 'Remote Address' column in the table
REMOTE_PORT_ROW_INDEX = 6     # Index of the 'Remote Port' column in the table
NAME_ROW_INDEX = 7        # Index of the 'Name' column in the table
IP_TYPE_ROW_INDEX = 8      # Index of the 'IP Type' column in the table
LOCATION_LAT_ROW_INDEX = 9   # Index of the 'Location' column in the table
LOCATION_LON_ROW_INDEX = 10  # Index of the 'Location' column in the table
PID_COLUMN_SIZE = 60
SUSPECT_COLUMN_SIZE = 30
PORTS_COLUMN_SIZE = 70
IP_TYPE_COLUMN_SIZE = 20

CONNECTION_LIST_MAX_SIZE = 1000  # Maximum number of connection snapshots to keep in memory
TIME_SLIDER_TEXT = "Time slider position: "

START_CAPTURE_BUTTON_TEXT = "Start capture live connections"
STOP_CAPTURE_BUTTON_TEXT = "Stop capture live connections" 

show_tooltip = False # Show tooltips on map markers
map_refresh_interval = 120000  # Map refresh time in milliseconds
show_only_new_active_connections = False # Show only new connections in the table
table_column_sort_index = -1  # Default column index to sort the table by the index
table_column_sort_reverse = False  # Default sort order
do_reverse_dns = False  # Set to True to enable reverse DNS lookups
do_c2_check = False    # Set to True to enable C2-TRACKER checks

 

# Global cache and lock for thread-safe IP lookups
ip_cache = {}
cache_lock = threading.Lock()

class DNSWorker(threading.Thread):
    """
    Background DNS worker that continuously warms the ip_cache.

    - Receives IPs via `enqueue_many` / `enqueue`.
    - Resolves with blocking socket.gethostbyaddr inside the worker (off the UI thread).
    - Updates shared `ip_cache` under `cache_lock`.
    - Optionally calls `on_resolve(ip, hostname)` for each positive resolution
      (this callback must be thread-safe; the viewer uses QTimer.singleShot to marshal to UI).
    - Call `stop()` to request shutdown and `join()` to wait for termination.
    """
    def __init__(self, cache, lock, on_resolve=None, max_queue=10000, idle_sleep=0.05):
        super().__init__(daemon=True)
        self.cache = cache
        self.lock = lock
        self.on_resolve = on_resolve
        self.queue = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self.idle_sleep = idle_sleep

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

    def run(self):
        while not self._stop.is_set():
            try:
                ip = self.queue.get(timeout=0.5)
            except queue.Empty:
                # small idle sleep to reduce CPU when queue empty
                time.sleep(self.idle_sleep)
                continue

            if not ip:
                continue

            # skip if already in cache
            with self.lock:
                if ip in self.cache:
                    self.queue.task_done()
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


class TCPConnectionViewer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"TCP Geo Map - R001D00rs - v {VERSION}")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize database readers
        self.reader_ipv4 = None
        self.reader_ipv6 = None
        self.reader_c2_tracker = None
        self.connections = []
        
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
        
        self.load_databases()
        self.init_ui()
        self.load_settings()

        #self.refresh_connections()
        
        # Set up timer to refresh connections periodically

        self.timer.timeout.connect(self.refresh_connections)
        self.timer.start(map_refresh_interval)  # Refresh every 5 seconds
        self.timer_replay_connections.timeout.connect(self.replay_connections)

    def save_settings(self):
        """Save current settings to a JSON file"""
        settings = {
            'do_c2_check' : do_c2_check,
		    'show_only_new_active_connections': show_only_new_active_connections,
		    'do_reverse_dns': do_reverse_dns,
		    'map_refresh_interval': map_refresh_interval,
		    'table_column_sort_index': table_column_sort_index,
            'table_column_sort_reverse' : table_column_sort_reverse,
	    }
        try:
            with open(SETTINGS_FILE_NAME, 'w') as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            QMessageBox.critical(self, "Error saving settings", f"Error: {e}")
            

    def load_settings(self):
        """Load settings from a JSON file"""
        
        if os.path.exists(SETTINGS_FILE_NAME):
            try:
                with open(SETTINGS_FILE_NAME, 'r') as f:
                    settings = json.load(f)

                    # Apply loaded settings
                    global do_c2_check, show_only_new_active_connections, do_reverse_dns, map_refresh_interval, table_column_sort_index, table_column_sort_reverse

                    do_c2_check = settings.get('do_c2_check', do_c2_check)
                    show_only_new_active_connections = settings.get('show_only_new_active_connections', show_only_new_active_connections)
                    do_reverse_dns = settings.get('do_reverse_dns', do_reverse_dns)

                    map_refresh_interval = settings.get('map_refresh_interval', map_refresh_interval)
                    self.refresh_interval_combo_box.setCurrentText(f"{map_refresh_interval}")

                    table_column_sort_index = settings.get('table_column_sort_index', table_column_sort_index)
                    table_column_sort_reverse = settings.get('table_column_sort_reverse', table_column_sort_reverse)
		                
                    # Update UI elements if needed
                    self.only_show_new_connections.setChecked(show_only_new_active_connections)
                    self.reverse_dns_check.setChecked(do_reverse_dns)
                    self.c2_check.setChecked(do_c2_check)

            except Exception as e:
                QMessageBox.critical(self, "Error loading settings", f"Error: {e}")

    def closeEvent(self, event):
        """Save settings when closing the application"""
        try:
            if getattr(self, "dns_worker", None) is not None:
                self.dns_worker.stop()
                self.dns_worker.join(timeout=2.0)
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
            for fut in concurrent.futures.as_completed(futures):
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


    # def reverse_dns(self, ips):
    #     """
    #     Fast, thread-safe reverse DNS with local caching.

    #     - Uses the shared `ip_cache` protected by `cache_lock`.
    #     - Avoids work for already-cached addresses.
    #     - Executes lookups in a ThreadPoolExecutor with a bounded worker count.
    #     - Updates cache from worker threads to minimize post-processing allocations.
    #     - Returns a dict mapping only resolved IP -> hostname.
    #     """
    #     if isinstance(ips, str):
    #         ips = [ips]

    #     # normalize input and filter falsy entries early
    #     ips = [ip for ip in ips if ip]

    #     if not ips:
    #         return {}

    #     # Local references to globals to reduce attribute lookups
    #     global ip_cache, cache_lock

    #     results = {}
    #     to_resolve = []

    #     # Fast path: check cache under lock and build list of addresses that need lookup
    #     with cache_lock:
    #         for ip in ips:
    #             if ip in ip_cache:
    #                 host = ip_cache[ip]
    #                 if host:
    #                     results[ip] = host
    #             else:
    #                 to_resolve.append(ip)

    #     if not to_resolve:
    #         return results

    #     # Choose a sensible worker count (avoid oversubscription)
    #     max_workers = min(32, max(4, len(to_resolve)))

    #     def _lookup_and_cache(ip_addr):
    #         """Worker function: resolve ip and atomically store result in cache."""
    #         try:
    #             hostname = socket.gethostbyaddr(ip_addr)[0]
    #         except Exception:
    #             hostname = None

    #         # update cache immediately under lock (store None for negative answers)
    #         with cache_lock:
    #             ip_cache[ip_addr] = hostname
    #         return ip_addr, hostname

    #     # Submit lookups and collect resolved hostnames
    #     with ThreadPoolExecutor(max_workers=max_workers) as exe:
    #         futures = {exe.submit(_lookup_and_cache, ip): ip for ip in to_resolve}
    #         for fut in concurrent.futures.as_completed(futures):
    #             try:
    #                 ip_addr, hostname = fut.result()
    #             except Exception:
    #                 # defensive: skip on unexpected worker exception
    #                 continue
    #             if hostname:
    #                 results[ip_addr] = hostname

    #     return results

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

        for row in range(self.connection_table.rowCount()):
            self.sort_table_by_column(index, table_column_sort_reverse)


    def column_resort(self, index):
        """
        Handles sorting when a column header is clicked.
        
        Args:
            index (int): The column index that was clicked.
        """
        global table_column_sort_index
        global table_column_sort_reverse

        for row in range(self.connection_table.rowCount()):
            self.sort_table_by_column(index, table_column_sort_reverse)

    def sort_table_by_column(self, column_index, reverse=False):
        """
        Sorts the table based on the specified column index.
        
        Args:
            column_index (int): The column to sort by.
            reverse (bool): If True, sorts in descending order; otherwise ascending.
        """
        # Get all items from the specified column
        items = []
        for row in range(self.connection_table.rowCount()):
            item = self.connection_table.item(row, column_index)
            if item is not None:
                items.append((item.text(), row))
        
        # Sort the items based on their text (case-sensitive)
        items.sort(key=lambda x: x[0], reverse=reverse)  # Change to True for descending
        
        # Reorder the rows according to the sorted items
        for new_row, (_, original_row) in enumerate(items):
            if new_row != original_row:
                self.rearrange_rows(original_row, new_row)

    def rearrange_rows(self, source_row, destination_row):
        """
        Moves a row from source_row to destination_row.
        
        Args:
            source_row (int): The current position of the row.
            destination_row (int): The target position for the row.
        """
        # Get all items in the source row
        row_items = []
        for col in range(self.connection_table.columnCount()):
            item = self.connection_table.item(source_row, col)
            if item:
                row_items.append(item.text())
        
        # Remove the source row from the table
        self.connection_table.removeRow(source_row)
        
        # Insert the items into the destination row
        self.connection_table.insertRow(destination_row)
        for col in range(len(row_items)):
            self.connection_table.setItem(destination_row, col, QTableWidgetItem(row_items[col]))    

     # Update connection list when slider changes
    def update_slider_value(self, value):

        # Update your connection list here
        self.slider.setMaximum(self.connection_list_counter)

        self.timer.stop()
        self.status_label.setText("Auto-refresh paused. Click 'Start Capture' to resume.")

        if value >= self.connection_list_counter:
            value = self.connection_list_counter
        
        self.slider_value_label.setText(TIME_SLIDER_TEXT + str(value) + "/" + str(len(self.connection_list) -1))
        self.refresh_connections(slider_position=value)
        if not self.timer_replay_connections.isActive():
            self.start_capture_btn.setVisible(True)
            self.stop_capture_btn.setVisible(False)
            self.toggle_button.setVisible(True)

        self.slider.setToolTip(f"Map time: {self.connection_list[value]['datetime']}")

    def update_reverse_dns(self):
        global do_reverse_dns

        new_state = self.reverse_dns_check.isChecked()
        if new_state == True:
            do_reverse_dns = True
            self.dns_resolution_time.setVisible(True)
        else:
            do_reverse_dns = False
            self.dns_resolution_time.setVisible(False)

        self.refresh_connections()
        
    def update_c2_check(self):
        global do_c2_check

        new_state = self.c2_check.isChecked()
        if new_state == True:
            do_c2_check = True
        else:
            do_c2_check = False
            self.setStyleSheet("") # Reset any previous styles

        self.refresh_connections()

    def only_show_new_connections_changed(self):
        global show_only_new_active_connections

        new_state = self.only_show_new_connections.isChecked()
        if new_state == True:
            show_only_new_active_connections = True
        else:
            show_only_new_active_connections = False
            self.setStyleSheet("") # Reset any previous styles

        self.refresh_connections()
    
    def update_refresh_interval(self):
        global map_refresh_interval

        selected_interval = int(self.refresh_interval_combo_box.currentText())
        map_refresh_interval = selected_interval
        self.timer.stop()
        self.timer.start(map_refresh_interval)

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
            self.slider_value_label = QLabel(TIME_SLIDER_TEXT + "0")
            self.slider.setMaximum(self.connection_list_counter)
            self.slider_value_label.setText(TIME_SLIDER_TEXT + str(self.slider.value()) + "/" + str(len(self.connection_list)))
            self.update_map(self.connections)
            self.start_capture_btn.setVisible(True)
            self.stop_capture_btn.setVisible(False)         
        

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


    def toggle_auto_refresh_replay_connections(self, enabled):
        if enabled:
            if self.timer_replay_connections.isActive():
                return  # Already running
            self.status_label.setText("Replaying connections.")
            
            # Start refresh timer or process here
            self.timer_replay_connections.start(map_refresh_interval)

            self.start_capture_btn.setVisible(False)
            self.stop_capture_btn.setVisible(False) 

        else:
            self.status_label.setText("Connection replay paused.")
            
            # Stop refresh timer or process here
            self.timer_replay_connections.stop()
            self.start_capture_btn.setVisible(True)
            self.stop_capture_btn.setVisible(False)             


    # def init_ui(self):
    #     self.connection_list = []
    #     self.connection_list_counter = 0

    #     # Use a horizontal splitter so the user can resize left/right panels with the mouse
    #     self.splitter = QSplitter(Qt.Horizontal)

    #     # Main layout
    #     main_layout = QHBoxLayout()
    #     self.timer = QTimer(self)
    #     self.timer_replay_connections = QTimer(self)

    #     # Left panel for connection list
    #     self.left_panel = QGroupBox("Active Connections")
    #     self.left_layout = QVBoxLayout()

    #     # Right panel for map
    #     self.right_panel = QGroupBox("Network Connections Map")
    #     self.right_layout = QVBoxLayout()

    #     self.slider = QSlider(Qt.Horizontal)
    #     self.slider_value_label = QLabel(TIME_SLIDER_TEXT + "0")
        
    #     # Save Button
    #     self.save_connections_btn = QPushButton("Save connection list to CSV file")
    #     self.save_connections_btn.clicked.connect(self.save_all_connection_list_to_csv)
        
    #     self.save_connections_btn.setVisible(True)

    #     # Refresh button
    #     self.start_capture_btn = QPushButton(START_CAPTURE_BUTTON_TEXT)
    #     self.start_capture_btn.clicked.connect(self.refresh_connections)
        
    #     self.start_capture_btn.setVisible(False)

    #     self.stop_capture_btn = QPushButton(STOP_CAPTURE_BUTTON_TEXT)
    #     self.stop_capture_btn.clicked.connect(self.stop_capture_connections)
        
    #     self.stop_capture_btn.setVisible(True)        
        
    #     # Connection table
    #     self.connection_table = QTableWidget(0, LOCATION_LON_ROW_INDEX+1)
    #     self.connection_table.setHorizontalHeaderLabels([
    #         "Process", "PID", "C2", "Local Addr", "Local Port", "Remote Addr", "Remote Port", "Name", "IP Type", "Loc lat", "Loc lon"
    #     ])

    #     # Connect the header clicked signal to a custom sort function
    #     self.connection_table.horizontalHeader().sectionClicked.connect(self.on_header_clicked)        
    #     self.connection_table.setMinimumSize(CONNECTION_TABLE_MIN_WIDTH, CONNECTION_TABLE_MIN_HEIGHT)
    #     self.connection_table.setEditTriggers(QTableWidget.NoEditTriggers)
    #     self.connection_table.setSelectionBehavior(QTableWidget.SelectRows)
    #     self.connection_table.cellClicked.connect(self.on_table_cell_clicked)

    #     self.left_layout.addWidget(self.connection_table)
        
    #     # Respect minimum sizes and set sensible initial sizes for the splitter children
    #     self.left_panel.setMinimumWidth(CONNECTION_TABLE_MIN_WIDTH)
    #     self.right_panel.setMinimumWidth(MAP_TABLE_MIN_WIDTH)
    #     self.splitter.setSizes([int(self.width() * 0.35), int(self.width() * 0.65)])  # initial ratio
    #     self.splitter.setHandleWidth(6)

    #     self.left_panel.setLayout(self.left_layout)

    #     self.splitter.addWidget(self.left_panel)
    #     self.splitter.addWidget(self.right_panel)
        
    #     # Map view
    #     self.map_view = QWebEngineView()
    #     self.map_view.setMinimumSize(MAP_TABLE_MIN_WIDTH, MAP_TABLE_MIN_HEIGHT)
    #     self.map_view.setHtml("<html><body><h2>Loading map...</h2></body></html>")
    #     self.map_redraw = True
    #     self.map_objects = 0
    #     self.map_initialized = False

    #     # Pulse indicator - small green circle that fades in/out on refresh
    #     self.pulse_indicator = QFrame()
    #     self.pulse_indicator.setFixedSize(14, 14)
    #     self.pulse_indicator.setStyleSheet("background-color: #33cc33; border-radius: 7px;")
    #     self.pulse_indicator.setVisible(False)
    #     self.pulse_indicator.setAttribute(Qt.WA_TransparentForMouseEvents, True)
    #     self.pulse_indicator.setToolTip("Refreshing...")

    #     # opacity effect + animation
    #     self._pulse_opacity = QGraphicsOpacityEffect(self.pulse_indicator)
    #     self.pulse_indicator.setGraphicsEffect(self._pulse_opacity)
    #     self._pulse_anim = QPropertyAnimation(self._pulse_opacity, b"opacity", self)
    #     self._pulse_anim.setDuration(800)  # total pulse duration (ms)
    #     # fade in quickly, hold, then fade out
    #     self._pulse_anim.setKeyValueAt(0.0, 0.0)
    #     self._pulse_anim.setKeyValueAt(0.12, 1.0)
    #     self._pulse_anim.setKeyValueAt(0.88, 1.0)
    #     self._pulse_anim.setKeyValueAt(1.0, 0.0)
    #     self._pulse_anim.finished.connect(lambda: self.pulse_indicator.setVisible(False))


    #     self.right_layout.addWidget(self.map_view)

    #     # Create a fixed-size container for the pulse using a QGridLayout so its size is reserved.
    #     self.pulse_container = QWidget()
    #     # choose a height that fits the pulse and a small margin; width will stretch with the layout
    #     self.pulse_container.setFixedHeight(36)
    #     pulse_layout = QGridLayout(self.pulse_container)
    #     pulse_layout.setContentsMargins(0, 0, 6, 0)  # right margin so indicator sits inset
    #     pulse_layout.addWidget(self.pulse_indicator, 0, 0, Qt.AlignRight | Qt.AlignTop)

    #     # add the fixed container to the layout (it always occupies space, so children below won't move)
    #     self.right_layout.addWidget(self.pulse_container)




    #     self.right_layout.addWidget(self.start_capture_btn)
    #     self.right_layout.addWidget(self.stop_capture_btn)

    #     # Create slider
        
    #     self.slider.setMinimum(0)
    #     self.slider.setMaximum(0)  # Adjust based on your needs
    #     self.slider.setValue(0)  # Default position   
        
    #     self.right_layout.addWidget(self.slider)

    #     self.right_layout.addWidget(self.slider_value_label)

    #     self.slider.valueChanged.connect(self.update_slider_value)

    #     # Add play/pause button
    #     self.toggle_button = QToolButton()
        
    #     self.toggle_button.setVisible(False)
    #     self.refresh_action = self.toggle_button.addAction(QIcon('play.png'), 'Play')
    #     self.pause_action = self.toggle_button.addAction(QIcon('pause.png'), 'Pause')
        
    #     self.toggle_action = QAction("Replay connections", self)
    #     self.toggle_action.setCheckable(True)
    #     self.toggle_action.toggled.connect(self.toggle_auto_refresh_replay_connections)  # Add this method
        
    #     self.toggle_button.setDefaultAction(self.toggle_action)
    #     self.right_layout.addWidget(self.toggle_button)      
        
    #     self.refresh_interval_combo_box = QComboBox()
    #     self.refresh_interval_combo_box.setToolTip("Select map refresh interval in milliseconds")
    #     self.refresh_interval_combo_box.addItems(["2000", "5000", "10000", "20000", "30000", "40000", "50000", "120000", "300000", "600000", "1200000", "180000000"])
    #     self.refresh_interval_combo_box.currentIndexChanged.connect(self.update_refresh_interval)
    #     self.update_refresh_interval()
    #     self.right_layout.addWidget(self.refresh_interval_combo_box)

    #     # Status label
    #     self.status_label = QLabel("Auto-refreshing connections.")
    #     self.right_layout.addWidget(self.status_label)
    #     self.status_label.setAlignment(Qt.AlignTop)

    #     self.right_layout.addWidget(self.save_connections_btn)
    #     self.save_connections_btn.clicked.connect(self.save_connection_list_to_csv)

    #     # DNS resolution time label
    #     self.dns_resolution_time = QLabel("DNS lookups took : N/A")
    #     self.right_layout.addWidget(self.dns_resolution_time)
    #     self.dns_resolution_time.setAlignment(Qt.AlignTop)
    #     self.dns_resolution_time.setVisible(False)

    #     # Reverse DNS checkbox
    #     self.reverse_dns_check = QCheckBox("Perform Reverse DNS Lookup on captured IPs")
    #     self.reverse_dns_check.setChecked(False)
    #     self.right_layout.addWidget(self.reverse_dns_check)    
    #     self.reverse_dns_check.stateChanged.connect(self.update_reverse_dns)

    #     # C2 Check checkbox
    #     self.c2_check = QCheckBox("Perform C2 checks against C2-TRACKER database")
    #     self.c2_check.setChecked(False)
    #     self.right_layout.addWidget(self.c2_check)    
    #     self.c2_check.stateChanged.connect(self.update_c2_check)
    #     self.c2_check.setChecked(True)

    #     # Only show new connections
    #     self.only_show_new_connections = QCheckBox("Only show new connections")
    #     self.only_show_new_connections.setChecked(False)
    #     self.right_layout.addWidget(self.only_show_new_connections)    
    #     self.only_show_new_connections.stateChanged.connect(self.only_show_new_connections_changed)  
 
    #     self.reset_connections_btn = QPushButton("Reset connections")
    #     self.reset_connections_btn.clicked.connect(self.reset_connections)
    #     self.right_layout.addWidget(self.reset_connections_btn)  

    #     self.right_panel.setLayout(self.right_layout)    
        
    #     # Add panels to main layout
    #     main_layout.addWidget(self.left_panel, 1)
    #     main_layout.addWidget(self.right_panel, 2)
        
    #     # central_widget = QWidget()
    #     # central_widget.setLayout(main_layout)
    #     # self.setCentralWidget(central_widget)



    #     # Put splitter inside central widget to preserve your existing central widget setup
    #     central_widget = QWidget()
    #     central_layout = QHBoxLayout(central_widget)
    #     central_layout.setContentsMargins(0, 0, 0, 0)
    #     central_layout.addWidget(self.splitter)
    #     self.setCentralWidget(central_widget)



        
    #     # Connect the web view's load finished signal
    #     self.map_view.loadFinished.connect(self.on_map_loaded)

    def init_ui(self):
        self.connection_list = []
        self.connection_list_counter = 0

        # Use a horizontal splitter so the user can resize left/right panels with the mouse
        self.splitter = QSplitter(Qt.Horizontal)

        # Main layout
        main_layout = QHBoxLayout()
        self.timer = QTimer(self)
        self.timer_replay_connections = QTimer(self)

        # Left panel for connection list
        self.left_panel = QGroupBox("Active Connections")
        self.left_layout = QVBoxLayout()

        # Right panel for map
        self.right_panel = QGroupBox("Network Connections Map")
        self.right_layout = QVBoxLayout()

        self.slider = QSlider(Qt.Horizontal)
        self.slider_value_label = QLabel(TIME_SLIDER_TEXT + "0")
        
        # Save Button
        self.save_connections_btn = QPushButton("Save connection list to CSV file")
        self.save_connections_btn.clicked.connect(self.save_all_connection_list_to_csv)
        
        self.save_connections_btn.setVisible(True)

        # Refresh button
        self.start_capture_btn = QPushButton(START_CAPTURE_BUTTON_TEXT)
        self.start_capture_btn.clicked.connect(self.refresh_connections)
        
        self.start_capture_btn.setVisible(False)

        self.stop_capture_btn = QPushButton(STOP_CAPTURE_BUTTON_TEXT)
        self.stop_capture_btn.clicked.connect(self.stop_capture_connections)
        
        self.stop_capture_btn.setVisible(True)        
        
        # Connection table
        self.connection_table = QTableWidget(0, LOCATION_LON_ROW_INDEX+1)
        self.connection_table.setHorizontalHeaderLabels([
            "Process", "PID", "C2", "Local Addr", "Local Port", "Remote Addr", "Remote Port", "Name", "IP Type", "Loc lat", "Loc lon"
        ])

        # Connect the header clicked signal to a custom sort function
        self.connection_table.horizontalHeader().sectionClicked.connect(self.on_header_clicked)        
        self.connection_table.setMinimumSize(CONNECTION_TABLE_MIN_WIDTH, CONNECTION_TABLE_MIN_HEIGHT)
        self.connection_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.connection_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.connection_table.cellClicked.connect(self.on_table_cell_clicked)

        # Ensure header is interactive and enforce a minimum width for the "C2" column (index = SUSPECT_ROW_INDEX)
        self.connection_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        self.connection_table.setColumnWidth(PID_ROW_INDEX, PID_COLUMN_SIZE)
        self.connection_table.setColumnWidth(SUSPECT_ROW_INDEX, SUSPECT_COLUMN_SIZE)
        self.connection_table.setColumnWidth(LOCAL_PORT_ROW_INDEX, PORTS_COLUMN_SIZE)
        self.connection_table.setColumnWidth(REMOTE_PORT_ROW_INDEX, PORTS_COLUMN_SIZE)
        self.connection_table.setColumnWidth(IP_TYPE_ROW_INDEX, IP_TYPE_COLUMN_SIZE)

        self.connection_table.horizontalHeader().setMinimumSectionSize(SUSPECT_COLUMN_SIZE)



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
        self.map_view.setHtml("<html><body><h2>Loading map...</h2></body></html>")
        self.map_redraw = True
        self.map_objects = 0
        self.map_initialized = False

        # Pulse indicator - small green circle that fades in/out on refresh
        self.pulse_indicator = QFrame()
        self.pulse_indicator.setFixedSize(14, 14)
        self.pulse_indicator.setStyleSheet("background-color: #33cc33; border-radius: 7px;")
        self.pulse_indicator.setVisible(False)
        self.pulse_indicator.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.pulse_indicator.setToolTip("Refreshing...")

        # opacity effect + animation
        self._pulse_opacity = QGraphicsOpacityEffect(self.pulse_indicator)
        self.pulse_indicator.setGraphicsEffect(self._pulse_opacity)
        self._pulse_anim = QPropertyAnimation(self._pulse_opacity, b"opacity", self)
        self._pulse_anim.setDuration(800)  # total pulse duration (ms)
        # fade in quickly, hold, then fade out
        self._pulse_anim.setKeyValueAt(0.0, 0.0)
        self._pulse_anim.setKeyValueAt(0.12, 1.0)
        self._pulse_anim.setKeyValueAt(0.88, 1.0)
        self._pulse_anim.setKeyValueAt(1.0, 0.0)
        self._pulse_anim.finished.connect(lambda: self.pulse_indicator.setVisible(False))

        #
        # NEW: Create a vertical splitter inside the right panel so the top area is the map
        # and the bottom area holds controls (pulse indicator, buttons, slider, checkboxes).
        # This allows the user to resize the vertical space allocated to the map.
        #
        self.right_splitter = QSplitter(Qt.Vertical)
        self.right_splitter.setHandleWidth(6)

        # Controls container placed below the map in the vertical splitter
        self.controls_widget = QWidget()
        self.controls_layout = QVBoxLayout(self.controls_widget)
        self.controls_layout.setContentsMargins(0, 0, 0, 0)
        self.controls_layout.setSpacing(6)

        # Create a fixed-size container for the pulse using a QGridLayout so its size is reserved.
        self.pulse_container = QWidget()
        # choose a height that fits the pulse and a small margin; width will stretch with the layout
        self.pulse_container.setFixedHeight(36)
        pulse_layout = QGridLayout(self.pulse_container)
        pulse_layout.setContentsMargins(0, 0, 6, 0)  # right margin so indicator sits inset
        pulse_layout.addWidget(self.pulse_indicator, 0, 0, Qt.AlignRight | Qt.AlignTop)

        # add pulse container to controls
        self.controls_layout.addWidget(self.pulse_container)

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
        self.refresh_action = self.toggle_button.addAction(QIcon('play.png'), 'Play')
        self.pause_action = self.toggle_button.addAction(QIcon('pause.png'), 'Pause')
        self.toggle_action = QAction("Replay connections", self)
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

        # Save button
        self.controls_layout.addWidget(self.save_connections_btn)
        self.save_connections_btn.clicked.connect(self.save_connection_list_to_csv)

        # DNS resolution time label
        self.dns_resolution_time = QLabel("DNS lookups took : N/A")
        self.dns_resolution_time.setAlignment(Qt.AlignTop)
        self.dns_resolution_time.setVisible(False)
        self.controls_layout.addWidget(self.dns_resolution_time)

        # Reverse DNS checkbox
        self.reverse_dns_check = QCheckBox("Perform Reverse DNS Lookup on captured IPs")
        self.reverse_dns_check.setChecked(False)
        self.controls_layout.addWidget(self.reverse_dns_check)    
        self.reverse_dns_check.stateChanged.connect(self.update_reverse_dns)

        # C2 Check checkbox
        self.c2_check = QCheckBox("Perform C2 checks against C2-TRACKER database")
        self.c2_check.setChecked(False)
        self.controls_layout.addWidget(self.c2_check)    
        self.c2_check.stateChanged.connect(self.update_c2_check)
        self.c2_check.setChecked(True)

        # Only show new connections
        self.only_show_new_connections = QCheckBox("Only show new connections")
        self.only_show_new_connections.setChecked(False)
        self.controls_layout.addWidget(self.only_show_new_connections)    
        self.only_show_new_connections.stateChanged.connect(self.only_show_new_connections_changed)  

        self.reset_connections_btn = QPushButton("Reset connections")
        self.reset_connections_btn.clicked.connect(self.reset_connections)
        self.controls_layout.addWidget(self.reset_connections_btn)

        # Put map and controls into the vertical splitter (map on top, controls below)
        self.right_splitter.addWidget(self.map_view)
        self.right_splitter.addWidget(self.controls_widget)
        # Give the map more initial stretch so it's larger by default
        self.right_splitter.setStretchFactor(0, 8)
        self.right_splitter.setStretchFactor(1, 2)

        # Finally, add the vertical splitter to the right panel layout
        self.right_layout.addWidget(self.right_splitter)

        self.right_panel.setLayout(self.right_layout)    
        
        # Add panels to main layout
        main_layout.addWidget(self.left_panel, 1)
        main_layout.addWidget(self.right_panel, 2)
        
        # central_widget holds the top-level splitter
        central_widget = QWidget()
        central_layout = QHBoxLayout(central_widget)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.addWidget(self.splitter)
        self.setCentralWidget(central_widget)

        # Connect the web view's load finished signal
        self.map_view.loadFinished.connect(self.on_map_loaded)

        
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
            self.reader_c2_tracker = pd.read_csv(C2_TRACKER_DB_PATH, sep="\t", names=["ip", "type", "info"], comment="#", dtype=str)    

        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load databases: {str(e)}, nothing may show on map.")

    
    def check_ip_is_present_in_c2_tracker(self, ip_address):
        """Check if an IP address is present in the C2-TRACKER database"""
        try:
            if self.reader_c2_tracker is not None:
                match = self.reader_c2_tracker[self.reader_c2_tracker['ip'] == ip_address]
                if not match.empty:
                    return True, match.iloc[0]['type'], match.iloc[0]['info']
            return False, None, None
        except Exception as e:
            return False, None, None

    def download_database(self, db_path, url):
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            # Download file
            response = requests.get(url, stream=True)
            if response.status_code == 200:
                if os.path.exists(db_path):
                    os.remove(db_path)# remove the previous file first
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
                    print(f"Downloaded database {url} to {db_path}. This means you FULLY AGREE with the database' EULA and their liceensing terms.")
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

            connections = []
            
            for conn in psutil.net_connections(kind='inet4'):
                if conn.status == psutil.CONN_ESTABLISHED:
                    try:
                        # Get process information
                        process = psutil.Process(conn.pid) if conn.pid else None
                        process_name = process.name() if process else "Unknown"
                        
                        # Get local and remote addresses
                        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                        
                        # Determine IP type
                        ip_type = ""
                        if conn.family == socket.AF_INET:
                            ip_type = "IPv4"
                        elif conn.family == socket.AF_INET6:
                            ip_type = "IPv6"
                        
                        connections.append({
                            'process': process_name,
                            'pid': str(conn.pid) if conn.pid else "N/A",
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
        
    def are_connections_identical(self, conn1, conn2):
        # Check if all important fields are the same
        return (
            conn1['process'] == conn2['process'] and
            conn1['pid'] == conn2['pid'] and
            conn1['local'] == conn2['local'] and
            conn1['localport'] == conn2['localport'] and
            conn1['remote'] == conn2['remote'] and
            conn1['remoteport'] == conn2['remoteport'] and
            conn1['ip_type'] == conn2['ip_type'] 
        )  

    def is_connection_in_list(self, connection, connection_list):
        for conn in connection_list:
            if self.are_connections_identical(conn, connection):
                return True
        return False
        
    # def get_active_tcp_connections(self, position_timeline=None):
    #     connections = []
    #     c2_connections = []
    #     #new_connections = []
        
    #     # Get all connections from psutil
    #     all_connections = psutil.net_connections(kind='inet')
    #     # Filter for TCP connections that are established and not local loop
    #     end_time_dns_resolution=0.0
    
    #     # Collect all remote IPs for DNS resolution
    #     ips_to_resolve = set()
    #     for conn in all_connections:
    #         if conn.status == psutil.CONN_ESTABLISHED :
    #             if conn.raddr.ip not in ('127.0.0.1', '::1', None):
    #                 ips_to_resolve.add(conn.raddr.ip)
                
    #     # Resolve all IPs at once
    #     ip_hostnames = {}
    #     if do_reverse_dns:
    #         start_time_dns_resolution = time.time()

    #         ip_hostnames = self.reverse_dns(list(ips_to_resolve))
    #         end_time_dns_resolution = time.time() - start_time_dns_resolution
        
    #     if position_timeline is None:
    #         current_connections = all_connections
    #     else:
    #         # Get connections from the specified timeline position
    #         timeline_index = min(position_timeline, len(self.connection_list) - 1)
    #         return self.connection_list[timeline_index]['connection_list']   

    #     for conn in current_connections:
    #         if conn.status == psutil.CONN_ESTABLISHED:
    #             try:
    #                 # Get process information
    #                 process = psutil.Process(conn.pid) if conn.pid else None
    #                 process_name = process.name() if process else "Unknown"
                    
    #                 # Get local and remote addresses
    #                 local_addr = f"{conn.laddr.ip}"
    #                 remote_addr = f"{conn.raddr.ip}" if conn.raddr else "N/A"
                    
    #                 # Determine IP type
    #                 ip_type = ""
    #                 if conn.family == socket.AF_INET:
    #                     ip_type = "IPv4"
    #                 elif conn.family == socket.AF_INET6:
    #                     ip_type = "IPv6"

    #                 lat, lng = None, None
    #                 name = ""
                    
    #                 # Get coordinates for map
    #                 if ip_type == "IPv4":
    #                     ip = remote_addr.split(':')[0] if ':' in remote_addr else remote_addr
    #                 else:
    #                     ip = remote_addr

    #                 if ip not in ('127.0.0.1','::1'):
    #                     lat, lng = self.get_coordinates(ip, ip_type)

    #                     if do_reverse_dns:
                            
    #                         hostname = ip_hostnames.get(ip if ip else "N/A", None)

    #                         if hostname:                    
    #                             remote_addr += f" ({hostname})"
    #                             name = hostname
                    
    #                 if self.reader_c2_tracker is not None and do_c2_check:
    #                     is_c2, c2_type, c2_info = self.check_ip_is_present_in_c2_tracker(ip)
    #                     if  is_c2:
    #                         c2_connections.append({
    #                             'process': process_name,
    #                             'pid': str(conn.pid) if conn.pid else "N/A",
    #                             'suspect': 'Yes',
    #                             'local': local_addr,
    #                             'localport': str(conn.laddr.port) if conn.laddr else "N/A",
    #                             'remote': remote_addr,
    #                             'remoteport': str(conn.raddr.port) if conn.raddr else "N/A",
    #                             'name': name,
    #                             'ip_type': ip_type,
    #                             'lat': lat,
    #                             'lng': lng,                                  
    #                             'connection': conn,
    #                             'icon': 'redIcon'
    #                         })

    #                 connections.append({
    #                     'process': process_name,
    #                     'pid': str(conn.pid) if conn.pid else "N/A",
    #                     'suspect': '',
    #                     'local': local_addr,
    #                     'localport': str(conn.laddr.port) if conn.laddr else "N/A",
    #                     'remote': remote_addr,
    #                     'remoteport': str(conn.raddr.port) if conn.raddr else "N/A",
    #                     'name': name,
    #                     'ip_type': ip_type,
    #                     'lat': lat,
    #                     'lng': lng,                                  
    #                     'connection': conn,
    #                     'icon': 'greenIcon'
    #                 })

    #                 if len(self.connection_list) > 0 :
    #                     # Check if connection is already in the list
    #                     if not self.is_connection_in_list(connections[-1], self.connection_list[-1]['connection_list']):
    #                         connections[-1]['icon'] = 'blueIcon'  # Mark as new connection


    #             except (psutil.NoSuchProcess, psutil.AccessDenied):
    #                 # Skip connections that can't be accessed
    #                 continue

    #     if position_timeline is None:
    #         if len(c2_connections) > 0:
    #             c2_connections.extend(connections)
    #             connections = c2_connections
            
    #         current_time = datetime.datetime.now()

    #         # Add another connection as a dictionary with the current time and connection list

    #         another_connection = {
    #             "datetime": datetime.datetime.now(),
    #             "connection_list": connections
    #         }

    #         self.connection_list_counter = len(self.connection_list) 
    #         self.slider.setMaximum(self.connection_list_counter)
    #         self.slider_value_label.setText(TIME_SLIDER_TEXT + str(self.slider.value()) + "/" + str(len(self.connection_list)))

    #         # make sure we don't exceed max size to protect memory
    #         if self.connection_list_counter >= CONNECTION_LIST_MAX_SIZE:
    #             self.connection_list.pop(0)

    #         self.connection_list.append(another_connection)

    #     if do_reverse_dns:
    #         self.dns_resolution_time.setText(f"DNS lookups took : {end_time_dns_resolution:.4f} seconds")

    #     return connections

    def get_active_tcp_connections(self, position_timeline=None):
        """
        Enumerate TCP connections and build the connection snapshot.

        Performance and reliability improvements:
        - Use local variable references to reduce attribute lookups.
        - Avoid multiple calls to psutil.net_connections().
        - Build ip collection and perform reverse DNS in batches only when enabled.
        - Write to `self.connection_list` with minimum temporary allocations.
        """
        connections = []
        c2_connections = []

        # Get all connections once
        all_connections = psutil.net_connections(kind='inet')

        # Collect remote IPs for DNS resolution (only those we care about)
        ips_to_resolve = set()
        for c in all_connections:
            if c.status == psutil.CONN_ESTABLISHED and getattr(c, "raddr", None):
                raddr_ip = getattr(c.raddr, "ip", None)
                if raddr_ip and raddr_ip not in ('127.0.0.1', '::1'):
                    ips_to_resolve.add(raddr_ip)

        # ip_hostnames = {}
        # if do_reverse_dns and ips_to_resolve:
        #     start_time_dns = time.time()
        #     ip_hostnames = self.reverse_dns(list(ips_to_resolve))
        #     end_time_dns = time.time() - start_time_dns
        # else:
        #     end_time_dns = 0.0

        ip_hostnames = {}
        if do_reverse_dns and ips_to_resolve:
            # enqueue for background warming (non-blocking)
            try:
                if getattr(self, "dns_worker", None) is not None:
                    self.dns_worker.enqueue_many(ips_to_resolve)
            except Exception:
                pass

            # read any already-cached names immediately (non-blocking)
            with cache_lock:
                for ip in ips_to_resolve:
                    host = ip_cache.get(ip)
                    if host:
                        ip_hostnames[ip] = host
        else:
            ip_hostnames = {}


        # Use local references for speed
        reader_ipv4 = self.reader_ipv4
        reader_ipv6 = self.reader_ipv6
        reader_c2 = self.reader_c2_tracker
        do_c2 = do_c2_check

        # Choose the source of connections (live or timeline)
        if position_timeline is None:
            current_connections = all_connections
        else:
            idx = min(position_timeline, len(self.connection_list) - 1)
            return self.connection_list[idx]['connection_list']

        for conn in current_connections:
            if conn.status != psutil.CONN_ESTABLISHED:
                continue

            try:
                pid = conn.pid
                process = psutil.Process(pid) if pid else None
                process_name = process.name() if process else "Unknown"

                laddr = getattr(conn, "laddr", None)
                raddr = getattr(conn, "raddr", None)

                local_addr = f"{laddr.ip}" if laddr else "N/A"
                local_port = str(getattr(laddr, "port", "N/A")) if laddr else "N/A"

                remote_addr = f"{raddr.ip}" if raddr else "N/A"
                remote_port = str(getattr(raddr, "port", "N/A")) if raddr else "N/A"

                # Determine IP type
                family = getattr(conn, "family", None)
                ip_type = "IPv4" if family == socket.AF_INET else ("IPv6" if family == socket.AF_INET6 else "")

                lat = lng = None
                name = ""

                # obtain IP string for lookup (strip any appended hostname)
                ip_lookup = remote_addr.split(' ')[0].split(':')[0]

                if ip_lookup and ip_lookup not in ('127.0.0.1', '::1'):
                    # geolocation lookup
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
                    except Exception:
                        lat = lng = None

                    # reverse DNS result from batched lookup
                    if do_reverse_dns:
                        hostname = ip_hostnames.get(ip_lookup)
                        if hostname:
                            remote_addr = f"{remote_addr} ({hostname})"
                            name = hostname

                    # c2 check
                    if do_c2 and reader_c2 is not None:
                        try:
                            is_c2, c2_type, c2_info = self.check_ip_is_present_in_c2_tracker(ip_lookup)
                            if is_c2:
                                c2_connections.append({
                                    'process': process_name,
                                    'pid': str(pid) if pid else "N/A",
                                    'suspect': 'Yes',
                                    'local': local_addr,
                                    'localport': local_port,
                                    'remote': remote_addr,
                                    'remoteport': remote_port,
                                    'name': name,
                                    'ip_type': ip_type,
                                    'lat': lat,
                                    'lng': lng,
                                    'connection': conn,
                                    'icon': 'redIcon'
                                })
                        except Exception:
                            # ignore C2 lookup failures
                            pass

                # append standard connection entry
                connections.append({
                    'process': process_name,
                    'pid': str(pid) if pid else "N/A",
                    'suspect': '',
                    'local': local_addr,
                    'localport': local_port,
                    'remote': remote_addr,
                    'remoteport': remote_port,
                    'name': name,
                    'ip_type': ip_type,
                    'lat': lat,
                    'lng': lng,
                    'connection': conn,
                    'icon': 'greenIcon'
                })

                # if this is a new connection (timeline-based detection), mark it
                if self.connection_list:
                    try:
                        if not self.is_connection_in_list(connections[-1], self.connection_list[-1]['connection_list']):
                            connections[-1]['icon'] = 'blueIcon'
                    except Exception:
                        # defensive: ignore comparison errors
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                # defensive catch-all to avoid breaking the main loop for unexpected errors
                continue

        # Merge C2 entries at front if present
        if c2_connections:
            c2_connections.extend(connections)
            connections = c2_connections

        # record timeline snapshot only when requested (position_timeline is None)
        if position_timeline is None:
            another_connection = {
                "datetime": datetime.datetime.now(),
                "connection_list": connections
            }

            # append while ensuring we maintain the list size cap
            self.connection_list.append(another_connection)
            self.connection_list_counter = len(self.connection_list)
            # keep slider in sync
            self.slider.setMaximum(self.connection_list_counter)
            self.slider_value_label.setText(TIME_SLIDER_TEXT + str(self.slider.value()) + "/" + str(len(self.connection_list)))

            if self.connection_list_counter > CONNECTION_LIST_MAX_SIZE:
                # pop oldest until within limit
                excess = self.connection_list_counter - CONNECTION_LIST_MAX_SIZE
                for _ in range(excess):
                    self.connection_list.pop(0)
                self.connection_list_counter = len(self.connection_list)

        # update DNS timing metric
        if do_reverse_dns:
            try:
                self.dns_resolution_time.setText(f"DNS lookups took : {end_time_dns:.4f} seconds")
            except Exception:
                pass

        return connections

    
    def get_coordinates(self, ip_address, ip_type):
        """Get coordinates for an IP address"""

        if ip_type == "IPv4":
            try:
                # Get coordinates from the database
                result = self.reader_ipv4.get(ip_address)
                if result is not None:

                # if result and 'location' in result and result['location']:
                #     return result['location']['latitude'], result['location']['longitude']
                    return result['latitude'], result['longitude']                     
            except:
                pass
        
            return None, None
                            
        elif ip_type == "IPv6":
            try:
                # Get coordinates from the database
                result = self.reader_ipv6.get(ip_address)
                if result is not None:

                # if result and 'location' in result and result['location']:
                #     return result['location']['latitude'], result['location']['longitude']
                    return result['latitude'], result['longitude']                     
            except:
                pass
        
            return None, None
        
        else:
            return None, None
            
    def _pulse_map_indicator(self):
        """Show and start the pulse animation (non-blocking)."""
        try:
            self.pulse_indicator.setVisible(True)
            self._pulse_anim.stop()
            self._pulse_anim.start()
        except Exception:
            # defensive: ignore if animations not ready yet
            pass


    def update_map(self, connection_data, force_show_tooltip=False):
        """
        Load map HTML once and afterwards update markers via injected JavaScript
        using QWebEnginePage.runJavaScript(). Ensure we only call the updater after
        the page has finished loading to avoid "updateConnections is not defined".
        """
        data_json = json.dumps(connection_data)
        js = f"updateConnections({data_json}, {str(force_show_tooltip).lower()});"

        # If not initialized, load the full HTML and wait for loadFinished before calling JS
        if not getattr(self, "map_initialized", False):
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
                <style> html, body { height:100%; margin:0; } #map { height:100%; width:100%; } </style>
            </head>
            <body>
                <div id="map"></div>
                <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
                <script>
                    const iconDefinitions = {
                        'redIcon': new L.Icon({iconUrl:'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png', iconSize:[25,41], iconAnchor:[12,41]}),
                        'greenIcon': new L.Icon({iconUrl:'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png', iconSize:[25,41], iconAnchor:[12,41]}),
                        'blueIcon': new L.Icon({iconUrl:'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-blue.png', iconSize:[25,41], iconAnchor:[12,41]})
                    };

                    var map = L.map('map').setView([20, 0], 2);
                    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                        attribution: '&copy; OpenStreetMap contributors'
                    }).addTo(map);

                    var liveMarkers = [];

                    function updateConnections(conns, showTooltip) {
                        for (var i=0; i<liveMarkers.length; i++) {
                            try { map.removeLayer(liveMarkers[i]); } catch(e) {}
                        }
                        liveMarkers = [];

                        if (!conns || !Array.isArray(conns)) { return; }

                        conns.forEach(function(conn) {
                            if (conn.lat && conn.lng) {
                                var iconName = conn.icon || 'greenIcon';
                                var icon = iconDefinitions[iconName] || iconDefinitions['greenIcon'];
                                var marker = L.marker([conn.lat, conn.lng], { icon: icon }).addTo(map);
                                var tooltipOptions = { permanent: !!showTooltip, opacity: 0.9, direction: 'auto' };
                                marker.bindTooltip(conn.process || '', tooltipOptions);
                                var popupHtml = "<b>" + (conn.process || '') + "</b><br>" +
                                                "PID: " + (conn.pid || '') + "<br>" +
                                                "Remote: " + (conn.remote || '') + "<br>" +
                                                "Local: " + (conn.local || '') + "<br>";
                                marker.bindPopup(popupHtml);
                                liveMarkers.push(marker);
                            }
                        });
                    }

                    window.updateConnections = updateConnections;
                </script>
            </body>
            </html>
            """
            # load the HTML and call updateConnections only after loadFinished
            self.map_view.setHtml(html_content)

            def _on_loaded(ok):
                # run update if the page loaded successfully
                if ok:
                    try:
                        # call the updater now that the JS context is ready
                        self.map_view.page().runJavaScript(js)
                        # show pulse now that we sent the update
                        self._pulse_map_indicator()
                    except Exception:
                        pass
                # mark initialized and disconnect this one-shot handler
                try:
                    self.map_view.loadFinished.disconnect(_on_loaded)
                except Exception:
                    pass
                self.map_initialized = True

            # connect a one-shot handler that will invoke the JS updater when ready
            self.map_view.loadFinished.connect(_on_loaded)
            return

        # If already initialized, call the JS updater directly
        try:
            self.map_view.page().runJavaScript(js)
            # pulse after attempting to send the update
            self._pulse_map_indicator()
        except Exception:
            # fallback: force reinitialize on failure
            self.map_initialized = False
            self.map_view.setHtml("<html><body><h2>Reloading map...</h2></body></html>")
            QTimer.singleShot(200, lambda: self.update_map(connection_data, force_show_tooltip))

    def replay_connections(self):

        slider_position = self.slider.value()

        if len(self.connection_list) > 0:

            if slider_position >= self.connection_list_counter - 1:
                slider_position = 0
            self.refresh_connections(slider_position)
            slider_position +=1
            self.slider.setValue(slider_position)

        else:
            self.refresh_connections(self, 0)
            self.timer_replay_connections.stop()

        
        self.slider.setValue(slider_position)    
            
        # for conn in self.connection_list[slider_position]['connection_list'] :
        #     print(conn)
            #TODO implement replay logic here from refresh_connections
            
    def stop_capture_connections(self):
        if self.timer.isActive():
            self.timer.stop()
            self.start_capture_btn.setVisible(True)
            self.status_label.setText("Auto-refresh paused. Click 'Start Capture' to resume.")
            self.stop_capture_btn.setVisible(False)
            self.toggle_button.setVisible(True)

    def refresh_connections(self, slider_position=None):

        # if not self.timer.isActive():
        #     self.toggle_button.setVisible(False)
        #     self.stop_capture_btn.setVisible(True)

        # Get connections
        
        # Restart timer if it was a manual refresh triggerd by button

        force_tooltip = show_tooltip

        if slider_position is False:
            slider_position=None
            if not self.timer.isActive():
                self.timer.start(map_refresh_interval)
                self.start_capture_btn.setVisible(False)
                self.status_label.setText("")
                self.toggle_button.setVisible(False)
                self.stop_capture_btn.setVisible(True)                

        if self.timer_replay_connections.isActive():
            self.status_label.setText("Replaying connections.")

        number_of_previous_objects = self.map_objects
        
        self.connections = self.get_active_tcp_connections(slider_position)
        
        if len(self.connections) != number_of_previous_objects:
            self.map_redraw = True
            self.map_objects = len(self.connections)
            
            self.left_panel.setTitle(f"Active Connections - {self.map_objects} connections")
            

        
        # Update table
        self.connection_table.setRowCount(0)

        connections_to_show_on_map = []
        
        for conn in self.connections:
            # Add to table

            if not show_only_new_active_connections or (show_only_new_active_connections and conn['icon'] == 'blueIcon'):
                if conn['icon'] == 'blueIcon':
                    force_tooltip = True
                
                row = self.connection_table.rowCount()
                self.connection_table.insertRow(row)
                
                self.connection_table.setItem(row, PROCESS_ROW_INDEX, QTableWidgetItem(conn['process']))
                self.connection_table.setItem(row, PID_ROW_INDEX , QTableWidgetItem(conn['pid']))
                self.connection_table.setItem(row, SUSPECT_ROW_INDEX, QTableWidgetItem(conn['suspect']))
                self.connection_table.setItem(row, LOCAL_ADDRESS_ROW_INDEX, QTableWidgetItem(conn['local']))
                self.connection_table.setItem(row, LOCAL_PORT_ROW_INDEX, QTableWidgetItem(conn['localport']))
                self.connection_table.setItem(row, REMOTE_ADDRESS_ROW_INDEX, QTableWidgetItem(conn['remote']))
                self.connection_table.setItem(row, REMOTE_PORT_ROW_INDEX, QTableWidgetItem(conn['remoteport']))
                self.connection_table.setItem(row, NAME_ROW_INDEX, QTableWidgetItem(conn['name']))
                self.connection_table.setItem(row, IP_TYPE_ROW_INDEX, QTableWidgetItem(conn['ip_type']))


                
                lat, lng = None, None
                # Get coordinates for map
                if conn['ip_type'] == 'IPv4':
                    ip = conn['remote'].split(':')[0]# if ':' in conn['remote'] else conn['remote']
                    ip = ip.split(' (')[0]  # Remove any appended hostname
                else:
                    ip = conn['remote']

                if ip not in ('127.0.0.1','::1'):

                    ip = conn['remote'].split(' ')[0]
                    ip = ip.split(' (')[0]  # Remove any appended hostname                    

                    lat, lng = self.get_coordinates(ip, conn['ip_type'])

                    if lat is not None and lng is not None:
                        self.connection_table.setItem(row, LOCATION_LAT_ROW_INDEX, QTableWidgetItem(f"{lat}"))
                        self.connection_table.setItem(row, LOCATION_LON_ROW_INDEX, QTableWidgetItem(f"{lng}"))
                    else:
                        self.connection_table.setItem(row, LOCATION_LAT_ROW_INDEX, QTableWidgetItem("N/A"))
                        self.connection_table.setItem(row, LOCATION_LON_ROW_INDEX, QTableWidgetItem("N/A"))
                
                # location = f"{lat}, {lng}" if lat is not None else "N/A"
                # self.connection_table.setItem(row, LOCATION_ROW_INDEX, QTableWidgetItem(location))
                if conn['suspect'] == "Yes":
                    for col in range(self.connection_table.columnCount()):
                        self.connection_table.item(row, col).setForeground(Qt.red)

                    self.setStyleSheet("border: 2px solid red;") # Set window border to red
                    self.status_label.setText("Warning: Suspect C2 connections detected!")
                
                connections_to_show_on_map.append(conn)

            
        # Update map with connection data
        self.update_map(connections_to_show_on_map, force_tooltip)

        if table_column_sort_index>-1:
            self.column_resort(table_column_sort_index)  
    
    def on_map_loaded(self, success):
        if not success:
            #self.status_label.setText("Map loaded successfully")
        #else:
            self.status_label.setText("Error loading map")
    
    def on_table_cell_clicked(self, row, column):
        # Get the connection data for the clicked row
        lat, lng = None, None

        if row < self.connection_table.rowCount():
            ip_hostnames = {}
            name = ""
            

            # Get all items in the source row
            # row_items = []
            # for col in range(self.connection_table.columnCount()):
            #     item = self.connection_table.item(row, col).text()

                # if item:
                #     row_items.append(item.text())            
            # Extract data from table cells based on predefined columns
            remote_address = self.connection_table.item(row, REMOTE_ADDRESS_ROW_INDEX).text()
            process_name = self.connection_table.item(row, PROCESS_ROW_INDEX).text()
            pid = self.connection_table.item(row, PID_ROW_INDEX).text()
            local_address = self.connection_table.item(row, LOCAL_ADDRESS_ROW_INDEX).text()

            
            # Process IP and hostname
            ip = remote_address
            ip = ip.split(' (')[0]  # Remove any appended hostname
            if ip not in ('127.0.0.1','::1'):
                
                lat = self.connection_table.item(row, LOCATION_LAT_ROW_INDEX).text()
                lng = self.connection_table.item(row, LOCATION_LON_ROW_INDEX).text()                

                if do_reverse_dns:
                    hostname = self.connection_table.item(row, NAME_ROW_INDEX).text()

            
            # Check if the connection is marked as suspect
            suspect = (self.connection_table.item(row, SUSPECT_ROW_INDEX).text() == 'Yes')

            if suspect:
                icon = 'redIcon'
            else:
                icon = 'greenIcon'

            # Prepare focused data for map update
            focused_data = [{
                'process': process_name,
                'pid': pid,
                'suspect': suspect,
                'local': local_address,
                'remote': remote_address,
                'name': name,
                'lat': lat,
                'lng': lng,
                'connection': {},  # Placeholder if needed
                'icon': icon  # Default icon; change as needed based on conditions
            }]

            # Additional logic for C2 checks can be integrated here if required

            if lat is not None or lng is not None:
                self.update_map(focused_data)

def main():
    app = QApplication(sys.argv)
    viewer = TCPConnectionViewer()
    viewer.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

