# Summary

tcp_geo_map.py is a python desktop UI tool that enumerates active TCP and UDP connections (via `psutil` like a "netstat") per process, resolves geolocation using (MaxMind GeoLite2) and optionally it can perform reverse DNS/C2 checks. 
"Live snapshots" of the outbound TCP connections are then displayed in a Qt GUI (`PySide6`) with a Leaflet map using OpenStreetMap giving a graphical representation of where the current machine connects to.
If "Perform C2 checks against C2-TRACKER database" feature is on (turned on by default) users will be warned if the machine running the script connects to a suspected remote IP address. 

"Live network connection snapshots" refresh times can be customized, connections can be replayed and saved...
When the "Resolve public internet IP address" feature is turned on you can monitor your exit point.

Maximum connection snapshots to keep in memory can be modified on the Settings tab.

In the settings tab the "Capture screenshots of the map to disk" feature may be turned on to take screenshots of the map into the screen_captures folder. Everytime the map is lived refreshed an new .jpg file will be generated. When the feature is on a new button will apear on the main tab that will generate a new .mp4 video capture of all the present .jpg file in the same location. To prevent disk space from getting filled the older files are automaticaly deleted.

The latest release introduces many enhancements from general performance to agent (client) / server architecture and its new plugin API (ConnectionCollectorPlugin interface) that makes it extensible.

You can now start on one machine from the settings tab the server feature. Once done you can then deploy as many clients as you wish and point them to the server. From now on the server instance will now render remote machine connections allowing you to monitor your home machine network for example.

The built-in plugins are:

•	The psutil interface that requires low privileges.

•	A scapy live packet capture interface that requires administrative privileges or https://npcap.com/.

•	A pcap file visualization for recorded packet captures (pcaps).

# Why use tcp_geo_map.py?
Ever wondered, is this machine clean? To what endpoints and geographical destination is this host connecting to such as to sending telemetry or simply understand this machine "network" behavior based on what processes (running programs) on it? 
This GeoInt OSINT script UI shows on the earth map live network connections made and will warn based on the C2-Tracker list maintained by montysecurity if the machine connects to a suspicious C2 endpoint.

tcp_geo_map.pc as turned into a very effective forensic tool as each process / connection entry allows right clicking to collect traces on table of connections, dumps for Windows (using sysinternals toolset) and Linux (gcore, htop)

# Tested on
- (Kali, Bazzite) Linux
- Windows 11

![til](./pictures/tcp_geo_map_demo.gif)

# Contributors & Attribution
* This script uses GeoLite2 geo database to render the remote IP location using OpenStreetMap/leaflet/folium check out: https://github.com/sapics/ip-location-db/tree/main/geolite2-city

When prompted for download and agreed the script will fetch the following two files and save them in the database subfolder:
- https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv4.mmdb
- https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv6.mmdb

Accepting GeoLite2 the licensing terms for GeoLite is a requirement for this application to work.

GeoLite2 is created by MaxMind. The license of GeoLite2 is written in GEOLITE2_LICENSE and End User License Agreement (EULA) is written in GEOLITE2_EULA. Please carefully read the GEOLITE2_LICENSE and GEOLITE2_EULA files, if you use these databases. This package comes with certain restrictions and obligations, most notably:

You cannot prevent the library from updating the databases.
You cannot use the GeoLite2 data: for FCRA purposes, to identify specific households or individuals.
You can read the latest version of GeoLite2 EULA here https://www.maxmind.com/en/geolite2/eula. GeoLite2 database is provided under CC BY-SA 4.0 by MaxMind.

THe map is rendered using OpenStreetMap.org engine. OpenStreetMap data is available under the Open Database License (ODbL) v1.0 for further details please visit: https://www.openstreetmap.org/copyright/ and https://opendatacommons.org/licenses/odbl/1-0/.

* ipfy.com
Is a public internet API that provides any application such as this one to get its public address using an http call. If the "Resolve public internet IP using ipfy.com" checkbox is enabled a call to ipfy.com is performed and your public IP address will be queried and resolved using their service. If successful the public IP address will be shown on the map as a red circle.

* C2_TRACKER 
C2 Tracker is a free-to-use-community-driven IOC feed that searches to collect IP addresses of known malware/botnet/C2 infrastructure.

When prompted for download and agreed the script will fetch the following file containing the list of C2 Suspect IP addresses and save it in the database subfolder:
- https://github.com/montysecurity/C2-Tracker/raw/refs/heads/main/data/all.txt

* procmon-parser
When right clicking on a table item sysinternals procmon can be started to automaticaly start capturing process activity. To generate the procmon capture profile it uses https://github.com/eronnen/procmon-parser .

* flask
When using server and agent mode, the server will start by default a flask web server on port 5000 (port can be configured in the settings tab). You may need to create a firewall rule allow python to listen and allow remote agents (clients) to connect to it

* scapy
You may replace psutil collection by scapy live packet capture. To do so navigate to the settings tab and select the scapy collector. This requires to run the script (python) as an administrator. By default the scapy plugin will try to capture layer 2 packets and then falls back to layer 3 if not found. For layer 2 capture you will need to install https://npcap.com/ but this is not mandatory as if not present the default plugin will fallback to layer 3 (requiring administrative privileges though).

* aiodns
Is now used for async reverse dns name resolution.

tcp_geo_map uses:

* maxminddb
* PySide6
* psutil
* folium / OpenStreetMap
* opencv-python
* procmon-parser
* flask
* scapy
* https://github.com/pointhi/leaflet-color-markers
* aiodns

When a remote C2/suspect IP connection listed is the C2_TRACKER is made the UI will turn red, display a warning message and the process performing such a call will be tagged in red and "C2" column will mark "Yes".

Databases are considered as obsolete after a week, and you will be prompted to refresh it.

This tool has been developped with the help of Claude Sonnet and Claude Opus AI.

# Avoiding prompts
You can start the script by passing --accept_eula (Accept End User License Agreement) this means you agree, approve to follow all the licensing terms of all contributors and attributions including GeoLite2/MaxMind, C2_TRACKER, PySide6, psutil, folium / OpenStreetMap / Leaflet. 
When --accept_eula is passed the databases will be downloaded automatically when they expire (by default every 7 days) and the /resources/leaflet/ files cache will be populated automatically as well to speedup startup time and reduce telemetry footprint this means you agree as well with leaflet and https://github.com/pointhi/leaflet-color-markers licensing agreements.

# Offline / Telemetry reduction
Access to tile.openstreetmap.org is required to render the map so internet access is required to that site.
When starting the application will download leaflet/OpenStreetMap marker icons from https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img as well as https://unpkg.com/leaflet and will prompt you to cache them locally into /resources/leaflet/ in order to speed up next startup time.  You can also use the script download_resources.ps1 powershell script located in resources\leaflet directory  to download the below files independently.
If you want to be fully private you will need to download a .osm/.pbf extract of your area of interest, set up a local tile server or vector-tile stack, and point your `{z}/{x}/{y}` URL to your own server instead of tile.openstreetmap.org using the `TILE_OPENSTREETMAP_SERVER` constant in `tcp_geo_map.py` (see the Settings section below for details).

# Map marker colors
- Green icon - Connection that is available since the last refresh
- Blue icon - A new connection was made
- Red icon - A possible C2 / Suspect connection
- Yellow icon - A selected item.

Markers can be clicked for additional details, map can be zoomed...

# Install
- (kali) linux install using venv:

git clone https://github.com/jclauzel/R001D00rs

python3 -m venv ./R001D00rs

source R001D00rs/bin/activate

pip3 install pyside6 requests maxminddb psutil opencv-python procmon-parser flask scapy aiodns

or

pip install -r REQUIREMENTS.txt


Then execute script using:

cd R001D00rs 

python3 tcp_geo_map.py

- Windows:

Install a recent python interpreter from https://www.python.org/ if not done yet or directly from the Windows Store (search for Python and select 3.13 or higher).

Download source from latest "release" located on the right side of https://github.com/jclauzel/R001D00rs or git clone https://github.com/jclauzel/R001D00rs

Install required packages:

pip3 install pyside6 requests maxminddb opencv-python procmon-parser flask scapy aiodns

or

pip install -r REQUIREMENTS.txt

Execute the script:

python .\tcp_geo_map.py

- Note optional as a best practice it is always best to create an vistual environement here is how to do so:

Windows:

cd .\R001D00rs\

python -m venv R001D00rs

R001D00rs\Scripts\activate

pip install -r requirements.txt

python .\tcp_geo_map.py

deactivate



# Features overview
- Download and install of the MaxMind/GeoLite2 and https://github.com/montysecurity/C2-Tracker databases are made easy using a driven step-by-step process.
- When C2 detection is enabled if a remote connection to such a host defined in https://github.com/montysecurity/C2-Tracker/ database the UI will turn red and spew a warning.
- Remote IP location that can be resolved using MaxMind GeoLite2 will be displayed at every refresh on the OpenStreetMap. Note this IP geolocation is inherently imprecise and you can read more about this at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/ but gives a great starting point to whom your machine is communicating with.
- As the connections are refreshed based on a timer it is no case exhaustive and if a connection is opened and closed between two "netstat" collections it will not be collected, however, as stated above it is a good starting point. To avoid possible skipping connections keep the refresh time small (by default 2000 milliseconds so 2 seconds).
- Once connections have been captured you can use at any given point in time the time slider to revisit the connections or use the "replay" button option.
- Connections lists can be saved to disk.
- Maps can be moved, zoommed.
- UI state (screen full size, maximized) and settings are persisted to settings.json on script close. As a result next time the script is started, it restores its state as it was when leaving. F11 can be used to toggle on and off full-screen display.
- Settings can be rested by simply deleting the settings.json file stored in the same directory.
- The UI on the left shows the connection table collected at the time of the refresh and the map is shown on the right. There is a vertical slider that can be grabbed between the two to adjust the size and the map can be set fully horizontally.
- Bellow the map are located buttons and settings. There is also a horizontal slider that can be grabbed between these two parts of the screen. By combining the two sliders, you can have the map full screen.
- On the left table, connections are listed and can be selected. When clicked if the geo is resolved the map will show this unique remite address for clarity.
- Each table column can be sorted by clicking on the corresponding table header for example "Process".
- The application can be started by passing the --accept_eula as a parameter (as stated this means you accept and agree with MaxMind, GeoLite2, https://github.com/montysecurity/C2-Tracker, https://raw.githubusercontent.com/pointhi/leaflet-color-markers/ licensing terms ). Since the application starts capturing when the script start, the buffer will evict older connections and the UI reset its state to the selected monitor this means you can set the application to auto start when logging in and have live view of your connections on a separate monitor, for example.
- MaxMind/GeoLite2 and https://github.com/montysecurity/C2-Tracker databases will be considered stale/obsolete after 7 days by default. When this occurs the application will prompt for a new download of the database. The process is eased and automated through the UI when accepting the licensing rights. When --accept_eula is passed as a startup parameter since it means you agree with their licensing terms, the download of the databases will be done automatically.
- Summary tab shows an aggregated list view of all connections that are still in the capture buffer. This is useful for many reasons and may help uncover quick sporadic connections.
- No high privileges required during execution on Linux some limitations may apply check psutil.net_connections section at https://psutil.readthedocs.io/en/latest/.

# Settings

All settings are persisted in `settings.json` (located in the same directory as the script) and are saved automatically whenever a setting is changed in the UI, as well as when the application closes. To reset all settings to their defaults, delete `settings.json` — it will be recreated with defaults on the next launch.

The table below documents every key stored in `settings.json`.

---

### Connection capture

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_connection_list_filo_buffer_size` | integer | `1000` | Maximum number of connection snapshots kept in memory. The capture buffer is a First-In-First-Out (FIFO) queue: once full, the oldest snapshot is evicted to make room for the newest. Larger values let you look further back in time using the time slider or replay feature but consume more memory. Configurable on the Settings tab. |
| `map_refresh_interval` | integer (ms) | `2000` | How often (in milliseconds) the connection table and map are refreshed. Lowering this value reduces the chance of missing short-lived connections. Selectable from the refresh-interval drop-down on the main tab. |
| `show_only_new_active_connections` | boolean | `false` | When `true`, only connections that are **new** since the previous refresh are shown in the table and on the map. Useful for spotting sudden new activity without noise from persistent connections. |
| `show_only_remote_connections` | boolean | `false` | When `true`, loopback addresses (`127.0.0.1`, `::1`) and other purely local connections are hidden from the connection table. Local connections are never plotted on the map regardless of this setting. |
| `do_pause_table_sorting` | boolean | `false` | When `true`, the connection table stops re-sorting on each refresh cycle. Existing sort order is preserved so you can read the table without it jumping. New connections are still collected and appended; sorting resumes when unchecked. |

---

### Name resolution & enrichment

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `do_reverse_dns` | boolean | `true` | Perform reverse DNS lookups on remote IP addresses. Lookups are executed by a background thread to avoid blocking the UI, so the **Name** column may take a moment to populate after startup. Resolved hostnames also appear in map marker pop-ups. |
| `do_resolve_public_ip` | boolean | `false` | When `true`, the application periodically queries [ipify.org](https://api.ipify.org) to determine the machine's current public/exit IP address and plots it on the map as a red circle. The result is cached for 60 seconds to avoid excessive external requests. Only useful when behind NAT or a VPN where the local IP differs from the public one. |
| `do_c2_check` | boolean | `false` | Enable C2-Tracker threat-intelligence checks. Each remote IP is compared against the [montysecurity/C2-Tracker](https://github.com/montysecurity/C2-Tracker) database. When a match is found the UI turns red, a warning is displayed, and the offending row is tagged **C2: Yes** in the table. Requires the C2-Tracker database to be downloaded first (prompted automatically or via `--accept_eula`). |

---

### Display & table sorting

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `table_column_sort_index` | integer | `-1` | Column index used to sort the main connection table. `-1` means no explicit sort is applied (connections appear in capture order). |
| `table_column_sort_reverse` | boolean | `false` | Sort direction for the main connection table. `false` = ascending, `true` = descending. |
| `summary_table_column_sort_index` | integer | `-1` | Column index used to sort the Summary tab aggregated table. `-1` means no explicit sort. |
| `summary_table_column_sort_reverse` | boolean | `false` | Sort direction for the Summary tab table. `false` = ascending, `true` = descending. |

---

### Screenshots & recording

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `do_capture_screenshots` | boolean | `false` | When `true`, a `.jpg` screenshot of the map is written to the `screen_captures/` folder every time the map refreshes. Once enabled, a **Generate Video** button appears on the main tab that compiles all current screenshots into an `.mp4` video using OpenCV. Older screenshots are automatically pruned to prevent unbounded disk growth. Requires `opencv-python`. |

---

### Window & map layout

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `is_fullscreen` | boolean | `false` | Whether the application window was full-screen when last closed. Restored automatically on the next launch. |
| `is_maximized` | boolean | `false` | Whether the application window was maximized when last closed. Restored automatically on the next launch. Mutually exclusive with `is_fullscreen`. |
| `fullscreen_screen_name` | string | `null` | The OS display name (e.g. `"\\.\DISPLAY1"`) of the monitor the window was on. Used to restore the window to the correct screen on multi-monitor setups. |
| `splitter_state` | string (Base64) | `null` | Serialized state of the horizontal splitter that divides the connection table (left) from the map (right). Restored automatically; do not edit by hand. |
| `right_splitter_state` | string (Base64) | `null` | Serialized state of the vertical splitter that divides the map (top) from the controls/settings area (bottom). Restored automatically; do not edit by hand. |
| `map_center_lat` | float | — | Latitude of the map viewport centre when the application was last closed. Restored on next launch so the map opens at the same position. |
| `map_center_lng` | float | — | Longitude of the map viewport centre when the application was last closed. |
| `map_zoom` | integer | — | Zoom level of the map when the application was last closed. |

---

### Server / Agent mode

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enable_server_mode` | boolean | `false` | When `true`, the application starts a Flask HTTP endpoint (default port 5000) that accepts connection data POSTed by remote agents. All agent connections are rendered on the map alongside local connections. |
| `enable_agent_mode` | boolean | `false` | When `true`, the application periodically POSTs its live connection snapshot to the configured server. Can be combined with `--no_ui` / `--no_ui_off` for headless deployment. |
| `agent_server_host` | string | `""` | Hostname or IP address of the server to POST to in agent mode. No scheme or port — e.g. `"192.168.1.10"` or `"myserver"`. Configured via the **Agent server address** field on the Settings tab. |
| `flask_server_port` | integer | `5000` | TCP port the Flask server listens on in server mode. Must be reachable by all agents; a firewall rule may be required. |
| `flask_agent_port` | integer | `5000` | TCP port the agent POSTs to on the server. Must match `flask_server_port` on the server side. |
| `agent_no_ui` | boolean | `false` | When `true`, the application window is never shown — the process runs headless as a background agent. Equivalent to passing `--no_ui` on the command line. Set to `false` explicitly via `--no_ui_off`. Only meaningful when `enable_agent_mode` is also `true`. |
| `max_server_agents` | integer | `100` | Maximum number of distinct agents the server will accept simultaneously. When the limit is reached, new (unknown) agents receive HTTP 429 (Too Many Requests) and a rejection overlay is shown on their map. Agents already in the cache are unaffected. Persisted to and loaded from `settings.json`; also editable by changing the `MAX_SERVER_AGENTS` constant in the script. Must be a positive integer. |
| `agent_colors` | object | `{}` | Maps each remote agent hostname to a display colour used for its map markers and table rows, e.g. `{"laptop": "blue", "server": "green"}`. Managed automatically by the **Agent Management** tab; colours persist across restarts. |

---

### Connection collector plugin

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `active_collector_plugin` | string | `"Psutil Collector"` | Name of the active connection-collector plugin. Built-in options: `"Psutil Collector"` (default, low-privilege), `"Scapy Live Capture"` (requires admin/root or Npcap on Windows), `"PCAP File"` (offline replay of a saved `.pcap`). Selectable on the Settings tab. |
| `pcap_file_path` | string | `""` | Absolute path to the `.pcap` file used when `active_collector_plugin` is `"PCAP File"`. Set via the **Browse** button on the Settings tab. Has no effect when any other collector is active. |

---

### Other settings configurable in the script itself

The following constants are not exposed in the UI and must be changed directly in `tcp_geo_map.py`:

| Constant | Default | Description |
|----------|---------|-------------|
| `PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK` | `False` | Set to `True` to persist the reverse-DNS cache to `ip_cache.json` between runs. Speeds up startup but leaves a record on disk of every IP address the machine has connected to. |
| `IP_DNS_NAME_CACHE_FILE` | `"ip_cache.json"` | File name used for the on-disk DNS cache when `PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK` is enabled. |
| `DATABASE_EXPIRE_AFTER_DAYS` | `7` | Number of days after which the GeoLite2 and C2-Tracker databases are considered stale and a refresh is prompted. |
| `TILE_OPENSTREETMAP_SERVER` | `"tile.openstreetmap.org"` | Tile server hostname used to render the map. Change this to point to a self-hosted tile server for fully offline / private operation. |

# Troubleshooting
The script can spew additional information by changing in the tcp_geo_map.py:

logging.basicConfig(

    level=logging.WARNING,
    
by

logging.basicConfig(

    level=logging.DEBUG,

# Known limitations
- Proxies since this is where the remote IP address is.
- Tor usage will only show the first hop node.

# Warranty, Disclaimer of Warranty, Limitation of Liability.
THE SCRIPT SOFTWARE IS PROVIDED "AS IS." THE AUTHOR MAKES NO WARRANTIES OF ANY KIND WHATSOEVER WITH RESPECT TO SCRIPT SOFTWARE WHICH MAY CONTAIN THIRD PARTY COMMERCIAL SOFTWARE. 
IN NO EVENT WILL THE AUTHOR BE LIABLE FOR ANY LOST REVENUE, PROFIT OR DATA, OR FOR DIRECT, SPECIAL, INDIRECT, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY ARISING OUT OF THE USE OF OR INABILITY TO USE THE SCRIPT SOFTWARE, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
