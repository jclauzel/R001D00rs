# Summary

tcp_geo_map.py is a python desktop UI tool that enumerates active TCP connections (via `psutil` like a "netstat") per process, resolves geolocation using (MaxMind GeoLite2) and optionally it can perform reverse DNS/C2 checks. 
"Live snapshots" of the outbound TCP connections are then displayed in a Qt GUI (`PySide6`) with a Leaflet map using OpenStreetMap giving a graphical representation of where the current machine connects to.
If "Perform C2 checks against C2-TRACKER database" feature is on (turned on by default) users will be warned if the machine running the script connects to a suspected remote IP address. 

"Live network connection snapshots" refresh times can be customized, connections can be replayed and saved...
When the "Resolve public internet IP address" feature is turned on you can monitor your exit point.

# Why use tcp_geo_map.py?
Ever wondered, is this machine clean? To what endpoints and geographical destination is this host connecting to such as to sending telemetry or simply understand this machine "network" behavior based on what processes (running programs) on it? 
This GeoInt OSINT script UI shows on the earth map live network connections made and will warn based on the C2-Tracker list maintained by montysecurity if the machine connects to a suspicious C2 endpoint.

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

* maxminddb
* PySide6
* psutil
* folium / OpenStreetMap
* https://github.com/pointhi/leaflet-color-markers

When a remote C2/suspect IP connection listed is the C2_TRACKER is made the UI will turn red, display a warning message and the process performing such a call will be tagged in red and "C2" column will mark "Yes".

Databases are considered as obsolete after a week, and you will be prompted to refresh it.

# Avoiding prompts
You can start the script by passing --accept_eula (Accept End User License Agreement) this means you agree, approve to follow all the licensing terms of all contributors and attributions including GeoLite2/MaxMind, C2_TRACKER, PySide6, psutil, folium / OpenStreetMap / Leaflet. 
When --accept_eula is passed the databases will be downloaded automatically when they expire (by default every 7 days) and the /resources/leaflet/ files cache will be populated automatically as well to speedup startup time and reduce telemetry footprint this means you agree as well with leaflet and https://github.com/pointhi/leaflet-color-markers licensing agreements.

# Offline / Telemetry reduction
Access to tile.openstreetmap.org is required to render the map so internet access is required to that site.
When starting the application will download leaflet/OpenStreetMap marker icons from https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img as well as https://unpkg.com/leaflet and will prompt you to cache them locally into /resources/leaflet/ in order to speed up next startup time.  You can also use the script download_resources.ps1 powershell script located in resources\leaflet directory  to download the below files independently.
If you want to be fully private you will need to download a .osm/.pbf extract of your area of interest, set up a local tile server or vector-tile stack, and point your `{z}/{x}/{y}` URL to your own server instead of tile.openstreetmap.org using the TILE_OPENSTREETMAP_SERVER constant variable defined in the tcp_geo_map.py script though I have not tested this setup myself. 


# Persistent IP DNS reverse cache file
PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK = False set to True to turn on and speedup the script start time, False to disable. However this will keep track on the disk to what IP addresses machine was connected to.

IP_DNS_NAME_CACHE_FILE = "ip_cache.json" if PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK is set to true the application will save and load from the disk the IP DNS Name resolution made as name resolution is slow from the database subfolder. Next time the application starts it will reload this cache to speed up startup time of the script.

# Map marker colors
- Green icon - Connection that is available since the last refresh
- Blue icon - A new connection was made
- Red icon - A possible C2 / Suspect connection

Markers can be clicked for additional details, map can be zoomed...

# Install
- (kali) linux install using venv:

git clone https://github.com/jclauzel/R001D00rs

python3 -m venv ./R001D00rs

source R001D00rs/bin/activate

pip3 install pyside6 requests maxminddb psutil

or

pip install -r REQUIREMENTS.txt

python3 tcp_geo_map.py

- Windows:

Install a recent python interpreter from https://www.python.org/ if not done yet or directly from the Windows Store (search for Python and select 3.13 or higher).

Download source from latest "release" located on the right side of https://github.com/jclauzel/R001D00rs or git clone https://github.com/jclauzel/R001D00rs

Install required packages:

pip3 install pyside6 requests maxminddb

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
- No high privileges required during execution.

# Settings

Settings are persisted in a local file called settings.json and are saved when closing the script.
To reset them either change the various options in the UI or simply delete the settings.json file that will be recreated at the next execution.

Sample settings.json with explanations:

"max_connection_list_filo_buffer_size": 1000, // At each refresh intervals the connection list is maintained in memory and added to a First In First Out item type buffer. When the buffer is full, it will evict one at the time older connection list. The purpose of this is to allow you to go back in time using the time slider or to replay connections.

"do_c2_check": true, // Perfom C2 checks

"show_only_new_active_connections": false, // Only show new active connections (at the next refresh interval) on the map.

"show_only_remote_connections": true, // Only show remote connections made (at the next refresh interval) on the table, when selecting these remote IP addresses of 127.0.0.1 or ::1 will not be shown in the table. Local connections are not shown on the map anyway.

"do_reverse_dns": true, // Perform reverse DNS (Domain Name Service) lookups on remote IP addresses. Since this task is time consuming, this action is performed by a background worker thread when the script starts. Therefore, it may take a little while for the "Name" column to be populated. When the DNS name resolution is successful and remote location can be resolved, the DNS name will be shown as well when clicking on the marker on the map.

"map_refresh_interval": 2000, // "netstat" connection refresh interval in milliseconds

"table_column_sort_index": -1, // Left table ordering column number (-1 means no ordering is made on any table column)

"table_column_sort_reverse": false, // Left table ordering (ascending / descending)

"splitter_state": "AAAA/wAAAAEAAAACAAAAAAAABdwBAAAABgEAAAABAA==", // Horizontal splitter position

"right_splitter_state": "AAAA/wAAAAEAAAACAAADggAAAAABAAAABgEAAAACAA==" // Vertical splitter position

"is_fullscreen": false, // Allows restoring full-screen on startups - setting will be applied/reset after every closing of the script.

"is_maximized": true, // Allows restoring maximized screen on startups (it is either full-screen or maximized) - setting will be applied/reset after every closing of the script

"fullscreen_screen_name": "MyScreenName" // Allows restoring the application UI back on to the right screen - setting will be applied/reset after every closing of the script.

Other settings that you may tweak in the script itself:

* PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK = False 
Set to True to turn on and speedup script start time, False to disable. However this will keep track on the disk to what IP addresses machine was connected to.

* IP_DNS_NAME_CACHE_FILE = "ip_cache.json"
If PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK is set to true the script will save and load from disk the IP DNS Name resolution made as name resolution is slow from the database subfolder. Next time the application start it will reload this cache to speed up startup time and name resolution of the tcp_geo_map.py script.

* DATABASE_EXPIRE_AFTER_DAYS = 7
Databases expiration time in days from the last download date, default 7 days (1 week)

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
