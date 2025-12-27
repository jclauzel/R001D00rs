# Summary
tcp_geo_map.py is a python desktop tool that enumerates active TCP connections (via `psutil`), resolves geolocation using (MaxMind GeoLite2) and optional can perform reverse DNS/C2 checks. 
"Live snapshots" of the outbound tcp connections are then displayed in a Qt GUI (`PySide6`) with a Leaflet map using OpenStreetMap giving a graphical representation of where the current machine connects to.
If "Perform C2 checks against C2-TRACKER database" feature is on (turned on by default) user will be warned if the machine running the script connects to a suspected remote IP address.
"Live snapshots" refresh times can be customized, connections can be replayed and saved...

# Tested on
- (Kali) Linux
- Windows 11

![til](https://github.com/jclauzel/R001D00rs/tree/main/pictures/tcp_geo_map_demo.gif)

# Contributors & Attribution

* This script uses GeoLite2 geo database to render the remote IP location using OpenStreetMap/leaflet/folium check out: https://github.com/sapics/ip-location-db/tree/main/geolite2-city

When prompted for download and agreed the script will fetch the following two files and save them in the database subfolder:
- https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv4.mmdb
- https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv6.mmdb

Accepting GeoLite2 the licensing terms for GeoLite is a requirement for this application to work.

GeoLite2 is created by MaxMind. The license of GeoLite2 is written in GEOLITE2_LICENSE and End User License Agreement (EULA) is written in GEOLITE2_EULA. Please carefully read the GEOLITE2_LICENSE and GEOLITE2_EULA files, if you use these database. This package comes with certain restrictions and obligations, most notably:

You cannot prevent the library from updating the databases.
You cannot use the GeoLite2 data:
for FCRA purposes,
to identify specific households or individuals.
You can read the latest version of GeoLite2 EULA here https://www.maxmind.com/en/geolite2/eula. GeoLite2 databse is provided under CC BY-SA 4.0 by MaxMind.

* C2_TRACKER 
C2 Tracker is a free-to-use-community-driven IOC feed that uses Shodan searches to collect IP addresses of known malware/botnet/C2 infrastructure.

When prompted for download and agreed the script will fetch the following file containing the list of C2 Suspect IP addresses and save it in the database subfolder:
- https://github.com/montysecurity/C2-Tracker/raw/refs/heads/main/data/all.txt

* maxminddb
* PySide6
* psutil
* folium / OpenStreetMap
* https://github.com/pointhi/leaflet-color-markers

When a remote C2/suspect IP connection listed is the C2_TRACKER is made the UI will turn red, display a warning message and the process making such a call will be tagged in red and "C2" column will mark "Yes".

Databases are considered as obsolete after a week and you will be prompted to refresh it.

# Avoiding prompts
You can start the script by passing --accept_eula this means you agree, approve to follow all the licensing terms of all contributors and attributions including GeoLite2/MaxMind, C2_TRACKER, PySide6, psutil, folium / OpenStreetMap. 
When --accept_eula is passed the databases will be downloaded automatically when they expire (by default every 7 days).

# Telemetry/Internet Access
When starting the application will download leaflet/OpenStreetMap marker icons from https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img so internet access is required.

# Persistent IP DNS reverse cache file
PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK = False # set to True to turn on and speedup application start time, False to disable. However this will keep track on disk to what IP addresses machine was connected to.
IP_DNS_NAME_CACHE_FILE = "ip_cache.json" # if PERSIST_LOCAL_DNS_CACHE_NAME_RESOLUTION_TO_DISK is set to true the application will save and load to disk the IP DNS Name resolution made as name resolution is slow from the database sub folder. Next time the application start it will reload this cache to speed up startup time of the application

# Map marker colors
- Green icon - Connection that is available since the last refresh
- Blue icon - A new connection was made
- Red icon - A possible C2 / Suspect connection

Markers can be clicked for additional details, map can be zoomed...

# Warranty, Disclaimer of Warranty, Limitation of Liability.
THE SCRIPT SOFTWARE IS PROVIDED "AS IS." THE AUTHOR MAKES NO WARRANTIES OF ANY KIND WHATSOEVER WITH RESPECT TO SCRIPT SOFTWARE WHICH MAY CONTAIN THIRD PARTY COMMERCIAL SOFTWARE. 
IN NO EVENT WILL THE AUTHOR BE LIABLE FOR ANY LOST REVENUE, PROFIT OR DATA, OR FOR DIRECT, SPECIAL, INDIRECT, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY ARISING OUT OF THE USE OF OR INABILITY TO USE THE SCRIPT SOFTWARE, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
