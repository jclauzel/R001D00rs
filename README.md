# tcp_geo_map.py

A Python desktop tool that enumerates active TCP and UDP connections per process, resolves geolocation via MaxMind GeoLite2, and displays them on a live Leaflet/OpenStreetMap in a PySide6 Qt GUI. Connection snapshots are collected on a configurable timer, stored in a FIFO replay buffer, and can be replayed at any time using the built-in timeline slider.

---

## Why use tcp_geo_map.py?

Ever wondered what endpoints a machine is connecting to, or whether it is sending unexpected telemetry? tcp_geo_map.py renders live network connections on an interactive world map per process, letting you see at a glance *who* is talking, *where*, and *how much* traffic is flowing. It is equally useful as a day-to-day privacy monitor and as a forensic triage tool -- each row in the connection table can be right-clicked to launch Sysinternals Process Monitor, dump the process (Windows/Linux), and more.

---

## Tested on

- Kali Linux, Bazzite Linux
- Windows 11

![Demo](./pictures/tcp_geo_map_demo.gif)

---

## Requirements

On Windows it is recommended to install [Npcap](https://npcap.com/) for full Layer 2 capture; without it the collector falls back to Layer 3. Administrative/root privileges are required for raw socket access regardless of Npcap presence.²

---

## Built-in connection collector plugins

The active collector is selected in **Settings -> Connection Collector Plugin**. The default is **Scapy Live Capture**.

| Plugin | Notes |
|--------|-------|
| **Scapy Live Capture** *(Recommended -- default)* | Live packet capture via Scapy `sniff()`. Provides per-connection byte-level sent/recv accounting. On Windows, install [Npcap](https://npcap.com/) for full Layer 2 capture; without it the collector falls back to Layer 3. Requires administrative/root privileges or Npcap. |
| **psutil / OS connection table** | Uses `psutil.net_connections()` supplemented with `netstat`/`ss`. Lower privilege requirements; no byte-level traffic accounting. |
| **PCAP File Collector** | Reads an existing `.pcap` / `.pcapng` file and overlays its traffic byte counts on the live OS connection table. Useful for offline analysis of recorded captures. Requires `scapy`. |

> **Windows without Npcap:** If Npcap is not installed and the Scapy collector is active, a one-time warning dialog is shown directing you to [https://npcap.com/](https://npcap.com/). This warning can be suppressed permanently via **Settings -> Warn if Npcap is not installed**.

---

## Database persistence providers

Connection history can be persisted across restarts. Configured in **Settings -> Database Persistence**.

| Provider | Notes |
|----------|-------|
| **Disabled** *(default)* | No persistence; the in-memory buffer is lost on exit. |
| **SQLite** *(Recommended)* | Zero-configuration local file at `connection_databases/connection_history.db`. |
| **MongoDB** | Requires a running MongoDB instance. |
| **SQL Server** | Requires a reachable SQL Server instance. |
| **Oracle** | Requires a reachable Oracle database instance. |

Use `--force_complete_database_load` at startup to pre-fill the in-memory buffer from the database and replay the full stored history on the timeline slider without starting live capture.

---

## Server / Agent mode

One machine can run as a **server** and aggregate connections POSTed by multiple remote **agents**:

1. On the server: enable **Server mode** in Settings (or pass `--enable_server_mode`). A Flask endpoint starts on the configured port (default `5000`).
2. On each client: enable **Agent mode** in Settings and point it at the server hostname (or pass `--enable_agent_mode <host>`). The agent periodically POSTs its live connections to the server.
3. The server renders all agents connections on the same map, colour-coded per agent. Up to `MAX_SERVER_AGENTS` (default `100`) distinct agents are accepted; new agents beyond this limit receive HTTP 429.

You may need to add a firewall rule to allow inbound TCP on the Flask port.

---

## Map marker colours

| Colour | Meaning |
|--------|---------|
| Green | Connection present since the last refresh |
| Blue | New connection observed this refresh cycle |
| Red | Public exit-point circle; or a suspicious IP flagged by IPAnalyze |
| Yellow | Currently selected connection |

Markers are clickable for details; the map can be panned and zoomed freely.

---

## Features overview

- **Live geo-mapping** -- remote IP locations resolved via MaxMind GeoLite2 plotted on OpenStreetMap at every refresh.
- **Timeline replay** -- captured snapshots stored in a FIFO buffer; use the time slider or the Replay button to step through history.
- **Traffic gauges & histogram** -- per-marker sent/recv byte gauges and a global traffic histogram overlay (requires Scapy or PCAP collector).
- **Summary tab** -- aggregated per-process/host connection statistics across the entire capture buffer; useful for spotting sporadic short-lived connections.
- **Reverse DNS** -- background async DNS lookups populate the **Name** column without blocking the UI.
- **Public IP monitoring** -- optional ipify.com query to show the current internet exit point on the map.
- **Screenshot & video capture** -- optionally save a `.jpg` map screenshot on every refresh; generate an `.mp4` timelapse from captured frames. Old frames are deleted automatically to avoid filling disk space.
- **Right-click actions** -- per-row context menu to launch Sysinternals Process Monitor (Windows), create process dumps (Windows/Linux), and copy connection details.
- **Persistent UI state** -- window geometry, settings, column widths, column order, and map position/zoom are all saved to `settings.json` automatically.
- **Full-screen mode** -- press `F11` to toggle; the map can be expanded to fill the entire window using the two resizable splitters.
- **Extensible collector API** -- drop a new `ConnectionCollectorPlugin` subclass into the `plugins/` directory and it appears automatically in the Settings collector combo.
- **Headless agent mode** -- run as a background agent with no window using `--no_ui` combined with `--enable_agent_mode`.

---

## Install

### Linux (venv recommended)

```bash
git clone https://github.com/jclauzel/R001D00rs
python3 -m venv ./R001D00rs
source R001D00rs/bin/activate
pip install -r REQUIREMENTS.txt
cd R001D00rs
python3 tcp_geo_map.py
```

### Windows

1. Install Python 3.13+ from [python.org](https://www.python.org/) or the Microsoft Store.
2. Download the latest release from [GitHub Releases](https://github.com/jclauzel/R001D00rs/releases) or `git clone https://github.com/jclauzel/R001D00rs`.
3. Install dependencies:

```bat
pip install -r REQUIREMENTS.txt
```

4. Run:

```bat
python tcp_geo_map.py
```

**Windows venv (best practice):**

```bat
cd R001D00rs
python -m venv R001D00rs
R001D00rs\Scripts\activate
pip install -r REQUIREMENTS.txt
python tcp_geo_map.py
deactivate
```

> **Scapy / Npcap on Windows:** Install [Npcap](https://npcap.com/) for full Layer 2 packet capture with the Scapy collector. Without it the collector falls back to Layer 3 (administrative privileges still required for raw socket access).

---

## Command-line options

```
Usage: python tcp_geo_map.py [OPTIONS]

  --accept_eula
      Automatically accept the GeoLite2/MaxMind EULA and allow the database
      to be downloaded and refreshed on startup without prompting. By passing
      this flag you confirm you have read and agree to all licensing terms
      listed in the Contributors & Attribution section.

  --enable_server_mode
      Start in server mode. A Flask endpoint is started on the configured
      port (default 5000) to collect connection data from remote agents.

  --enable_agent_mode <host>
      Start in agent mode. The app periodically POSTs its live connection
      data to the server at <host> (bare hostname/IP or legacy full URL
      e.g. "http://myserver:5000").

  --no_ui
      Run as a headless background agent -- no window is shown and no
      taskbar button is created. Only meaningful with --enable_agent_mode.

  --no_ui_off
      Explicitly disable headless mode and persist that choice to
      settings.json so future launches without any flag also show the UI.
      Takes precedence over any saved "agent_no_ui" value in settings.json.

  --force_complete_database_load
      Override the in-memory buffer size with the database limit and
      pre-fill the buffer from the persisted database so the full stored
      history is available on the timeline slider. Live capture is NOT
      started -- the app enters replay-only mode. Has no effect when the
      database layer is set to "Disabled".

  -h, -?, /?, --h, --help
      Show this help message and exit.
```

---

## Offline / telemetry reduction

- **Map tiles** -- `tile.openstreetmap.org` is required to render the map. To run fully offline, point `TILE_OPENSTREETMAP_SERVER` in `tcp_geo_map.py` to a self-hosted tile server.
- **Leaflet resources** -- on first launch the app downloads Leaflet JS/CSS and marker icons from `unpkg.com` and `raw.githubusercontent.com` and caches them in `resources/leaflet/`. Use `resources/leaflet/download_resources.ps1` to pre-populate this cache offline.
- **ipify.com** -- queried only when **Resolve public internet IP using ipify.com** is enabled. Uncheck to disable entirely.
- **GeoLite2 database** -- downloaded once (with EULA acceptance) and refreshed automatically after 7 days. Stored in the `database/` subfolder.

---

## Contributors & attribution

### MaxMind GeoLite2

IP geolocation database used to resolve remote IP coordinates.
Source: [ip-location-db/geolite2-city-mmdb](https://github.com/sapics/ip-location-db/tree/main/geolite2-city)

Files downloaded on first use (with EULA acceptance):
- `https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv4.mmdb`
- `https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv6.mmdb`

GeoLite2 is created by MaxMind and provided under CC BY-SA 4.0. Licensing terms are in `GEOLITE2_LICENSE` and `GEOLITE2_EULA`. See also: [MaxMind GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula).

### OpenStreetMap / Leaflet

Map rendering uses the OpenStreetMap engine. Data is available under the [Open Database License (ODbL) v1.0](https://opendatacommons.org/licenses/odbl/1-0/). See [openstreetmap.org/copyright](https://www.openstreetmap.org/copyright/).
Marker icons from [leaflet-color-markers](https://github.com/pointhi/leaflet-color-markers).

### ipify.com

Provides the public IP address lookup when **Resolve public internet IP using ipify.com** is enabled.

### procmon-parser

Used to auto-generate Sysinternals Process Monitor capture profiles when right-clicking a table row.
Source: [eronnen/procmon-parser](https://github.com/eronnen/procmon-parser)

### Flask

Powers the server endpoint in server/agent mode (default port 5000).

### Scapy

Used by the Scapy Live Capture collector plugin and the PCAP File Collector plugin.
Install [Npcap](https://npcap.com/) on Windows for full Layer 2 capture.

### aiodns

Used for asynchronous reverse DNS name resolution.

---

## Python dependencies

```
aiodns
PySide6 >= 6.5.1
psutil >= 5.9.5
maxminddb >= 2.2.0
pandas >= 2.0.3
numpy >= 1.25.0
requests >= 2.31.0
folium >= 0.14.0
opencv-python >= 4.8.0
procmon-parser >= 0.3.3
flask >= 3.0.0
scapy >= 2.5.0
```

---

## Settings

All settings are persisted in `settings.json` (same directory as the script) and saved automatically on every change and on application close. To reset all settings to defaults, delete `settings.json` -- it is recreated on the next launch.

---

### Connection capture

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_connection_list_filo_buffer_size` | integer | `1000` | Maximum connection snapshots kept in the in-memory FIFO replay buffer. When full, the oldest snapshot is evicted. Larger values allow deeper history replay but use more memory. Configurable on the Settings tab. |
| `map_refresh_interval` | integer (ms) | `1000` | How often the connection table and map are refreshed in milliseconds. Lower values reduce the chance of missing short-lived connections. |
| `show_only_new_active_connections` | boolean | `false` | When `true`, only connections new since the previous refresh are shown in the table and on the map. |
| `show_only_remote_connections` | boolean | `false` | When `true`, loopback and LAN-local connections are hidden from the table and map. |
| `do_pause_table_sorting` | boolean | `false` | When `true`, the main connection table stops re-sorting on each refresh so you can read it without rows jumping. New connections are still collected. |
| `do_collect_connections_asynchronously` | boolean | `true` | When `true`, connection collection runs on a background thread, keeping the UI responsive during slow collector operations such as VPN switches. Set to `false` as a thread-safety fallback; all three views (table, map, Summary) work correctly in both modes. |
| `do_show_listening_connections` | boolean | `false` | When `true`, sockets in the `LISTEN` state are included in the connection table. |
| `do_always_supplement_psutil_with_netstat_when_available` | boolean | `true` | When `true`, psutil connection data is cross-referenced with `netstat`/`ss` to catch connections psutil may miss (e.g. system-owned sockets on Linux). |

---

### Name resolution & enrichment

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `do_reverse_dns` | boolean | `true` | Perform async reverse DNS lookups on remote IPs. Results populate the **Name** column and map marker pop-ups. |
| `do_resolve_public_ip` | boolean | `true` | Periodically query [ipify.org](https://api.ipify.org) for the machine's public exit IP and plot it on the map as a red circle. Result is cached for 60 seconds. |
| `do_pulse_exit_points` | boolean | `true` | Animate a pulsing ring on agent/server exit-point circles on the map. |

---

### Display & map

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `do_show_traffic_gauge` | boolean | `true` | Show per-marker sent/recv byte gauges on the map. Requires the Scapy Live Capture or PCAP File Collector plugin. |
| `do_show_traffic_histogram` | boolean | `true` | Show the network traffic histogram overlay on the map. |
| `do_capture_screenshots` | boolean | `false` | Save a `.jpg` screenshot of the map to `screen_captures/` on every refresh. When enabled a **Generate .mp4 video** button appears on the main tab. Old frames are deleted automatically. |
| `table_column_sort_index` | integer | `-1` | Column index for the main connection table sort. `-1` = insertion order. |
| `table_column_sort_reverse` | boolean | `false` | Sort direction for the main table. `false` = ascending, `true` = descending. |
| `summary_table_column_sort_index` | integer | `-1` | Column index for the Summary tab sort. `-1` = insertion order. |
| `summary_table_column_sort_reverse` | boolean | `false` | Sort direction for the Summary table. `false` = ascending, `true` = descending. |
| `conn_table_column_order` | integer[] | `[]` | Persisted visual column order for the main connection table (logical indices). |
| `summary_table_column_order` | integer[] | `[]` | Persisted visual column order for the Summary table (logical indices). |
| `conn_table_column_widths` | integer[] | `[]` | Persisted per-column pixel widths for the main connection table. |
| `summary_table_column_widths` | integer[] | `[]` | Persisted per-column pixel widths for the Summary table. |

---

### Connection collector plugin

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `active_collector_plugin` | string | `"Scapy Live Capture"` | Name of the active collector plugin. Built-in values: `"Scapy Live Capture"` *(Recommended)*, `"psutil"`, `"PCAP File Collector"`. |
| `pcap_file_path` | string | `""` | Path to the `.pcap` / `.pcapng` file used by the PCAP File Collector. Configurable via the Settings tab. |
| `do_scapy_force_use_interface_name` | string | `""` | When non-empty, passed as `iface=` to Scapy `sniff()`, overriding interface auto-detection. Use the **Scapy interface** combo in Settings to select from available interfaces. |
| `do_warn_npcap_not_installed` | boolean | `true` | When `true`, a one-time warning dialog is shown on startup if Npcap is not detected and the Scapy collector is active. Uncheck **Warn if Npcap is not installed** in Settings to suppress future warnings. |

---

### Database persistence

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `db_provider_name` | string | `"Disabled"` | Database backend for persistent connection history. Options: `"Disabled"`, `"SQLite"` *(Recommended)*, `"MongoDB"`, `"SQL Server"`, `"Oracle"`. |
| `max_connection_list_database_size` | integer | `100000` | Maximum snapshots stored in the database. Older records are purged automatically when the limit is exceeded. |

---

### Server / Agent mode

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enable_server_mode` | boolean | `false` | Start a Flask server endpoint to receive connections from remote agents. |
| `enable_agent_mode` | boolean | `false` | Periodically POST this machine's live connections to a remote server. |
| `agent_server_host` | string | `""` | Hostname or IP of the server to POST to in agent mode (no scheme, no port). |
| `flask_server_port` | integer | `5000` | Port the Flask server listens on (server mode). |
| `flask_agent_port` | integer | `5000` | Port the agent POSTs to (agent mode). |
| `max_server_agents` | integer | `100` | Maximum distinct agents accepted by the server. New agents beyond this limit receive HTTP 429. |
| `agent_no_ui` | boolean | `false` | When `true` in agent mode, the window is never shown (headless agent). |
| `agent_colors` | object | `{}` | Per-agent hex colour assignments used to colour-code each agent's markers on the map. |
| `agent_hidden` | object | `{}` | Per-agent visibility flags. Agents set to `true` are hidden from the map and table. |

---

### Logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `loggingLevel` | string | `"WARNING"` | Python logging level written to the console. Valid values: `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"`, `"CRITICAL"`. |

---

## Avoiding prompts

Pass `--accept_eula` to suppress the GeoLite2 EULA prompt and allow automatic database downloads and refreshes without prompting. By passing this flag you confirm you have read and agree to all licensing terms listed in the Contributors & Attribution section above (MaxMind GeoLite2, OpenStreetMap/Leaflet, leaflet-color-markers).

When `--accept_eula` is passed the Leaflet resource cache (`resources/leaflet/`) is also populated automatically on first run to speed up subsequent startups and reduce external requests.

---

## Development notes

This tool was developed with the assistance of Claude Sonnet and Claude Opus AI.