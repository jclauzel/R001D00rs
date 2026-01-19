# Leaflet Resources - Local Fallback

This directory contains local fallback resources for the TCP Geo Map application.

## Required Files

### Marker Icons
Download these PNG files from [leaflet-color-markers](https://github.com/pointhi/leaflet-color-markers):

- **marker-icon-2x-red.png** - Red marker for C2/suspect connections  
  Download: https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png

- **marker-icon-2x-green.png** - Green marker for normal connections  
  Download: https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png

- **marker-icon-2x-blue.png** - Blue marker for new connections  
  Download: https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-blue.png

### Optional: Full Leaflet Bundle
For complete offline capability, you can also download:

- **leaflet.css** - Leaflet CSS  
  Download: https://unpkg.com/leaflet@1.9.4/dist/leaflet.css

- **leaflet.js** - Leaflet JavaScript library  
  Download: https://unpkg.com/leaflet@1.9.4/dist/leaflet.js

## Quick Download Script (PowerShell)

```powershell
# Download marker icons
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png" -OutFile "marker-icon-2x-red.png"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png" -OutFile "marker-icon-2x-green.png"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-blue.png" -OutFile "marker-icon-2x-blue.png"

# Optional: Download Leaflet library
Invoke-WebRequest -Uri "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" -OutFile "leaflet.css"
Invoke-WebRequest -Uri "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" -OutFile "leaflet.js"
```

## Quick Download Script (Linux/macOS)

```bash
# Download marker icons
wget https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png
wget https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png
wget https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-blue.png

# Optional: Download Leaflet library
wget https://unpkg.com/leaflet@1.9.4/dist/leaflet.css
wget https://unpkg.com/leaflet@1.9.4/dist/leaflet.js
```

## License

The marker icons from leaflet-color-markers are licensed under MIT License.
Leaflet is licensed under BSD-2-Clause License.

Please review their respective licenses before use.
