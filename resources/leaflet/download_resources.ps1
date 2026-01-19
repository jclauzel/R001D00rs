# Download Leaflet marker icons and library
# Run this script from the resources/leaflet directory

Write-Host "Downloading Leaflet marker icons..." -ForegroundColor Green

try {
    # Download marker icons
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png" -OutFile "marker-icon-2x-red.png"
    Write-Host "  ✓ Downloaded marker-icon-2x-red.png" -ForegroundColor Green
    
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-green.png" -OutFile "marker-icon-2x-green.png"
    Write-Host "  ✓ Downloaded marker-icon-2x-green.png" -ForegroundColor Green
    
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-blue.png" -OutFile "marker-icon-2x-blue.png"
    Write-Host "  ✓ Downloaded marker-icon-2x-blue.png" -ForegroundColor Green

    Write-Host ""
    Write-Host "Downloading Leaflet library (optional, for full offline mode)..." -ForegroundColor Yellow
    
    Invoke-WebRequest -Uri "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" -OutFile "leaflet.css"
    Write-Host "  ✓ Downloaded leaflet.css" -ForegroundColor Green
    
    Invoke-WebRequest -Uri "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" -OutFile "leaflet.js"
    Write-Host "  ✓ Downloaded leaflet.js" -ForegroundColor Green

    Write-Host ""
    Write-Host "All files downloaded successfully!" -ForegroundColor Green
    
} catch {
    Write-Host ""
    Write-Host "Error downloading files: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please check your internet connection and try again." -ForegroundColor Yellow
    exit 1
}
