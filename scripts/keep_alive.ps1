<#
.SYNOPSIS
    Lightweight keep-alive heartbeat script for Glyph Render Relay.
.DESCRIPTION
    Pings https://glyph-relay.onrender.com/health every 10 minutes to prevent container sleep.
#>

$url = "https://glyph-relay.onrender.com/health"
$intervalSeconds = 600 # 10 minutes

Write-Host "Starting Glyph Relay Keep-Alive monitor (Interval: $intervalSeconds s)..." -ForegroundColor Cyan
Write-Host "Target: $url" -ForegroundColor DarkGray

while ($true) {
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 15
        Write-Host "[$timestamp] OK - Service: $($response.service), Status: $($response.status)" -ForegroundColor Green
    }
    catch {
        Write-Host "[$timestamp] PING FAILED: $_" -ForegroundColor Red
    }
    Start-Sleep -Seconds $intervalSeconds
}
