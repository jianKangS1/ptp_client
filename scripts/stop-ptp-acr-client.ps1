# Kill orphaned PTP ACR client Python processes (after VS Code "Terminate Task" left them running).

$ErrorActionPreference = "Stop"

$procs = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" |
    Where-Object { $_.CommandLine -match 'ptp_client\.ptp' }

if (-not $procs) {
    Write-Host "No python.exe running ptp_client.ptp found." -ForegroundColor Yellow
    exit 0
}

foreach ($p in $procs) {
    Write-Host ("Stopping PID {0}: {1}" -f $p.ProcessId, $p.CommandLine) -ForegroundColor Cyan
    Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "Done." -ForegroundColor Green
