# PTP ACR client: read config/ptp-acr-client.json and run python -m ptp_client.ptp.

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ConfigPath = Join-Path $Root "config\ptp-acr-client.json"

if (-not (Test-Path $ConfigPath)) {
    Write-Error "missing config: $ConfigPath"
}

. (Join-Path $PSScriptRoot "ptp-acr-config.ps1")
$cfg = Read-PtpAcrClientConfig -Path $ConfigPath

try {
    $resolved = Resolve-PtpAcrClientLaunch -Cfg $cfg
} catch {
    Write-Error $_.Exception.Message
}

if ($resolved.MasterSource -eq "wsl-eth0") {
    Write-Host ("GM (WSL eth0): {0}" -f $resolved.Master) -ForegroundColor Cyan
} else {
    Write-Host ("GM (config): {0}" -f $resolved.Master) -ForegroundColor Cyan
}
Write-Host ("profile={0} domain={1} transport={2} mode={3}" -f $resolved.Profile, $resolved.Domain, $resolved.Transport, $resolved.Mode) -ForegroundColor Cyan
if ($resolved.Bind) {
    Write-Host ("local bind: {0} (bind-port {1})" -f $resolved.Bind, $resolved.BindPort) -ForegroundColor Cyan
}

$env:PYTHONPATH = (Join-Path $Root "src")
Set-Location -LiteralPath $Root

$pythonExe = (Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
if (-not $pythonExe) {
    Write-Error "python not found on PATH"
}

$argDisplay = $resolved.PyArgs -join " "
Write-Host ("command: {0} {1}" -f $pythonExe, $argDisplay) -ForegroundColor DarkGray

$p = Start-Process -FilePath $pythonExe -ArgumentList $resolved.PyArgs -WorkingDirectory $Root -NoNewWindow -Wait -PassThru
if ($null -eq $p.ExitCode) { exit 1 }
exit $p.ExitCode
