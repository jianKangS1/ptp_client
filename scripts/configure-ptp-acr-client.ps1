# Validate config/ptp-acr-client.json and print the equivalent python command (no network I/O).

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ConfigPath = Join-Path $Root "config\ptp-acr-client.json"

if (-not (Test-Path $ConfigPath)) {
    Write-Error "missing config: $ConfigPath"
}

. (Join-Path $PSScriptRoot "ptp-acr-config.ps1")
$cfg = (Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8) | ConvertFrom-Json

try {
    $resolved = Resolve-PtpAcrClientLaunch -Cfg $cfg
} catch {
    Write-Error $_.Exception.Message
}

Write-Host "config: $ConfigPath" -ForegroundColor Cyan
Write-Host ("  profile   = {0}" -f $resolved.Profile)
Write-Host ("  master    = {0} ({1})" -f $resolved.Master, $resolved.MasterSource)
Write-Host ("  domain    = {0}" -f $resolved.Domain)
Write-Host ("  transport = {0}" -f $resolved.Transport)
Write-Host ("  mode      = {0}" -f $resolved.Mode)
if ($resolved.Bind) {
    Write-Host ("  bind      = {0}:{1}" -f $resolved.Bind, $resolved.BindPort)
} else {
    Write-Host "  bind      = (none)"
}
if ($cfg.extraArgs -and $cfg.extraArgs.Count -gt 0) {
    Write-Host ("  extraArgs = {0}" -f ($cfg.extraArgs -join ' '))
} else {
    Write-Host "  extraArgs = (none)"
}

$preview = @("python") + $resolved.PyArgs
Write-Host "`ncommand preview:" -ForegroundColor Green
Write-Host ($preview -join ' ')
