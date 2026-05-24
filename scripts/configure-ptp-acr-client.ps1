# Validate config/ptp-acr-client.json and print the equivalent python command (no network I/O).

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

Write-Host "config: $ConfigPath" -ForegroundColor Cyan
Write-Host ("  profile   = {0}" -f $resolved.Profile)
Write-Host ("  master    = {0} ({1})" -f $resolved.Master, $resolved.MasterSource)
Write-Host ("  domain    = {0}" -f $resolved.Domain)
Write-Host ("  transport = {0}" -f $resolved.Transport)
Write-Host ("  mode      = {0}" -f $resolved.Mode)
if ($null -ne $cfg.announceLogPeriod) {
    Write-Host ("  announceLogPeriod = {0} (interval 2^n s)" -f $cfg.announceLogPeriod)
}
if ($null -ne $cfg.syncLogPeriod) {
    Write-Host ("  syncLogPeriod     = {0} (interval 2^n s)" -f $cfg.syncLogPeriod)
}
if ($null -ne $cfg.durationSec) {
    Write-Host ("  durationSec       = {0}" -f $cfg.durationSec)
}
if ($null -ne $cfg.delayRequest) {
    Write-Host "  delayRequest      =" -ForegroundColor DarkGray
    if ($cfg.delayRequest.clockIdentity) {
        Write-Host ("    clockIdentity   = {0}" -f $cfg.delayRequest.clockIdentity)
    }
    if ($null -ne $cfg.delayRequest.portNumber) {
        Write-Host ("    portNumber      = {0}" -f $cfg.delayRequest.portNumber)
    }
    if ($null -ne $cfg.delayRequest.flags) {
        Write-Host ("    flags           = 0x{0:X} ({1})" -f [int]$cfg.delayRequest.flags, $cfg.delayRequest.flags)
    }
    if ($null -ne $cfg.delayRequest.correctionFieldNs) {
        Write-Host ("    correctionFieldNs = {0}" -f $cfg.delayRequest.correctionFieldNs)
    }
    if ($null -ne $cfg.delayRequest.requestIntervalSec) {
        Write-Host ("    requestIntervalSec = {0} s (client send rate, not in PTP header)" -f $cfg.delayRequest.requestIntervalSec)
    }
}
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
