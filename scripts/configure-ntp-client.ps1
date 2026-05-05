# NTP 客户端「配置相关」命令：校验 config/ntp-client.json 并打印将传给 CLI 的参数（不发起网络请求）。
# 修改运行参数请直接编辑 config/ntp-client.json。

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ConfigPath = Join-Path $Root "config\ntp-client.json"

if (-not (Test-Path $ConfigPath)) {
    Write-Error "缺少配置文件: $ConfigPath"
}

$cfg = (Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8) | ConvertFrom-Json

Write-Host "配置文件: $ConfigPath" -ForegroundColor Cyan
Write-Host ("  host    = {0}" -f $cfg.host)
Write-Host ("  port    = {0}" -f $(if ($null -ne $cfg.port) { $cfg.port } else { "(默认 123)" }))
Write-Host ("  timeout = {0}" -f $(if ($null -ne $cfg.timeout) { $cfg.timeout } else { "(默认 5)" }))
if ($cfg.extraArgs -and $cfg.extraArgs.Count -gt 0) {
    Write-Host ("  extraArgs = {0}" -f ($cfg.extraArgs -join ' '))
} else {
    Write-Host "  extraArgs = (无)"
}

$preview = @("python -m ptp_client.ntp", [string]$cfg.host)
if ($null -ne $cfg.port) { $preview += @("--port", [string]$cfg.port) }
if ($null -ne $cfg.timeout) { $preview += @("--timeout", [string]$cfg.timeout) }
if ($cfg.extraArgs) { $preview += $cfg.extraArgs }
Write-Host "`n等效命令（预览）:" -ForegroundColor Green
Write-Host ($preview -join ' ')
