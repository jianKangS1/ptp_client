# NTP 客户端启动脚本：读取 config/ntp-client.json，调用 Python 模块。
# 在仓库根目录执行，或由 VS Code 任务调用。

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ConfigPath = Join-Path $Root "config\ntp-client.json"

if (-not (Test-Path $ConfigPath)) {
    Write-Error "缺少配置文件: $ConfigPath"
}

$raw = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
# 允许 JSON 中带注释时失败：当前配置为严格 JSON
$cfg = $raw | ConvertFrom-Json

if (-not $cfg.host) {
    Write-Error "config/ntp-client.json 中必须包含 host 字段"
}

$env:PYTHONPATH = (Join-Path $Root "src")

$argList = @(
    "-m", "ptp_client.ntp",
    [string]$cfg.host
)
if ($null -ne $cfg.port) {
    $argList += @("--port", ([string]$cfg.port))
}
if ($null -ne $cfg.timeout) {
    $argList += @("--timeout", ([string]$cfg.timeout))
}
if ($cfg.extraArgs -and $cfg.extraArgs.Count -gt 0) {
    foreach ($a in $cfg.extraArgs) {
        $argList += [string]$a
    }
}

Set-Location -LiteralPath $Root
Write-Host "python $($argList -join ' ')" -ForegroundColor DarkGray
& python @argList
exit $LASTEXITCODE
