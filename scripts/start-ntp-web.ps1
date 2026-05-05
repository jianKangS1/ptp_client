# 仅启动 NTP Web 控制台（不安装依赖）。请先运行 VS Code 任务「NTP Web: 安装依赖 (pip web)」。
# 默认 http://127.0.0.1:8765/

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $Root
$env:PYTHONPATH = (Join-Path $Root "src")

Write-Host "PYTHONPATH=$env:PYTHONPATH" -ForegroundColor DarkGray
Write-Host "Open http://127.0.0.1:8765/  (Ctrl+C to stop)" -ForegroundColor Cyan

python -m ptp_client.web
$code = $LASTEXITCODE
if ($code -ne 0) {
    Write-Host ""
    Write-Host "Process exited with $code. If 'No module named fastapi', run task: NTP Web: 安装依赖 (pip web)" -ForegroundColor Yellow
    exit $code
}
