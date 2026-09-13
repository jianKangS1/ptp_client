# 启动 Web 控制台（NTP + PTP ACR 实验室）。请先安装依赖：pip install -e ".[web]"。
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
    Write-Host "Process exited with $code. If 'No module named fastapi', run: pip install -e `".[web]`"" -ForegroundColor Yellow
    exit $code
}
