@echo off
REM Opens a NEW window: WSL runs install_python311_apt.sh — type your Linux sudo password in that terminal.
REM (Cursor/agent cannot pop a system password dialog for automated commands.)

set "SCRIPT=/mnt/e/project/ptp_client/scripts/wsl/install_python311_apt.sh"

where wt >nul 2>nul
if %errorlevel% equ 0 (
  wt.exe new-tab wsl.exe -e bash -lc "bash '%SCRIPT%'; echo.; read -r -p 'Press Enter to close...' _"
) else (
  start "WSL Python 3.11 install" wsl.exe -e bash -lc "bash '%SCRIPT%'; echo.; read -r -p 'Press Enter to close...' _"
)
