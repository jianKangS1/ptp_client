#!/usr/bin/env bash
# Run in an interactive WSL terminal (double-click the .cmd on Windows, or: wsl bash /mnt/e/.../install_python311_apt.sh).
# sudo will prompt for your Linux user password in the terminal (not a separate GUI dialog).
set -euo pipefail
echo "=== Install Python 3.11 (deadsnakes) — enter your LINUX sudo password when asked ==="
sudo apt-get update
sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv python3.11-dev
python3.11 -V
echo "Done."
