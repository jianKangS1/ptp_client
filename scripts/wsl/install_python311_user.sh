#!/usr/bin/env bash
# Install Python 3.11+ in WSL without sudo (via uv). Run: bash scripts/wsl/install_python311_user.sh
set -euo pipefail
export PATH="${HOME}/.local/bin:${PATH}"
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="${HOME}/.local/bin:${PATH}"
uv python install 3.11
echo "Installed interpreters:"
uv python list
echo "Smoke test:"
uv run --python 3.11 python -V
