#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -x ".venv/bin/python" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

echo "Installing core requirements..."
.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -r requirements.txt

echo "Installing optional requirements (best effort)..."
if ! .venv/bin/python -m pip install -r requirements-optional.txt; then
  echo "Warning: optional requirements failed. Core server still works."
fi

echo "Running preflight check..."
.venv/bin/python src/self_test.py

echo "Setup complete."
echo "Start server with: .venv/bin/python src/osint_tools_mcp_server.py"
