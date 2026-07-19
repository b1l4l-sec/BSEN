#!/usr/bin/env bash
# BSEN installer (Linux / macOS)
# Created by b1l4l-sec.
# Usage: ./scripts/install.sh [--with-remote]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> BSEN installer (by b1l4l-sec)"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "!! $PYTHON_BIN not found. Install Python 3.9+ and re-run." >&2
    exit 1
fi

PY_VERSION=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
echo "==> Using Python $PY_VERSION"

VENV_DIR="${VENV_DIR:-.venv}"
if [ ! -d "$VENV_DIR" ]; then
    echo "==> Creating virtual environment at $VENV_DIR"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

echo "==> Installing BSEN"
pip install --upgrade pip -q
pip install -e . -q

if [[ "${1:-}" == "--with-remote" ]]; then
    echo "==> Installing remote-audit extras (paramiko, pywinrm)"
    pip install -e ".[remote]" -q
fi

echo ""
echo "==> Done. Activate with:  source $VENV_DIR/bin/activate"
echo "==> Then run:             bsen scan"
echo ""
echo "Verifying installation..."
bsen --version
