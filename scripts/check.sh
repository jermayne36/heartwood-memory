#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3.11 >/dev/null 2>&1; then
  echo "error: Python 3.11 is required for the local quality gate. Install it, then run bash scripts/check.sh." >&2
  exit 1
fi

python_version="$(python3.11 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$python_version" != "3.11" ]]; then
  echo "error: expected python3.11 to report Python 3.11, got Python $python_version." >&2
  exit 1
fi

if ! python3.11 -c 'import pytest, ruff' >/dev/null 2>&1; then
  echo "error: missing development tools. Run: python3.11 -m pip install -e \".[dev]\"" >&2
  exit 1
fi

python3.11 -m ruff check .
python3.11 -m pytest tests/ -q
