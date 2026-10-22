#!/usr/bin/env bash
# Run after installing the real pinned Hermes checkout and Heartwood dev deps.
set -euo pipefail
cd "$(dirname "$0")/../.."
python_bin="${1:-python3.14}"
"$python_bin" -m ruff check .
HEARTWOOD_TEST_HERMES=1 "$python_bin" -m pytest tests/test_hermes_integration.py -q
