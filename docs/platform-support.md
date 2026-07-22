# Platform Support

Heartwood Memory targets local development on:

- macOS
- Linux
- Windows
- Linux containers

## Runtime Baseline

- Python 3.11+
- SQLite local mode by default
- Postgres optional, tested with PostgreSQL 16 through the local suite and manual verification workflow

## Local Verification

Use a fresh virtual environment so package installation and the core test suite
exercise only declared dependencies and the files in this repository:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
cd /path/to/heartwood-memory
bash scripts/check.sh
```

The local gate requires Python 3.11, runs Ruff, and runs the full pytest suite.
It visibly skips the optional Hermes Agent contract suite when that separate
integration is not installed.

To exercise that optional real-provider contract as well:

```bash
python -m pip install --no-deps "git+https://github.com/NousResearch/hermes-agent.git@2bd1977d8fad185c9b4be47884f7e87f1add0ce3"
python -m pip install PyYAML==6.0.3
python -m pytest tests/test_hermes_integration.py -q
```

On Windows PowerShell, activate the environment with
`.\.venv\Scripts\Activate.ps1`; the remaining commands are unchanged.

## Command Style

Use forward slashes in repo-relative commands. They work in bash, zsh, and
Windows PowerShell.
