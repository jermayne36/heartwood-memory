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
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]" pytest
python -m pip install --no-deps "git+https://github.com/NousResearch/hermes-agent.git@2bd1977d8fad185c9b4be47884f7e87f1add0ce3"
python -m pip install PyYAML==6.0.3
python -m pytest
```

On Windows PowerShell, activate the environment with
`.\.venv\Scripts\Activate.ps1`; the remaining commands are unchanged.

## Command Style

Use forward slashes in repo-relative commands. They work in bash, zsh, and
Windows PowerShell.
