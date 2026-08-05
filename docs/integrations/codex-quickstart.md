# Codex Quickstart

This is the Option A path for giving Codex governed memory through Heartwood's
existing MCP server. The supported path today is local stdio: Codex starts
`heartwood.adapters.mcp_server` as a child process. Hosted or remote MCP is a
Phase 2 roadmap item and should not be documented as live until an HTTP MCP
endpoint exists, is deployed, and is smoke-tested.

Minimum Codex CLI version for this recipe: `0.141.0`.

## Prerequisites

- Python 3.11 or newer, available here as `python3.11`
- Codex CLI 0.141.0 or newer
- A fresh clone of this repository, with your shell in the repository root

## Install Heartwood And Create Its Data Directory

Create a repository-local virtual environment, install the checked-out source,
and create a durable data directory outside the clone:

```bash
python3.11 -m venv .venv
PYBIN="$PWD/.venv/bin/python"
"$PYBIN" -m pip install --quiet -e ".[recall,mcp]"

HEARTWOOD_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/heartwood"
mkdir -p "$HEARTWOOD_DATA_DIR"
HEARTWOOD_DB_PATH="$HEARTWOOD_DATA_DIR/heartwood.db"

printf 'Python: %s\nDatabase: %s\n' "$PYBIN" "$HEARTWOOD_DB_PATH"
```

Keep this shell open for the remaining commands. `PYBIN` and
`HEARTWOOD_DB_PATH` are absolute paths, so Codex can start Heartwood regardless
of the directory from which you launch it. The `mkdir` is required before
SQLite opens the database on its first run.

## Register The Local MCP Server

Safe default: read-only recall plus health. Add `remember` or `forget` only when
the tenant has explicitly approved write or erasure access for Codex.

```bash
codex mcp add heartwood \
  --env HEARTWOOD_DB_PATH="$HEARTWOOD_DB_PATH" \
  --env HEARTWOOD_TENANT=tenant:ops \
  --env HEARTWOOD_MCP_ALLOWED_TOOLS=recall,explain_recall,health \
  -- "$PYBIN" -m heartwood.adapters.mcp_server

codex mcp list --json
```

The `codex mcp list --json` output must include a `heartwood` server before you
rely on the memory tools.

## Equivalent `~/.codex/config.toml`

Use this form for reviewed config, infrastructure-managed laptops, or settings
that the CLI command does not expose directly.

```toml
[mcp_servers.heartwood]
command = "/absolute/path/to/heartwood-memory/.venv/bin/python"
args = ["-m", "heartwood.adapters.mcp_server"]
env = { HEARTWOOD_DB_PATH = "/absolute/path/to/heartwood-data/heartwood.db", HEARTWOOD_TENANT = "tenant:ops", HEARTWOOD_MCP_ALLOWED_TOOLS = "recall,explain_recall,health" }
startup_timeout_sec = 45
tool_timeout_sec = 120
enabled = true
enabled_tools = ["recall", "explain_recall", "health"]

[memories]
disable_on_external_context = true
generate_memories = false
```

`startup_timeout_sec = 45` avoids false startup failures when the embedder is
cold-loading. The server-side `HEARTWOOD_MCP_ALLOWED_TOOLS` value is the hard
gate; Codex `enabled_tools` is a client-side narrowing layer and should not be
the only control. If `HEARTWOOD_MCP_ALLOWED_TOOLS` is ever unset, the server fails
closed to the read-only subset (`recall`, `explain_recall`, `health`) rather than
exposing write or erasure tools.

The `[memories]` block is required for governed deployments:

- `disable_on_external_context = true` is the baseline for every Heartwood MCP
  deployment. It prevents Codex's local memory process from summarizing
  MCP-touching sessions into a separate local store.
- `generate_memories = false` is required for regulated or governed tenants that
  need Heartwood to be the only durable memory store.

## Allowlist Patterns

| Pattern | `HEARTWOOD_MCP_ALLOWED_TOOLS` | Codex `enabled_tools` |
|---|---|---|
| Read-only default | `recall,explain_recall,health` | `["recall", "explain_recall", "health"]` |
| Governed write access | `recall,explain_recall,remember,health` | `["recall", "explain_recall", "remember", "health"]` |
| Operator-approved erasure | `recall,explain_recall,remember,forget,health` | `["recall", "explain_recall", "remember", "forget", "health"]` |

Valid server tools are `remember`, `recall`, `explain_recall`, `forget`,
`evaluate_egress`, `assess_faithfulness`, `memory`, and `health`. Unknown names
fail server startup. Avoid exposing `memory`, `evaluate_egress`, or
`assess_faithfulness` to Codex unless the deployment has a specific reason to
use those tools.

## AGENTS.md Template

After registering the MCP server, add the usage instructions from
`docs/integrations/codex-AGENTS.md.template` to the `AGENTS.md` file Codex reads.
Those instructions tell Codex when to call `recall`, `remember`, `explain_recall`,
and `forget`.

## Local Verification

```bash
codex --version
codex mcp get heartwood --json
```

Then run the Heartwood-side smoke checks. The recipe test starts the configured
server over stdio, completes an MCP handshake, lists the read-only tools, calls
`health`, and confirms that the database was created at the absolute path:

```bash
HEARTWOOD_DB_PATH="$HEARTWOOD_DB_PATH" \
HEARTWOOD_TENANT=tenant:ops \
HEARTWOOD_MCP_ALLOWED_TOOLS=recall,explain_recall,health \
"$PYBIN" tests/test_codex_recipe.py

"$PYBIN" tests/test_mcp_hardening.py
```

If the Codex CLI is unavailable in your environment, the Heartwood tests still
validate the recipe text and MCP allowlist contract, but the CLI registration
step remains manual.
