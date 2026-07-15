# Codex Quickstart

This is the Option A path for giving Codex governed memory through Heartwood's
existing MCP server. The supported path today is local stdio: Codex starts
`heartwood.adapters.mcp_server` as a child process. Hosted or remote MCP is a
Phase 2 roadmap item and should not be documented as live until an HTTP MCP
endpoint exists, is deployed, and is smoke-tested.

Minimum Codex CLI version for this recipe: `0.141.0`.

## Install Heartwood In A Python Environment

Install Heartwood with the MCP extra in the Python environment you want Codex to
launch:

```bash
/absolute/path/to/.venv/bin/python -m pip install "heartwood-memory[recall,mcp]"
/absolute/path/to/.venv/bin/python -c "import sys; print(sys.executable)"
```

Use the absolute interpreter path printed by the second command. Do not configure
Codex with a bare `python`, `python3`, or `python3.11` command unless you fully
control the PATH for every Codex launch.

## Register The Local MCP Server

Safe default: read-only recall plus health. Add `remember` or `forget` only when
the tenant has explicitly approved write or erasure access for Codex.

```bash
PYBIN="/absolute/path/to/.venv/bin/python"

codex mcp add heartwood \
  --env HEARTWOOD_DB_PATH=.heartwood/heartwood.db \
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
command = "/absolute/path/to/.venv/bin/python"
args = ["-m", "heartwood.adapters.mcp_server"]
env = { HEARTWOOD_DB_PATH = ".heartwood/heartwood.db", HEARTWOOD_TENANT = "tenant:ops", HEARTWOOD_MCP_ALLOWED_TOOLS = "recall,explain_recall,health" }
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
codex mcp list --json
```

Then run the Heartwood-side smoke checks:

```bash
/absolute/path/to/.venv/bin/python tests/test_codex_recipe.py
/absolute/path/to/.venv/bin/python tests/test_mcp_hardening.py
```

If the Codex CLI is unavailable in your environment, the Heartwood tests still
validate the recipe text and MCP allowlist contract, but the CLI registration
step remains manual.
