# MCP Quickstart

This is the Phase 1 B4 path for using Heartwood as a governed MCP memory server.
The checked-in `.mcp.json` runs the published package through `uvx` and stores
local runtime state in `heartwood.db`. It needs no repository path
or virtual-environment path.

## Install

```bash
uvx heartwood-memory
```

The first run creates a cached, isolated environment from the published PyPI
package. Stop the foreground process after it starts; the MCP client launches
the same command over stdio.

## Configure

The repo includes this directly runnable, read-only config:

```json
{
  "mcpServers": {
    "heartwood-memory": {
      "command": "uvx",
      "args": ["heartwood-memory"],
      "env": {
        "HEARTWOOD_DB_PATH": "heartwood.db",
        "HEARTWOOD_TENANT": "tenant:ops",
        "HEARTWOOD_MCP_ALLOWED_TOOLS": "recall,explain_recall,health"
      }
    }
  }
}
```

Override `HEARTWOOD_DB_PATH` when you want MCP to use the same store built by
`import-markdown` or `bulk-remember`.

The starter config names only the read-only subset (`recall`, `explain_recall`,
`health`); see the next section to enable write or erasure tools. If the variable
is omitted, the server still fails closed to the same subset.

## Default Exposure Is Fail-Closed

The server is fail-closed: when `HEARTWOOD_MCP_ALLOWED_TOOLS` is unset, only the
read-only subset (`recall`, `explain_recall`, `health`) is exposed. The write verb
`remember`, the `/memories` file verb `memory`, and the destructive `forget`
(crypto-shred erasure) are NOT exposed by default — name them explicitly to opt in.

To expose write or erasure tools, set a comma-separated allowlist that includes
them. The server logs a stderr warning whenever a mutating or destructive verb is
exposed, so an unintended `forget` is visible in logs:

```json
{
  "mcpServers": {
    "heartwood-memory-write": {
      "command": "uvx",
      "args": ["heartwood-memory"],
      "env": {
        "HEARTWOOD_DB_PATH": "heartwood.db",
        "HEARTWOOD_TENANT": "tenant:ops",
        "HEARTWOOD_MCP_ALLOWED_TOOLS": "recall,explain_recall,remember,health"
      }
    }
  }
}
```

Valid tool names are `remember`, `recall`, `explain_recall`, `forget`,
`evaluate_egress`, `assess_faithfulness`, `memory`, and `health`. Unknown names
fail closed at server startup.

## Tools

| Tool | Purpose |
|---|---|
| `remember` | Tenant-aware governed write with classification, roles, attrs, source IDs, provenance signing, audit, encryption, and indexing |
| `recall` | Policy-enforced recall; denied memories are not returned or counted in the response |
| `explain_recall` | Ranking/freshness explanation without denied-candidate side channels |
| `forget` | Crypto-shred subject key and purge derived memories |
| `evaluate_egress` | Check source spans before external model egress |
| `assess_faithfulness` | Check generated-memory claims against source spans |
| `memory` | Anthropic memory-tool-compatible `/memories` file surface backed by Heartwood |
| `health` | Readiness, warmed tenants, model names, and key-custody mode |

## Smoke Test

```powershell
python tests/test_mcp_hardening.py
```

The test verifies:

- confidential memories are invisible without required roles;
- successful recall includes provenance validity and source IDs;
- MCP responses do not expose denied-count side channels;
- `forget()` purges the governed memory path;
- `/memories` path traversal remains confined.

## Use With A Derived Store

Point `HEARTWOOD_DB_PATH` at the same SQLite database used by the warm recall
service:

```powershell
$env:HEARTWOOD_DB_PATH = ".\heartwood.db"
$env:HEARTWOOD_TENANT = "tenant:ops"
python -m heartwood.adapters.mcp_server
```

Keep Heartwood embedded and local for Phase 1. Do not expose the MCP server over
a remote transport until the deployment has explicit auth, network isolation,
and key custody configured.
