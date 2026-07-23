# VS Code + GitHub Copilot MCP integration

Heartwood can run as a local stdio MCP server for VS Code agent chat. The
workspace configuration is appropriate for a synthetic evaluation or an
administrator-approved local deployment; it does not prove that a constrained
enterprise organization permits MCP or agent mode.

Current VS Code documentation:

- [Add and manage MCP servers](https://code.visualstudio.com/docs/agent-customization/mcp-servers)
- [MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)

## Prerequisites

1. VS Code with agent chat/GitHub Copilot available and signed in.
2. Python 3.11 with `heartwood-memory[recall,mcp]` installed, or this source
   checkout on `PYTHONPATH`.
3. An isolated Heartwood database. For the model-rotation scenario, generate it
   with [`examples/rotation-continuity/run_demo.py`](../../examples/rotation-continuity/README.md).

No new credential belongs in `mcp.json`. VS Code input variables prompt for the
interpreter and database paths without checking machine-specific values into
source control.

## Workspace configuration

This repository includes [`.vscode/mcp.json`](../../.vscode/mcp.json). For the
rotation demo it starts:

```text
<selected-python> ${workspaceFolder}/examples/rotation-continuity/mcp_server.py
```

with:

- `PYTHONPATH=${workspaceFolder}`;
- the selected isolated `HEARTWOOD_DB_PATH`;
- tenant `tenant:rotation-continuity-demo`;
- `HEARTWOOD_MCP_ALLOWED_TOOLS=recall,explain_recall,health`.

The explicit allowlist is read-only. Writes happen in the reproducible demo
script, not from the IDE agent. The wrapper injects the same deterministic
offline embedder/reranker used to create this tiny store, then calls the standard
`heartwood.adapters.mcp_server.build_server` adapter. For a normal store, use
the generic `python -m heartwood.adapters.mcp_server` configuration from the
[MCP quickstart](mcp-quickstart.md) and keep the import/serve model environment
identical.

The MCP allowlist limits exposed Heartwood operations; it is not a process
sandbox. This checked-in configuration does not enable VS Code's MCP sandbox,
so the Python server inherits the operator account's process permissions. Use
only a reviewed checkout and synthetic data unless an administrator adds and
validates filesystem and network restrictions.

## Start and inspect

1. Open this repository as the VS Code workspace.
2. Run **MCP: List Servers** from the Command Palette.
3. Select `heartwood-rotation-demo` and review its command and environment names.
4. Start the server through **MCP: List Servers** and review the first-start
   trust prompt. Current VS Code documentation warns that starting directly
   from `mcp.json` may skip that prompt.
5. In agent chat, select **Configure Tools** and confirm only Heartwood
   `recall`, `explain_recall`, and `health` are present.
6. Ask the agent to recall the Project Juniper release decision and explain the
   returned recall ID.

VS Code stores enable/disable state separately from the shared workspace file
and provides a separate trust reset. An organization can centrally restrict MCP
access; validate both organization policy and the actual first-start path in the
design-partner environment.

## Headless command receipt

Before the UI check, verify the same stdio server command and demo store:

```bash
python3.11 examples/rotation-continuity/check_vscode_mcp.py \
  --python "$(python3.11 -c 'import sys; print(sys.executable)')" \
  --db-path /absolute/path/to/heartwood-demo.db
```

PASS requires MCP initialization, the exact read-only tool set, `health.ok=true`,
and both governed Project Juniper records for the authorized demo principal.

## Fallback venue

If Copilot is unavailable or organization policy disables MCP, use the
deterministic stub route only until the live-route security gate in
`ADMIN-SECURITY.md` is cleared. A transcript demonstrates only the route
executions recorded in that run. Treat the checked-in VS Code file as
configuration evidence, not evidence of a successful deployment or
constrained-organization validation.
