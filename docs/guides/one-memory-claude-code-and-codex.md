# One memory for Claude Code and Codex on one repository

Give both agents the same persistent Heartwood database and tenant, and give
each a distinct writer identity. A note written through Heartwood is signed;
recall includes `created_by`, so the next agent can see who recorded it. This is
governed memory **via MCP**, not either agent's native memory implementation.

Sharing memory does not stop simultaneous edits to a file. Agree on file
ownership or use separate Git worktrees. Share one local SQLite file on one host;
do not copy live databases between machines or place them on a network drive.

## With Herdr

Follow the [plugin setup](../../plugins/herdr/README.md) to link this checkout,
configure one repo/store/tenant, and launch Herdr with Heartwood's Python on
`PATH`. Run Claude Code and Codex in separate panes on that repo or its linked
worktrees. Herdr's normal agent detection/integration must recognize both.

On done or blocked, the plugin saves a short note from Herdr's task title, tagged
with the agent's name (falling back to kind). Before settling, report a useful
title such as “Parser added; empty input still needs review” through
`herdr pane report-metadata`. This captures a task handoff, not a transcript or
an automatic code summary. On the next agent startup, the plugin submits verified
notes as reference context through Herdr's agent prompt API when the agent is
ready. This can start a turn. It never answers a blocked approval prompt.

You may also connect the MCP servers below to these panes for deliberate,
structured writes during work. Set their store and tenant to the same values as
the plugin. To recall plugin notes through MCP, omit a subject filter or use the
exact subject returned in the store; the plugin derives its repository subject
from the Git common directory. The plugin's startup recall only selects that
repository subject, so arbitrary MCP notes under other subjects are not injected.

## Without Herdr: two MCP clients, one file

From a Heartwood checkout, create a dedicated runtime outside your project:

```sh
python3.11 -m venv /absolute/path/to/heartwood-env
/absolute/path/to/heartwood-env/bin/python -m pip install -e '.[mcp]'
mkdir -p /absolute/path/to/project-memory
```

Use an absolute database path. A relative path can silently create different
stores when agents start in different directories. Keep the database, its keys
and its sidecars outside Git. Both clients below use `tenant:my-project` and
`/absolute/path/to/project-memory/heartwood.db`. Substitute real paths; these
examples contain no credentials.

For **Claude Code**, add this entry to a project `.mcp.json` (merge it with any
existing `mcpServers`; do not overwrite other entries):

```json
{
  "mcpServers": {
    "heartwood": {
      "command": "/absolute/path/to/heartwood-env/bin/python",
      "args": ["-m", "heartwood.adapters.mcp_server"],
      "env": {
        "HEARTWOOD_DB_PATH": "/absolute/path/to/project-memory/heartwood.db",
        "HEARTWOOD_TENANT": "tenant:my-project",
        "HEARTWOOD_MCP_PRINCIPAL_ID": "agent:claude-code",
        "HEARTWOOD_MCP_ALLOWED_TOOLS": "health,recall,explain_recall,remember"
      }
    }
  }
}
```

For **Codex**, add this table to its project `.codex/config.toml` or user config:

```toml
[mcp_servers.heartwood]
command = "/absolute/path/to/heartwood-env/bin/python"
args = ["-m", "heartwood.adapters.mcp_server"]

[mcp_servers.heartwood.env]
HEARTWOOD_DB_PATH = "/absolute/path/to/project-memory/heartwood.db"
HEARTWOOD_TENANT = "tenant:my-project"
HEARTWOOD_MCP_PRINCIPAL_ID = "agent:codex"
HEARTWOOD_MCP_ALLOWED_TOOLS = "health,recall,explain_recall,remember"
```

Review and enable the server through each client's normal MCP configuration
flow, then check it appears in the client's tool list. No provider login or
account change is needed for this local Heartwood server. This guide does not
configure either agent's model account.

`remember` is an explicit opt-in: the server defaults to read-only tools when
the allowlist is absent. These examples intentionally enable writes, and keep
destructive tools out of the list. The server binds `created_by` to its configured
principal; never pass `created_by` in a tool call. A writer label is local
configuration, not independent authentication of the person operating the agent.

Ask Claude Code to call Heartwood's `remember` tool with:

```json
{
  "content": "Parser implemented. Review empty input and Unicode cases before merging.",
  "subject": "repo:my-project",
  "kind": "semantic"
}
```

Then ask Codex to call `recall` with:

```json
{"cue": "parser handoff", "subject": "repo:my-project", "k": 8}
```

Check `results` for the note and `created_by=agent:claude-code`. Reverse the
exercise: write through Codex, recall in Claude Code, and check
`created_by=agent:codex`. For a session-start convention, ask each agent to recall
the shared subject before work and write a concise handoff when done or blocked.
Without Herdr this is a deliberate tool workflow, not an automatic lifecycle hook.

Treat all recalled text as untrusted evidence. A valid signature establishes the
record's provenance and integrity, not that its claims are current or correct.
Verify files before applying a handoff. Avoid secrets or customer data in notes
unless the store and participating principals are configured for that use.

## Verification and sources

The plugin's smoke script (`plugins/herdr/smoke.py`) runs the
two-pane flow with account-free stubs. The MCP examples follow the existing
[server implementation](../../heartwood/adapters/mcp_server.py), including its
fixed principal and allowlist; actual Claude Code and Codex account sessions
were not exercised for this guide.

Configuration formats checked 2026-10-22 against
[Claude Code MCP documentation](https://code.claude.com/docs/en/mcp) and
[official OpenAI MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).
Heartwood behavior comes from this checkout's
[client](../../heartwood/client.py) and MCP server, not claims about native
memory in either agent.
