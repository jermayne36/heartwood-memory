# Heartwood Agent Plugin maintainer note

## What changed

`plugins/agent-plugin` provides an evaluation package in the Agent Plugins 1.0
format: a manifest, one `heartwood-recall` skill, a local stdio MCP configuration,
installation guidance, and staged awesome-copilot submission text.

The configuration runs the published `heartwood-memory==0.2.10` package through
`uvx`. Its startup expression creates a per-user evaluation directory before
starting the server. The exposed tools are `recall`, `explain_recall`, and
`health`. The skill cites returned evidence and proposes memory updates for a
separately managed write workflow.

## How to test

From the repository root, run:

```bash
python3.11 -m ruff check .
python3.11 -m build --wheel --sdist --outdir /tmp/heartwood-plugin-dist
python3.11 -m pytest -q
```

Follow the [plugin README](../../plugins/agent-plugin/README.md) to seed a new
synthetic evaluation store before enabling the plugin. Check that the client
discovers exactly the three tools above. Call `health`, recall the synthetic
Juniper decision, and use its returned recall ID with `explain_recall`.

## Known limits

- A local macOS VS Code check discovered three MCP tools. A separate stdio MCP
  session exercised the configured server's health, recall, and explanation.
- Model-driven Copilot chat and skill invocation, Copilot CLI, the Copilot app,
  Windows, concurrent clients, and enterprise rollout remain unverified.
- Read-only describes the exposed memory operations. Server startup and recall
  can create database and key files and write audit records and recall traces.
  The process uses the local user's permissions.
- The package version is pinned; its transitive dependencies resolve at launch.
- The per-user evaluation store persists separately from plugin installation.
- The awesome-copilot submission is staged, not sent. Before submission, replace
  every staged source pin with the same full squash-merged commit SHA and obtain
  maintainer approval. Merge this change by squash to publish only the final tree.
