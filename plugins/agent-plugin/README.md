# Heartwood Agent Plugin

A thin, evaluation-only [Agent Plugins 1.0](https://agent-plugins.org/) package for
GitHub Copilot in VS Code, Copilot CLI, and the GitHub Copilot app. It bundles one
recall skill and a local stdio MCP configuration. Client support for each
component varies; see the verification record below.

## Install for one developer

Prerequisites: a compatible Copilot client, Python 3.11 or newer, and
[`uv`](https://docs.astral.sh/uv/getting-started/installation/) with `uvx` on the
client's executable search path. The first launch downloads Heartwood 0.2.10
from PyPI and its dependencies. Heartwood may also download its pinned retrieval
models; keep the same model environment when importing and recalling a store.
No hosted Heartwood account or API key is needed.

1. Clone the public repository and inspect `plugin.json`, `mcp.json`, and
   `skills/heartwood-recall/SKILL.md` in this folder. For the synthetic walkthrough,
   seed the evaluation store as described below **before first enabling** the plugin.
2. In VS Code, add this entry to your **user** `settings.json`, substituting the
   absolute path to your clone:

   ```json
   {
     "chat.plugins.enabled": true,
     "chat.pluginLocations": {
       "/absolute/path/to/heartwood-memory/plugins/agent-plugin": true
     }
   }
   ```

   `chat.pluginLocations` is Experimental. On Windows use a JSON path such as
   `"C:/src/heartwood-memory/plugins/agent-plugin"`. Restart the client if it
   does not discover the plugin. In **Chat: Open Customizations**, check Plugins
   and Skills; in **MCP: List Servers**, inspect the Heartwood server. Plugins
   implicitly trust their bundled MCP server, so review the files first.
3. In Copilot CLI, the corresponding local installation is:

   ```text
   /plugin install /absolute/path/to/heartwood-memory/plugins/agent-plugin
   ```

   Use the client's plugin manager to inspect the installed plugin and its MCP
   tools. The Copilot app supports the same portable package through its plugin
   manager. CLI and app behavior has not been verified on this Mac.
4. Verify that the Heartwood tool list is exactly `recall`, `explain_recall`, and
   `health`. Invoke the `heartwood-recall` skill for a task involving earlier
   decisions. Ask for the memory IDs, sources, and recall ID used in the answer.

Local installation works without a marketplace listing. If Heartwood is listed
in awesome-copilot, `/plugin install heartwood@awesome-copilot` installs the same
package.

## Local store and evaluation

`mcp.json` uses a small standard-library startup expression: it creates
`~/.heartwood/agent-plugin`, changes the process working directory there, and
calls the published `heartwood.adapters.mcp_server.main` entry point. The database
is `~/.heartwood/agent-plugin/heartwood.db` (on Windows, under the user's home
folder). This avoids relying on `${PLUGIN_DATA}` expansion, which failed in the
installed VS Code 1.138.0 client. The configured tenant is `tenant:agent-plugin`
and the principal is `agent:copilot` with internal clearance and no roles or
attributes. The store is shared by this user's compatible clients, not by all
developers.
It is not a company-wide shared memory service. A fresh store is
empty; empty recall is expected until an operator explicitly imports records.

To evaluate with one synthetic record, run this before the first server start,
with an **absolute** path to `~/.heartwood/agent-plugin/heartwood.db`. This is an explicit operator write outside the plugin;
use a new evaluation store, never an existing customer database.

```bash
uvx --from heartwood-memory==0.2.10 python - /absolute/home/.heartwood/agent-plugin/heartwood.db <<'PY'
import sys
from pathlib import Path
from heartwood import Heartwood

path = Path(sys.argv[1])
if path.exists():
    raise SystemExit("Use a new evaluation store; this example will not modify an existing one.")
path.parent.mkdir(parents=True, exist_ok=True)
db = Heartwood(path=path, tenant="tenant:agent-plugin")
try:
    result = db.remember(
        "Project Juniper uses a blue release badge. This is a synthetic evaluation decision.",
        subject="project:juniper", created_by="agent:copilot",
        source={"uri": "demo://juniper/release-decision"},
    )
    print(result)
finally:
    db.close()
PY
```

Start the server, call `health`, then `recall` with
`{"cue":"Project Juniper release badge", "subject":"project:juniper", "k":5}`.
The result should contain the synthetic decision with provenance. Use
`explain_recall` with the returned recall ID. Keep the database and its generated
key material private and together; do not commit them. Plugin uninstall leaves this directory
intact; manage its lifecycle separately and back up needed data before removing it.

## Company administration

After the plugin is approved and listed in awesome-copilot, merge this fragment
into your enterprise's `managed-settings.json` using GitHub's managed-settings
rollout process:

```json
{
  "enabledPlugins": {
    "heartwood@awesome-copilot": true
  },
  "allowedMcpServers": [
    {
      "serverCommand": [
        "uvx", "--from", "heartwood-memory==0.2.10", "python", "-c",
        "from pathlib import Path; import os; from heartwood.adapters.mcp_server import main; p=Path.home()/'.heartwood'/'agent-plugin'; p.mkdir(parents=True, exist_ok=True); os.chdir(p); main()"
      ]
    }
  ]
}
```

This is a staged example, not an active enterprise rollout. Preserve the
enterprise's other approved servers: setting `allowedMcpServers` blocks servers
that do not match any entry; multiple sources intersect and deny rules win.
The matcher compares the command and each argument exactly. If a managed client
resolves `uvx` to an absolute executable or needs a Windows command wrapper,
approve that exact resolved command after inspecting the client logs.

`enabledPlugins` requires an available marketplace entry; it does not publish
this plugin. Before public listing, administrators can place the reviewed plugin
in their own approved marketplace and use its qualified plugin identity instead.
Provision Python/uv and a suitable executable search path separately. This
package does not provision infrastructure or distribute a shared database.

The command allowlist approves a process, not individual tools or environment
values. Keep the reviewed MCP configuration and least-privilege store
permissions: the explicit Heartwood tool allowlist is what restricts the exposed
tools. The server inherits the local process's permissions; this plugin is not
a process sandbox or a security certification.

## What it can and cannot do

- Recall permitted records, explain those recalls, and report server health.
- Guide the agent to recall before acting and cite returned evidence. A skill
  loads on demand; this is guidance, not an enforced pre-action hook.
- Propose a memory update for user approval. It cannot execute that update:
  `remember`, `memory`, `forget`, `evaluate_egress`, and `assess_faithfulness` are
  absent. Use a separately approved operator write workflow if needed.
- Read-only refers to the exposed memory operations. Server initialization and
  recall can create local database/key files and write audit/recall records.
- No hosted connection, automatic ingestion, background
  capture, hooks, deployment provisioning, or automatic account setup is bundled.
- The repository and package are source-available under
  [BUSL-1.1](../../LICENSE), not OSI open source. Review the license before use.

## Verification and sources

The handback in [`docs/handoff/HANDBACK-HW-AGENT-PLUGIN.md`](../../docs/handoff/HANDBACK-HW-AGENT-PLUGIN.md)
records actual client coverage and fresh schema/MCP/test evidence. Unverified
clients are not implied by the portable format.

- [Agent Plugins 1.0 specification](https://github.com/agentplugins/agent-plugins-spec/blob/main/spec/1.0.0.md)
- [VS Code plugin installation](https://code.visualstudio.com/docs/agent-customization/agent-plugins)
- [VS Code authoring reference](https://code.visualstudio.com/docs/agents/reference/agent-plugin-reference)
- [Enterprise managed settings reference](https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings)
- [Awesome Copilot contribution workflow](https://github.com/github/awesome-copilot/blob/main/CONTRIBUTING.md)
