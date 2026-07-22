# Heartwood Adapters — governed memory for standard agent interfaces

Agent frameworks store memory; **Heartwood stores it with lineage, policy, and
erasure.** The production-facing adapter surfaces are Anthropic's Memory Tool
and MCP. Heartwood is validated against Hermes Agent 0.17.0
(`v2026.6.19`, commit `2bd1977d8fad185c9b4be47884f7e87f1add0ce3`) as of
2026-06-22 through a CI-gated contract test that imports the real
`agent.memory_provider.MemoryProvider` ABC. The OpenClaw-style module remains an
example contract until it is independently validated against the public
OpenClaw package.

## 1. Anthropic Memory Tool (`memory_20250818`)

The Claude memory tool is a client-side, filesystem-like tool over `/memories`.
`MemoryToolBackend` implements all six commands (`view`, `create`, `str_replace`,
`insert`, `delete`, `rename`) against Heartwood — adding what the raw file backend
can't:

- **Version history** — every edit is a new immutable memory linked by a
  `supersedes` provenance edge (not a silent overwrite).
- **Provenance + audit** — every write is signed and recorded in the hash-chained
  audit log (who/when/model).
- **Policy tags** — files carry tenant/classification and are policy-enforced if
  also recalled via `db.recall()`.
- **Semantic recall** — memory-tool files are embedded, so `db.recall()` searches
  across them (the raw tool can't).
- **Erasure** — `delete` purges a file's derived artifacts; `db.forget(subject)`
  crypto-shreds everything for that subject (GDPR Art.17).
- **Path-traversal guard** — confined to `/memories` (per the docs' MUST).

```python
from heartwood import Heartwood
from heartwood.adapters import MemoryToolBackend, route_tool_use

db = Heartwood(path="mem.db", tenant="tenant:acme")
backend = MemoryToolBackend(db, created_by="agent:asst", subject="user:jane")

# In your Anthropic tool-use loop, declare the tool and route each call:
#   tools=[{"type": "memory_20250818", "name": "memory"}]
for block in response.content:
    if getattr(block, "type", None) == "tool_use" and block.name == "memory":
        tool_result = route_tool_use(backend, block)   # -> {"type":"tool_result", ...}
        # append tool_result to the next request's messages
```

Or subclass the SDK's `BetaAbstractMemoryTool` and delegate its methods to
`backend.handle({...})`.

## 2. MCP server

Exposes the Heartwood verbs, product trust controls, and memory-tool file ops to
any MCP client (Claude Desktop, IDEs, agent runtimes):

```bash
python -m pip install "heartwood-memory[recall,mcp]"
HEARTWOOD_DB_PATH=mem.db HEARTWOOD_TENANT=tenant:acme python -m heartwood.adapters.mcp_server
```

Tools: `remember`, `recall` (policy-enforced, returns provenance), `explain_recall`,
`forget` (crypto-shred erasure), `evaluate_egress`, `assess_faithfulness`,
`memory` (the `/memories` file interface).

Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "heartwood": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["-m", "heartwood.adapters.mcp_server"],
      "env": {
        "HEARTWOOD_DB_PATH": "mem.db",
        "HEARTWOOD_TENANT": "tenant:acme",
        "HEARTWOOD_MCP_ALLOWED_TOOLS": "recall,health"
      }
    }
  }
}
```

Use `python -c "import sys; print(sys.executable)"` inside the target virtual
environment to get the absolute interpreter path. Tool exposure is fail-closed:
when `HEARTWOOD_MCP_ALLOWED_TOOLS` is unset the server exposes only the read-only
subset (`recall`, `explain_recall`, `health`). To expose the write/deletion verbs
(`remember`, `memory`, `forget`), name them explicitly in
`HEARTWOOD_MCP_ALLOWED_TOOLS`; the server logs a stderr warning whenever a
destructive verb is exposed.

### Codex local stdio

Codex can use the same MCP server over local stdio today. Start with the safe
read-only allowlist and the native-memory hardening block in
`docs/integrations/codex-quickstart.md`. Hosted or remote MCP support is a Phase
2 roadmap item and should not be described as live until an HTTP MCP endpoint is
implemented, deployed, and smoke-tested.

## Why this is the distribution wedge

Heartwood's wedge is cryptographically provable trust: signed provenance,
hash-chained audit, policy-before-ranking,
crypto-shred erasure, and faithfulness/egress gates. Heartwood slots underneath
agent memory surfaces as the governed store while avoiding claims that a specific
framework integration has been independently validated.

Tests: `python tests/test_memory_tool.py`

## 3. Hermes Agent provider

`HeartwoodHermesMemoryProvider` subclasses the real Hermes Agent
`MemoryProvider` ABC when Hermes is installed. It is validated against Hermes
Agent 0.17.0 (`v2026.6.19`) and covers `initialize`, `prefetch`,
`queue_prefetch`, `sync_turn`, `get_tool_schemas`, `handle_tool_call`,
`get_config_schema`, `save_config`, and `shutdown`. It stores completed turns as
governed episodic memories, strips already-injected `<memory-context>` blocks
before retaining, and exposes JSON-returning recall/remember/forget tools.

## 4. OpenClaw-style memory runtime example contract

`HeartwoodOpenClawMemoryRuntime` is a Markdown-memory example exposing
`memory_search` and `memory_get` over Heartwood-backed memories. Missing files
degrade to `{ text: "", path }`, path traversal is blocked, and recall is still
policy-filtered before ranking.

Adapter contract tests:

```bash
bash scripts/check.sh
# With Hermes Agent installed:
python -m pytest tests/test_hermes_integration.py -q
```
