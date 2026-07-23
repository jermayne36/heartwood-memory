# Rotation-continuity demo

This five-minute demo keeps one agent on one isolated Heartwood store while its
model backend changes from a GPT-class route to a Claude-class route and then a
local open-weights route.

It proves the capability Heartwood ships today: the same governed memories,
policy decision, policy-filtered result sets, `explain_recall` semantics,
provenance checks, and hash-chained audit survive the route swaps. It does **not**
claim that model prose is identical, that every model has equivalent capability,
or that Heartwood already ships a model capability-contract/rotation-evaluation
product.

## What runs

| Route | Default executable | Default model | Fallback |
|---|---|---|---|
| A — GPT class | `codex` | `gpt-5.6-sol` | disclosed deterministic stub |
| B — Claude class | `claude` | `sonnet` | disclosed deterministic stub |
| C — open weights | `ollama` | local Qwen GGUF named by `--open-weights-model` | disclosed deterministic stub |

The provider CLIs receive only the synthetic Project Juniper scenario and
policy-authorized recall context. They receive no Heartwood database access and
no tools. Existing CLI authentication is reused; the demo neither creates nor
stores credentials and never signs up for a provider.

## Run it

From the repository root, use Python 3.11 with the project development
dependencies installed:

```bash
demo_dir="$(mktemp -d)"
python3.11 examples/rotation-continuity/run_demo.py \
  --route-mode auto \
  --require-live 2 \
  --output-dir "$demo_dir"
```

`auto` attempts all three routes. An unavailable route is marked `stub`, with the
reason in `session.json` and `transcript.md`; the command still fails unless at
least `--require-live` routes ran live. Use `--route-mode live --require-live 3`
for a strict three-provider run. Use `--route-mode stub --require-live 0` only
for an offline mechanics check.

The output directory contains:

- `heartwood-demo.db` — the dedicated throwaway store;
- `receipts/*.json` — `explain_recall` receipts before and after both swaps;
- `session.json` — route execution and continuity assertions;
- `audit-chain.json` — every audit event and final chain verification;
- `transcript.md` — the five-minute talk track and receipts.

The script refuses to reuse a non-empty output directory, so it cannot silently
mix sessions or touch another Heartwood store.

## VS Code + GitHub Copilot venue

The checked-in [`.vscode/mcp.json`](../../.vscode/mcp.json) defines a local stdio
Heartwood server with a fail-closed read-only allowlist. Its small demo wrapper
injects the same offline deterministic models used to build the throwaway index,
then delegates tool registration and serving to Heartwood's standard MCP
adapter. VS Code prompts for:

1. the absolute Python 3.11 executable that imports this checkout; and
2. the absolute `heartwood-demo.db` path printed by the demo.

Start the server from **MCP: List Servers**, review the command, and approve the
workspace server trust prompt. Then enable the Heartwood `recall`,
`explain_recall`, and `health` tools in agent chat. See the
[VS Code + Copilot guide](../../docs/integrations/vscode-copilot.md).

Before opening VS Code, exercise the exact stdio command and read-only tool set:

```bash
python3.11 examples/rotation-continuity/check_vscode_mcp.py \
  --python "$(python3.11 -c 'import sys; print(sys.executable)')" \
  --db-path "$demo_dir/heartwood-demo.db" \
  --output "$demo_dir/vscode-mcp-receipt.json"
```

This headless receipt verifies the server command, initialization, listed tools,
health, and recall against the same demo store. VS Code/Copilot UI discovery and
first-run trust still require the local UI and a signed-in Copilot installation.

## Re-run receipt

Create a second empty directory and repeat the same command:

```bash
second_demo_dir="$(mktemp -d)"
python3.11 examples/rotation-continuity/run_demo.py \
  --route-mode auto \
  --require-live 2 \
  --output-dir "$second_demo_dir"
```

The generated recall IDs and audit hashes are intentionally new. The stable
continuity fingerprint must remain identical across all four checkpoints within
each run.

## Security boundary

Read [ADMIN-SECURITY.md](ADMIN-SECURITY.md) before using the demo with a customer.
Use synthetic data only. Heartwood is managed-key and decrypts in the local
server to serve recall. Signed provenance is re-verified and surfaced rather
than enforced as a hard read failure today. The audit chain detects edits or
dropped retained rows; tail truncation still needs an external anchor.
