# Rotation demo: administrator security brief

## Decision summary

The demo runs Heartwood as a local stdio MCP server on the operator's machine.
It uses one explicitly selected SQLite file and exposes only `recall`,
`explain_recall`, and `health` to VS Code. No Heartwood-hosted service receives
the store or its contents.

## What an administrator approves

- the absolute Python interpreter;
- the checked-in `examples/rotation-continuity/mcp_server.py` wrapper, which
  injects the demo's offline models and delegates to the standard adapter;
- the absolute path to the isolated demo database;
- tenant `tenant:rotation-continuity-demo`;
- the read-only MCP allowlist `recall,explain_recall,health`;
- the VS Code workspace trust decision for this checked-in server definition.

The configuration does not expose `remember`, `memory`, or `forget`. The
reproducible script seeds the synthetic store before the IDE connects.

## Data flow

1. The demo script writes synthetic Project Juniper facts and one restricted
   release policy into a dedicated local store.
2. Heartwood policy-filters recall before ranking.
3. Only policy-authorized result content is sent to the selected model route.
4. Each recall appends to the local hash-chained audit log.
5. The script emits `explain_recall` and audit verification receipts locally.

Provider CLIs use their existing local authentication. Heartwood does not read,
copy, print, or persist provider credentials.

## Controls visible in the receipt

- one tenant and one agent principal across the whole audit chain;
- stable memory and policy fingerprints across four swap checkpoints;
- restricted policy absence for a principal without `release-manager`;
- provenance signature validity and content-hash equality on every authorized
  result;
- `index_lag=0` for the two-record deterministic demo;
- final `verify_audit=true` and explicit `prev_hash` linkage.

## Honest boundaries

- Heartwood is managed-key; its local process decrypts authorized content to
  serve recall.
- Signature validity is re-verified and surfaced, not yet a hard read-enforcement
  mode.
- The hash chain detects edits or dropped retained rows. Tail truncation or
  rollback requires the planned external anchor.
- This demo is not evidence of E2EE, byte-level deletion, tamper-proof storage,
  a compliance certification, or constrained-enterprise Copilot approval.
- It proves memory/policy/audit continuity across routes, not equivalent model
  quality or a shipped capability-contract product.

## Enterprise rollout gates

Before using non-synthetic data, the customer administrator should pin the
package version, select key custody, restrict the store path, review the MCP
allowlist, decide which provider may receive each classification, and validate
their organization-level Copilot/MCP policies. The local unconstrained setup is
not a substitute for that design-partner verification.
