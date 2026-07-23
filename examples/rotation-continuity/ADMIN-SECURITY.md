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

The read-only tool list limits MCP operations; it does not confine the server
process. Use a reviewed checkout and add validated VS Code or operating-system
process restrictions before non-synthetic use.

The configuration does not expose `remember`, `memory`, or `forget`. The
reproducible script seeds the synthetic store before the IDE connects.

## Data flow

1. The demo script writes synthetic Project Juniper facts and one restricted
   release policy into a dedicated local store.
2. Heartwood policy-filters recall before ranking.
3. After the initial synthetic route seeds the store, routes B and C receive
   only the policy-authorized recalled content recorded in the receipt.
4. Each recall appends to the local hash-chained audit log.
5. The script emits `explain_recall` and audit verification receipts locally.

Each provider route runs with a route-specific environment allowlist. Provider
credential values are excluded from prompts, command receipts, stored route
output, and transcripts.

The Ollama route does not launch a child process. It reads only an optional
`OLLAMA_HOST`, rejects non-loopback endpoints, and sends a closed schema to the
local structured-output API with no tools.

## Controls visible in the receipt

- one observed tenant and one observed agent principal across the displayed
  audit rows; the verifier also checks that displayed event metadata matches the
  hash-bound event body;
- stable memory and policy fingerprints across four swap checkpoints;
- restricted policy absence for a principal without `release-manager`;
- provenance signature validity and content-hash equality on every authorized
  result;
- `index_lag=0` for the two-record deterministic demo;
- final `verify_audit=true` and explicit `prev_hash` linkage.

## Honest boundaries

- Heartwood is managed-key; its local process decrypts authorized content to
  serve recall.
- The demo does not explicitly enable strict provenance enforcement. With
  `HEARTWOOD_STRICT_SIGNATURES` unset, Heartwood defaults to `OFF`, re-verifying
  and surfacing signature state; operators can opt into the `FILTER` or
  `ENFORCE` read-failure modes shipped in 0.2.4 via an operator-approved
  cutover. Strict mode authenticates the signed provenance payload and content
  hash, not authorization metadata.
- The current chain detects changes to the hash-bound event body or timestamp
  and detects a dropped interior row. Opt-in external anchoring and the
  `heartwood verify-audit` receipt CLI shipped in 0.2.4; this demo does not
  configure an anchor sink. Loss after the latest separately protected anchor
  remains outside detection.
- This demo is not evidence of E2EE, byte-level deletion, modification
  prevention, compliance certification, or approval under a constrained
  enterprise Copilot policy.
- A passing receipt demonstrates memory, policy, and audit continuity only
  across the route executions identified in that receipt. Stub routes
  demonstrate harness mechanics; the receipt does not establish equivalent
  model quality or a shipped capability-contract product.
- Current provenance signatures authenticate the content hash and selected
  provenance fields, not authorization metadata such as classification or
  roles. Direct database writers remain inside the residual threat boundary
  until the signed payload is versioned to cover those fields.
- The canonical machine-readable claim scope for this repository is anchored in
  [`docs/api/continuity.md`](../../docs/api/continuity.md): the claim is signed
  content/provenance authenticity. Recall exclusion, authorization integrity,
  tamper-proof RBAC or visibility, and resistance to a principal that can
  rewrite the database are explicitly not claimed.

## Enterprise rollout gates

Before using non-synthetic data, the customer administrator should pin the
package version, select key custody, restrict the store path, review the MCP
allowlist, decide which provider may receive each classification, evaluate the
opt-in strict provenance enforcement and external audit anchoring shipped in
0.2.4, and validate their organization-level Copilot/MCP policies. The local unconstrained setup is
not a substitute for that design-partner verification.
