# Continuity capability contracts and rotation receipts

`heartwood.continuity` defines the dependency-free core types for capability
contracts and signed rotation receipts. A receipt is a measured diff over a
customer-supplied eval run. Model invocation, provider adapters, eval execution,
and catalog-change automation are outside this module.

## Storage boundary

`Continuity.store_capability_contract()` stores the canonical contract as a
provenance-signed Heartwood memory with:

- `kind="capability-contract"`
- `policy_scope="continuity-privileged"`
- `classification="confidential"`
- the `continuity-admin` role gate
- `indexed=0`

The contract is not added to the vector index or warm plaintext cache. Hybrid,
lexical, typed, default, warm, and MCP recall all retain the `indexed` gate.
`Heartwood.set_indexed()` refuses to move a capability contract into ordinary
recall, and `Heartwood.read_content()` does not expose it. Retrieval is through
`Continuity.get_capability_contract()` with a same-tenant
`continuity-admin` principal.

## Closed schemas

Every object and nested object rejects unknown fields. Identifiers use opaque
prefixed tokens, numeric deltas are finite and bounded to `[-1.0, 1.0]`, enum
fields are closed, summary counts must reconcile with the cases, and fixed
secret sentinels are rejected before storage or signing.

The receipt has no fields for prompts, memory content, model output, evidence
text, raw errors, environments, commands, credentials, or callable
representations. Failures use fixed `ErrorCategory` values. A fallback marked
as exercised must contain its observed trigger, target route, outcome, and any
required sanitized error category; an unobserved fallback is rejected.

## Receipt binding and audit event

A signed receipt binds:

- both route ids and both capability-contract hashes/schema versions;
- the eval-suite id, hash, and version;
- the run id;
- the prior signed baseline receipt id and hash;
- every opaque case id, enum outcome, bounded delta, and observed fallback;
- the machine-readable `production` or `prototype` evidence mode;
- the exact Heartwood audit sequence.

The general audit event contains only the receipt id as its target plus
`receipt_hash` and the minimal evidence-mode status. The rich receipt body is
returned to the caller and is not copied into the audit log or recall corpus.

## Canonical signing and verification root

Receipt signing version
`heartwood.continuity.rotation-receipt.v1` uses canonical sorted JSON and an
explicit domain separator. The existing `Signer` signs the canonical receipt
body; the existing `AuditLog` binds it to the exact audit sequence.

Verification assumes the principal's registered public key in Heartwood's
verification-key registry is trusted. That registry is in the mutable
Heartwood store. Deployments requiring a stronger boundary must pin or custody
the verification root outside that store. Durable cross-process signing also
requires Heartwood's durable key custodian; this module does not create a
parallel key system.

## Core-only boundary

The package imports no provider SDK and has no model-route callable protocol.
The separate customer-side runner is responsible for executing eval cases,
converting failures to fixed categories, and passing only validated fields into
this core.
