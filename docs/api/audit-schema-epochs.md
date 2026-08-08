# Audit schema epochs

Heartwood verifies one cryptographic chain across every audit schema epoch. It
never rewrites historical rows to fit the current schema.

Current rows use a canonical JSON body containing `tenant`, `principal`,
`action`, `target`, and `detail`. Verification checks both the predecessor/hash
chain and equality between those four body fields and their query/display
columns.

One 2026-07-01 classification migration wrote 31 contiguous rows before that
display-binding schema existed. Their bodies contain only the classification
transition (`from`, `to`, `operation`, `source_ids_json`, and `task_id`). The
body, timestamp, and predecessor were always hash-bound; the four display
columns were not present in the body.

The verifier handles that closed legacy epoch with explicit compatibility
commitments in `heartwood/audit_epochs.py`. Each accepted row is pinned by:

- store chain ID;
- exact audit sequence;
- exact chained row hash;
- exact legacy body-key set and operation; and
- a SHA-256 commitment to the canonical display-column object.

Any different chain, sequence, row hash, body shape, or display value fails
verification. No wildcard legacy exception exists, and no database row is
changed. Audit bundles use the same verifier, so offline verification has the
same epoch semantics as `verify_audit()`.

This compatibility commitment preserves the claim the historical format can
actually support: the original bytes remain intact and the previously unbound
display projection is now pinned without pretending it was part of the old row
hash. New rows continue to require direct body/display equality.
