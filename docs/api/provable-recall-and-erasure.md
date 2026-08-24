# Provable recall and erasure receipts

Heartwood can emit portable, signed receipts when the instance has both durable
signing custody and an audit anchor sink. Receipt verification is offline: it
does not contact Heartwood or any network service. A buyer supplies the
verification-root fingerprint and latest anchor ID obtained through a separate
trusted channel.

If durable signing is unavailable, recall returns `receipt: null` with
`receipt_unavailable_reason: "no_durable_signing_root"`. Hard erasure returns
`receipt: null`, `proof_status: "UNAVAILABLE"`, and a sanitized reason. Heartwood
never emits a receipt-shaped unsigned object.

## Wire contracts

`heartwood.recall-receipt.v1` has this closed top-level key set:

`{schema, receipt_id, recall_id, tenant, principal_id, issued_at_utc, query_hash, chain_id, audit_seq, audit_row_hash, policy, results, principal_keys, signing, receipt_hash, signature}`

Each recall result binds the memory ID, content hash, epistemic class, producer,
source locator, source IDs, legacy v1 producer signature, producer-key
fingerprint, and the signature/content checks recomputed while serving. Inline
principal keys are attested by the deployment signature; they do not independently
prove historical key registration.

`heartwood.erasure-receipt.v1` has this closed top-level key set:

`{schema, receipt_id, tenant, subject_id, actor, issued_at_utc, erasure_initiated_at, key_shred_requested, purge_requested, custody_backend, custody_retention_floor_seconds, payload, key, purge, chain_id, audit_seq, audit_row_hash, boundary, signing, receipt_hash, signature}`

The signing block is closed and contains `signing_key_id`, positive
`signing_key_epoch`, `sink_id`, `signing_public_key`, and
`verification_root_fingerprint`. The external trust policy—not receipt time—must
decide which fingerprint and epoch are valid for a chain and sink.

Receipts use UTF-8 canonical JSON with sorted keys, compact separators, Unicode
preserved, and non-finite numbers rejected. `receipt_hash` commits to every field
except `audit_row_hash`, `receipt_hash`, and `signature`; the final Ed25519
signature commits to every field except `signature`. Recall and erasure use the
fixed domains `heartwood.recall-receipt.v1\0` and
`heartwood.erasure-receipt.v1\0` respectively.

Producer signatures preserve the existing v1 bytes exactly:

`id|content_hash|str(source_uri)|created_by|epistemic`

Consequently, JSON null and the literal string `"None"` collide in v1 producer
payload bytes. A typed canonical producer payload requires a future version; v1
bytes cannot be changed compatibly.

## Offline commands

```bash
heartwood export-principal-keys --db ./heartwood.db --tenant tenant:acme

heartwood verify-recall-receipt \
  --receipt recall-receipt.json --results results.json \
  --audit-bundle audit-bundle.tar.gz \
  --anchor-root-fingerprint sha256:<externally-pinned-root> \
  --expected-latest-anchor-id anc_<externally-pinned-checkpoint>

heartwood verify-erasure \
  --receipt erasure-receipt.json --db ./heartwood.db \
  --audit-bundle audit-bundle.tar.gz \
  --anchor-root-fingerprint sha256:<externally-pinned-root> \
  --expected-latest-anchor-id anc_<externally-pinned-checkpoint>
```

The `heartwood` CLI exits 0 only for `PASS`, 2 for recognized non-PASS results,
and 1 for usage or unexpected input failures. The shell-oriented module command
`python -m heartwood.receipts verify <receipt.json>` exits 0 for `PASS` and 1
for every non-PASS result.

## Exact erasure boundary

This receipt and store check prove absence only for the exact tenant, `subject_id`, receipt-named memory IDs, provenance edges, and subject aliases actually represented by that identifier in the inspected SQLite copy at verification time. They do not prove semantic identification or deletion of the same person/data re-ingested under a different subject ID, an unknown alias, no subject tag, another database, a backup/snapshot, a cache, an export, a downstream system, or any later point in time.

The check also does not prove byte-level overwrite, physical destruction of an
external root, or legal/regulatory completion. `reason` and `legal_basis` make an
erasure receipt sensitive evidence; Heartwood excludes both from logs and audit
row details.

## Publication boundary

The verifier and receipts are public evaluation logic. Private experiment,
generator, benchmark-harness, deployment, and custody material is not part of
this interface and is not required to verify an artifact.
