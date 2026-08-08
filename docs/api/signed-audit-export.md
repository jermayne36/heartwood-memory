# Signed audit export

Heartwood can hand an auditor a portable copy of the store-global audit chain
that verifies without access to the source database, anchor service, or network.
Only the installed `heartwood-memory` wheel and the bundle are required.

## Export and verify

Configure the database, local anchor path, and externally pinned anchor root
used by the running Heartwood instance, then export:

```bash
export HEARTWOOD_DB_PATH=/path/to/heartwood.db
export HEARTWOOD_ANCHOR_PATH=/separate/failure-domain/anchors.jsonl
export HEARTWOOD_ANCHOR_ROOT_FINGERPRINT=sha256:...
heartwood export-audit --out bundle.tar.gz
```

The exporter is read-only. It opens SQLite in `mode=ro`, never creates an
anchor, and never changes the database, anchor sink, retention state, erasure
state, or any metadata marker. If rows exist beyond the latest signed anchor,
the bundle ends at that anchor and reports `excluded_unanchored_rows` rather
than presenting the unsigned tail as protected.

An auditor verifies offline with the published wheel:

```bash
python -m pip install heartwood-memory
heartwood verify-audit-bundle bundle.tar.gz \
  --anchor-root-fingerprint sha256:...
```

The JSON receipt prints `status: PASS` or `status: FAIL`, the verified chain
range, number of anchors checked, and every anchor-root fingerprint observed.
A failure exits with status 2.

For independent signer authentication, exchange the root fingerprint through a
separate trusted channel and pass it explicitly as shown. If it is omitted, the
verifier can still check bundle self-consistency using the fingerprint recorded
in the manifest, but reports `trust_source: bundle_manifest`; that mode does not
protect against wholesale replacement of both the bundle and its claimed root.

## Bundle contract (`heartwood.audit-bundle.v1`)

The gzip-compressed tar contains exactly three canonical files:

- `manifest.json` — schema, chain range, file hashes, signed-anchor sink head,
  root fingerprints, and export semantics.
- `audit.jsonl` — the complete hash chain from sequence 1 through the latest
  signed anchor.
- `anchors.jsonl` — signed out-of-database anchor and manifest-pin records.

Verification fails closed for missing, duplicate, extra, non-regular, oversized,
non-canonical, or checksum-mismatched members; discontinuous or altered audit
rows; malformed, reordered, forged, or rolled-back anchors; a chain/anchor
mismatch; or a root outside the supplied trust set.

## Erasure and privacy semantics

Crypto-shred erasure destroys the subject key and purges memory/derived data,
while its minimal audit event remains in the append-only chain. The export
copies that audit chain, so a range containing events before and after an
erasure remains verifiable without restoring the destroyed key or content.

The bundle excludes memory plaintext, ciphertext, encryption keys, embeddings,
and indexes. Audit bodies can still contain operational identifiers, actor IDs,
targets, reasons, and other customer-controlled detail. Treat the bundle as
sensitive compliance evidence and apply the recipient, storage, access, and
retention policy appropriate to that audit metadata.

The bundle itself is an immutable snapshot. Heartwood does not delete or expire
bundles after export; operators own their lifecycle. Future WORM retention and
SIEM streaming can store or transmit these exact bytes, preserving this
verification contract rather than inventing a second audit representation.
