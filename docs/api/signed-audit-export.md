# Signed audit export

See [Audit schema epochs](audit-schema-epochs.md) for the version-aware
display-binding rules shared by live and offline verification.

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
  --anchor-root-fingerprint sha256:... \
  --expected-latest-anchor-id anc_...
```

The JSON receipt prints `status: PASS` or a non-PASS state, the verified chain
range, number of anchors checked, and every anchor-root fingerprint observed.
A failure exits with status 2.

For independent signer authentication and rollback detection, exchange both the
root fingerprint and expected latest anchor ID through a separate trusted
channel and pass them explicitly as shown. The export receipt prints the latest
anchor ID for that exchange. Reading either value from the bundle itself does
not establish trust or freshness.

`PASS` requires both external values. If the root is omitted, the verifier can
still check internal bundle consistency using the manifest's claimed root, but
returns `UNTRUSTED_SELF_CONSISTENT` with `ok: false`. If the external root is
present but the expected latest anchor ID is omitted, it returns
`FRESHNESS_UNVERIFIED` with `ok: false`. Both states exit with status 2 and must
not be treated as auditor verification.

## Bundle contract (`heartwood.audit-bundle.v1`)

The gzip-compressed tar contains exactly three canonical files:

- `manifest.json` — schema, chain range, file hashes, signed-anchor sink head,
  root fingerprints, and export semantics.
- `audit.jsonl` — the complete hash chain from sequence 1 through the latest
  signed anchor.
- `anchors.jsonl` — signed out-of-database anchor and manifest-pin records.

Verification fails closed for missing, duplicate, extra, non-regular, oversized,
non-canonical, or checksum-mismatched members; discontinuous or altered audit
rows; malformed, reordered, or forged anchors; a chain/anchor mismatch; a root
outside the supplied trust set; or a latest anchor that differs from the
externally supplied checkpoint. It also rejects any audit rows after the latest
signed anchor, even when an attacker recomputes their hash chain and rewrites the
unsigned manifest receipts. A genuine older signed prefix is detectable only
when the auditor supplies the expected latest anchor ID out of band.

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
