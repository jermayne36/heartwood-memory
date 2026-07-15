# Markdown Import Quickstart

This is the Phase 1 B1 path for building a derived Heartwood store from a
Markdown memory corpus while keeping Markdown as the human-readable source of
truth.

## Command

Install Heartwood from PyPI:

```powershell
python -m pip install "heartwood-memory[recall,mcp]"
heartwood import-markdown `
  C:\path\to\workspace\memory `
  C:\path\to\workspace\team-memory `
  --db .\heartwood.db `
  --tenant-map-json '{"acme":"tenant:acme-payments","northwind":"tenant:northwind-retail"}' `
  --output .\heartwood-import-report.json
```

For deterministic local smoke tests without external embedding models:

```powershell
heartwood import-markdown .\memory .\team-memory --db .\heartwood.db --dev-models
```

The command writes imported memories through the shipped `Heartwood.remember()`
path, so records get the normal policy envelope, provenance signature,
source-span hashes, audit events, and tenant-scoped storage.

## Mapping

Explicit frontmatter wins. Caller-supplied maps are the fallback. If neither
exists, the importer uses the generic fallback tenant.

| Markdown signal | Heartwood field |
|---|---|
| `tenant:` / `tenant_id:` | tenant, normalized to `tenant:<slug>` |
| `--tenant-map-json` path token match | tenant inference supplied by the consuming repo |
| `feedback_*.md` | default `epistemic=user-stated` |
| `reference_*.md` | default `kind=source`, `epistemic=imported-source` |
| `project_*.md` | default `epistemic=observed-fact` |
| `--prefix-epistemic-map-json` | optional override for filename prefix conventions |
| filename contains `hypothesis` | `epistemic=hypothesis` |
| filename contains `inferred` or `belief` | `epistemic=inferred-belief` |
| no tenant match | `tenant:ops` or `--default-tenant` |

Supported frontmatter fields:

```yaml
---
tenant: northwind-retail
classification: confidential
pii: false
roles: [finance]
attrs: [region=us]
subject: northwind-retail:auth
subject_ids: [northwind-retail, auth]
kind: source
epistemic: imported-source
created_by: owner:operator
confidence: 0.95
salience: 0.8
entities: [northwind-retail, auth]
valid_from: 2026-06-01
---
```

If a filename or metadata contains secret-like hints such as `password`,
`secret`, `api_key`, `token`, or `credential`, the importer forces
`classification=restricted` and `pii=true`. Credentials should still be stored
as pointers to vault records, not as Markdown body content.

## Idempotency

Memory ids are stable for the tuple `(tenant, relative path, content hash)`.
Re-running the same import skips already-imported records and reports them under
`skipped`. Importing multiple roots preserves the root folder segment in source
URIs, so duplicate filenames in different roots do not collide.

## Freshness Checks

Use the import report, not the SQLite database file mtime, to decide whether a
Markdown-derived store is current. Active recall services can update WAL and
checkpoint timestamps without importing any new Markdown source.

Freshness tooling should gate on:

- `source_lag_count == 0`
- `source_coverage_count == source_count`
- expected `memory_row_count_delta` for that run (`0` for a no-op re-import,
  positive when new source files are imported)

The report also includes `memory_row_count_before`, `memory_row_count_after`,
and per-tenant row-count maps so operators can compare row-count deltas without
reading filesystem timestamps.
