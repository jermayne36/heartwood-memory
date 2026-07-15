# Postgres And SQLite Migration Guide

Heartwood Phase 1 is a derived memory layer beside existing systems of record.
Do not migrate source-of-truth data into Heartwood. Instead, project source rows
or files into governed memories that can be rebuilt.

## SQLite-First Path

Use SQLite when Heartwood runs embedded with an agent or local hook:

```powershell
python -m pip install "heartwood-memory[recall,mcp]"
heartwood import-markdown .\memory .\team-memory --db .\heartwood.db
heartwood serve-recall --db .\heartwood.db --tenant tenant:ops
```

Recommended pattern:

1. Keep Markdown, app SQLite, Postgres, or files as source of truth.
2. Import into Heartwood with stable `memory_id` and `source_uri`.
3. Treat vector/BM25 indexes as rebuildable.
4. Use `forget(subject)` for erasure; rebuild from source when needed.

## Postgres Projection Path

For teams already on Postgres:

1. Select rows that should be visible to agents.
2. Emit JSONL records with:
   - `tenant`
   - `subject`
   - `content`
   - `classification`
   - `roles` / `attrs`
   - `source_uri` like `postgres://schema/table/pk`
   - `source_ids`
   - `source_spans`
3. Import with:

```powershell
heartwood bulk-remember `
  --input .\postgres-projection.jsonl `
  --db .\heartwood.db `
  --tenant tenant:ops
```

## Example JSONL Record

```json
{
  "tenant": "acme",
  "subject": "customer:42",
  "content": "Customer 42 prefers email updates for support cases.",
  "classification": "internal",
  "roles": ["support"],
  "source_uri": "postgres://crm/customer_preferences/42",
  "source_spans": [
    {
      "source_id": "postgres://crm/customer_preferences/42",
      "span_id": "postgres://crm/customer_preferences/42#preference",
      "text": "Customer 42 prefers email updates for support cases."
    }
  ]
}
```

## Cutover Guidance

| Current State | Recommended Heartwood Path |
|---|---|
| Local Markdown memory | `import-markdown` |
| SQLite app tables | Export JSONL, then `bulk-remember` |
| Postgres app tables | Export JSONL or build a projection job, then `bulk-remember` |
| Existing vector DB | Rebuild Heartwood from original source rows, not from vector payloads |

## Things Not In Phase 1

- Production Postgres CDC import is deferred until a partner pulls it.
- Heartwood does not replace transactional app tables.
- The Postgres adapter smoke gate is evidence that database integration is
  possible; Phase 1 adoption should still use derived stores unless CDC is
  explicitly needed.
