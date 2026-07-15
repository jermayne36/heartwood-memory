# Public API Ergonomics Quickstart

This is the Phase 1 B3 path for tenant-aware bulk writes and per-tenant recall
without hand-constructing low-level `Policy` and `Principal` objects at every
call site.

Install the productized recall/MCP extras before using the CLI or local service
paths from this guide:

```powershell
python -m pip install "heartwood-memory[recall,mcp]"
```

## Python API

```python
from heartwood import Heartwood

db = Heartwood(path="heartwood.db", tenant="tenant:ops")

report = db.remember_many(
    [
        {
            "tenant": "acme-payments",
            "subject": "acme-payments:audit",
            "content": "Acme Payments reviews must preserve audit details and source spans.",
            "created_by": "owner:operator",
            "classification": "internal",
            "source_uri": "doc://acme-payments/audit-guidance",
        },
        {
            "tenant": "northwind-retail",
            "subject": "northwind-retail:auth",
            "content": "Northwind Retail auth incidents require finance review.",
            "classification": "confidential",
            "roles": ["finance"],
            "source": {"kind": "fixture", "uri": "doc://northwind-retail/auth-review"},
        },
    ],
    default_created_by="agent:bulk",
)

out = db.recall_for_tenant(
    "northwind-retail",
    "who reviews auth incidents?",
    principal_id="agent:orchestrator",
    roles=["finance"],
    clearance="confidential",
    k=5,
)
```

`remember_many()` routes each record to the normalized tenant
(`acme-payments` becomes `tenant:acme-payments`) and still writes through
`Heartwood.remember()`. The result: normal provenance signatures,
source-span hashes, encrypted content, deletion-lineage registration, audit
rows, and index updates.

## Convenience Helpers

```python
from heartwood import normalize_tenant, policy_from, principal_from

tenant = normalize_tenant("acme-payments")  # tenant:acme-payments
policy = policy_from({"classification": "confidential", "roles": "finance"})
principal = principal_from("agent:orchestrator", tenant="northwind-retail", clearance="confidential")
```

Use `db.with_tenant("northwind-retail")` when a caller wants an explicit
tenant-scoped client over the same SQLite store and already-warm model callables.

## JSONL Bulk Import

Create `records.jsonl`:

```jsonl
{"tenant":"acme-payments","subject":"acme-payments:audit","content":"Acme Payments reviews preserve audit details.","classification":"internal","source_uri":"doc://acme-payments/audit"}
{"tenant":"northwind-retail","subject":"northwind-retail:auth","content":"Northwind Retail auth changes require finance review.","classification":"confidential","roles":["finance"],"source_uri":"doc://northwind-retail/auth"}
```

Import it:

```powershell
heartwood bulk-remember `
  --input .\records.jsonl `
  --db .\heartwood.db `
  --tenant tenant:ops `
  --created-by agent:bulk `
  --output .\heartwood-bulk-report.json
```

The command accepts either JSONL objects or a JSON list/object with `records[]`.
The report includes `tenant_counts`, per-record IDs, source coverage, and any
record-level errors. Add `--stop-on-error` for transactional-style local
debugging where the first malformed record should fail the command.

## Supported Record Fields

| Field | Notes |
|---|---|
| `tenant` / `tenant_id` | Normalized to `tenant:<slug>` when no namespace is supplied |
| `content` / `text` / `body` | Required |
| `subject` / `subject_id` | Required erasure and lineage unit |
| `created_by` / `producer` / `actor` | Producer principal signed into provenance |
| `kind` / `memory_type` | Defaults to `semantic` |
| `epistemic` / `epistemic_class` | Defaults to `user-stated` |
| `classification`, `pii`, `roles`, `attrs`, `visibility`, `retention`, `role_groups` | Policy fields; top-level fields override nested `policy` |
| `source`, `source_uri`, `source_id`, `source_ids`, `source_spans` | Source metadata. If a source ID exists and no span is supplied, the API creates a source span covering the record body. |
| `derived_from`, `entities`, `subject_ids`, `valid_from`, `valid_until`, `policy_scope`, `truth_status`, `model_version` | Passed through to the product memory envelope |

## B3 Exit Check

Run:

```powershell
python tests/test_bulk_api.py
```

The test verifies tenant routing, role/clearance enforcement, source-span
coverage, read-time provenance verification after CLI import, and the ergonomic
helpers.
