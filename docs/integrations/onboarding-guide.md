# Phase 1 Onboarding Guide

This guide is the Phase 1 C3 adoption path: get Heartwood running as a local
governed memory layer beside an existing system of record.

## 1. Install

```powershell
python -m pip install "heartwood-memory[recall,mcp]"
heartwood --help
```

Use deterministic local models only for smoke tests:

```powershell
$env:HEARTWOOD_DEV_MODELS = "1"
```

## 2. Build The Derived Store

```powershell
New-Item -ItemType Directory -Force -Path .\.heartwood | Out-Null
icacls .\.heartwood /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
heartwood import-markdown `
  C:\path\to\workspace\memory `
  C:\path\to\workspace\team-memory `
  --db .\.heartwood\heartwood.db `
  --tenant-map-json '{"acme":"tenant:acme-payments","northwind":"tenant:northwind-retail"}' `
  --output .\heartwood-import-report.json
```

For JSON/JSONL handoff records:

```powershell
heartwood bulk-remember `
  --input .\records.jsonl `
  --db .\.heartwood\heartwood.db `
  --tenant tenant:ops `
  --output .\heartwood-bulk-report.json
```

## 3. Start Warm Recall

```powershell
$env:HEARTWOOD_RECALL_TOKEN = "replace-with-local-secret"
heartwood serve-recall `
  --db .\.heartwood\heartwood.db `
  --tenant tenant:ops `
  --warm-tenant tenant:ops `
  --warm-tenant tenant:acme-payments `
  --warm-tenant tenant:northwind-retail
```

Smoke recall:

```powershell
heartwood recall `
  --url http://127.0.0.1:8765 `
  --tenant tenant:acme-payments `
  --principal-id agent:orchestrator `
  --query "what memory applies to Acme Payments audit details?" `
  --k 5
```

## 4. Enable MCP

Copy `.mcp.json.example` to `.mcp.json` and set its interpreter path, or run:

```powershell
$env:HEARTWOOD_DB_PATH = ".\.heartwood\heartwood.db"
$env:HEARTWOOD_TENANT = "tenant:ops"
python -m heartwood.adapters.mcp_server
```

MCP is for governed writes and agent-facing memory tools. Warm recall remains
the low-latency local path. For long-lived MCP client configs, use the absolute
interpreter path from `python -c "import sys; print(sys.executable)"` instead of
bare `python`.

## 5. Configure Key Custody

For production-like local use, provide a vault-sourced root secret:

```powershell
$env:HEARTWOOD_KEY_CUSTODY_ROOT_B64 = "<32-byte-base64url-secret>"
$env:HEARTWOOD_KEY_CUSTODY_KEY_ID = "local-root-v1"
```

Rotate by writing new memories with a new key id, then rebuilding the derived
store from source Markdown/JSONL if necessary.

## 6. Acceptance Checklist

From a repository checkout, run:

```powershell
python tests/test_markdown_importer.py
python tests/test_warm_recall.py
python tests/test_bulk_api.py
python tests/test_mcp_hardening.py
python tests/test_key_custody.py
```

From a packaged install, the repo test paths are not present. Use command-level
smoke checks instead:

```powershell
heartwood --help
heartwood import-markdown .\memory --db .\.heartwood\heartwood.db --dev-models
heartwood serve-recall --db .\.heartwood\heartwood.db --tenant tenant:ops --dev-models
```

Before a consumer cutover, verify:

- top-3 recall beats the current keyword-scoring baseline on held-out prompts;
- p95 warm recall is under 500ms;
- no cross-tenant leakage;
- every recalled result has source IDs and valid provenance;
- `forget()` purges source-derived memories;
- at least one real agent flow runs in shadow mode for two weeks.

## 7. Shadow Mode

During shadow mode, run Heartwood recall beside the existing memory path and
log:

- query text;
- tenant;
- baseline output;
- Heartwood top-3 result IDs;
- p95 latency;
- whether the agent used the Heartwood answer;
- any missing memory or bad-ranking notes.

The two-week adoption gate is calendar-bound and must be completed in the
consuming workspace. This repo contains the generic code and tests needed to
start that run.
