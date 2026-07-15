# Warm Recall Quickstart

This is the Phase 1 B2 path for low-latency local recall from hooks, agents, or
other client processes. The service keeps the Heartwood store, vector index,
embedder, and reranker warm so calls do not pay startup/model-load cost.

## Install

```powershell
python -m pip install "heartwood-memory[recall,mcp]"
New-Item -ItemType Directory -Force -Path .\.heartwood | Out-Null
icacls .\.heartwood /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
```

The `recall` extra installs the optional model and SQLite-vector dependencies
used by production-like local recall. Use `--dev-models` only for deterministic
smoke tests.

## Start The Service

Prefer `HEARTWOOD_RECALL_TOKEN` or `--token-file`. Do not pass bearer tokens with
`--token` in shared shells because command-line arguments can be visible through
process listings.

```powershell
$env:HEARTWOOD_RECALL_TOKEN = "replace-with-local-secret"
heartwood serve-recall `
  --db .\.heartwood\heartwood.db `
  --tenant tenant:ops `
  --warm-tenant tenant:ops `
  --warm-tenant tenant:acme-payments `
  --warm-tenant tenant:northwind-retail `
  --host 127.0.0.1 `
  --port 8765
```

Token-file form:

```powershell
Set-Content -NoNewline -Path .\.heartwood\heartwood-recall.token -Value "replace-with-local-secret"
heartwood serve-recall `
  --db .\.heartwood\heartwood.db `
  --tenant tenant:ops `
  --host 127.0.0.1 `
  --port 8765 `
  --token-file .\.heartwood\heartwood-recall.token
```

Production use should use the package defaults or an explicitly configured local
embedder and reranker once that configuration surface lands.

## Recall From The CLI

Embedded, one-shot recall:

```powershell
heartwood recall `
  --db .\.heartwood\heartwood.db `
  --tenant tenant:acme-payments `
  --principal-id agent:orchestrator `
  --query "what guidance applies to Acme Payments audit details?" `
  --k 5 `
  --json
```

Warm service recall uses `HEARTWOOD_RECALL_TOKEN` automatically:

```powershell
heartwood recall `
  --url http://127.0.0.1:8765 `
  --tenant tenant:acme-payments `
  --principal-id agent:orchestrator `
  --query "what guidance applies to Acme Payments audit details?" `
  --k 5 `
  --json
```

Token-file form for callers:

```powershell
heartwood recall `
  --url http://127.0.0.1:8765 `
  --token-file .\.heartwood\heartwood-recall.token `
  --tenant tenant:acme-payments `
  --principal-id agent:orchestrator `
  --query "what guidance applies to Acme Payments audit details?" `
  --k 5 `
  --json
```

Both paths return JSON with `recall_id`, `latency_ms`, `index_lag`, result
metadata, provenance validation, ranking signals, and source IDs.

## Delete A Subject

For deletion hooks and DSAR workflows that cannot call Python directly, use the
CLI or authenticated HTTP route:

```powershell
heartwood forget `
  --db .\.heartwood\heartwood.db `
  --tenant tenant:acme-payments `
  --subject customer:42 `
  --actor dpo `
  --reason "DSAR"
```

HTTP `POST /forget` always requires bearer auth. If the service was started
without a token, `/forget` returns `401 token_required` instead of accepting an
unauthenticated destructive call.

## Measure The 500ms Budget

```powershell
heartwood bench-recall `
  --url http://127.0.0.1:8765 `
  --tenant tenant:acme-payments `
  --principal-id agent:orchestrator `
  --query "Acme Payments audit provenance guidance" `
  --query "what should I remember about Northwind Retail auth incidents?" `
  --repeat 10 `
  --max-p95-ms 500 `
  --require-pass
```

The benchmark reports `p50_latency_ms`, `p95_latency_ms`, max latency, and pass
status. It should be run against the warm service before cutting over any
latency-sensitive caller.

## HTTP Surface

The service binds to `127.0.0.1` by default and is intended for local use. Keep
bearer auth enabled when agent tools can reach localhost.

### `GET /health`

Health is intentionally liveness-only and safe for unauthenticated process
checks:

Response:

```json
{
  "ok": true,
  "service": "heartwood-recall"
}
```

Do not depend on `/health` for warmed-tenants, model, or key-custody metadata.

### `GET /local/readiness`

Use local readiness for model and embedding-dimension diagnostics. This endpoint
is disabled unless `HEARTWOOD_RECALL_LOCAL_DIAGNOSTICS=1` is set before daemon
startup, is loopback-only, and requires the bearer token when recall auth is
configured:

```bash
curl -s \
  -H "Authorization: Bearer $(tr -d '\n' < ./.heartwood/heartwood-recall.token)" \
  http://127.0.0.1:8765/local/readiness | python -m json.tool
```

Response:

```json
{
  "ok": true,
  "service": "heartwood-recall",
  "local_only": true,
  "embedder": {
    "name": "sentence-transformers/all-MiniLM-L6-v2@1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    "dimension": 384,
    "dev_fallback": false
  },
  "reranker": {
    "name": "cross-encoder/ms-marco-MiniLM-L-6-v2@c5ee24cb16019beea0893ab7796b1df96625c6b8",
    "dev_fallback": false
  },
  "index": "numpy",
  "db_embedding_dimensions": [384],
  "checks": {
    "non_dev_embedder": true,
    "non_dev_reranker": true,
    "db_dimension_match": true
  }
}
```

### `POST /recall`

Request:

```json
{
  "query": "Acme Payments audit provenance guidance",
  "tenant": "tenant:acme-payments",
  "principal_id": "agent:orchestrator",
  "roles": ["finance"],
  "attrs": ["region=us"],
  "clearance": "confidential",
  "k": 5,
  "topc": 50,
  "filters": {
    "subject": "acme-payments:audit",
    "kinds": ["semantic"]
  },
  "typed": true,
  "entities": ["acme-payments"]
}
```

Required fields: `query` or `cue`. All other fields are optional and default to
the service tenant, `agent:recall`, `internal` clearance, `k=5`, and `topc=50`.
If bearer auth is enabled, send `Authorization: Bearer <token>`.

Response:

```json
{
  "ok": true,
  "tenant": "tenant:acme-payments",
  "principal_id": "agent:orchestrator",
  "latency_ms": 42.5,
  "recall_id": "rec_...",
  "index_lag": 0,
  "result_count": 1,
  "results": [
    {
      "id": "mem_...",
      "content": "Acme Payments reviews must preserve audit details.",
      "score": 0.98,
      "source_ids": ["doc://acme-payments/audit"],
      "provenance": {
        "signature_valid": true,
        "content_hash_match": true
      },
      "signals": {
        "dense_sim": 0.71,
        "bm25": 1.2,
        "rrf": 0.032,
        "rerank_score": 0.98,
        "final_rank": 0
      }
    }
  ],
  "models": {
    "embedder": "sentence-transformers/all-MiniLM-L6-v2",
    "reranker": "cross-encoder/ms-marco-MiniLM-L-6-v2",
    "index": "numpy"
  }
}
```

### `POST /forget`

Request:

```json
{
  "tenant": "tenant:acme-payments",
  "subject": "customer:42",
  "mode": "hard",
  "actor": "dpo",
  "reason": "DSAR",
  "legal_basis": "GDPR Art.17"
}
```

Required fields: `subject`. `mode` currently supports `hard`.

Response:

```json
{
  "ok": true,
  "tenant": "tenant:acme-payments",
  "subject": "customer:42",
  "mode": "hard",
  "purged": 3,
  "cascade": 1,
  "key_shredded": true,
  "reason": "DSAR",
  "legal_basis": "GDPR Art.17"
}
```

### Other Routes

- `GET /metrics` returns process-local recall latency counters and p95.
- `POST /warm` accepts `{"tenant":"tenant:ops"}` or `{"tenants":["tenant:ops"]}`
  and warms additional tenants.
