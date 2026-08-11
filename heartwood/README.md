# Heartwood Memory

A provenance-first, embedded agent-memory library. The differentiator is
**governance** — tamper-evident provenance, policy-enforced recall, and
crypto-shred erasure — layered over **benchmark-validated hybrid retrieval**
(dense + BM25 + cross-encoder rerank). Spreading activation was empirically
cut; this library does not ship it.

Why this exists: 2026 agent-memory frameworks expose varying governance
surfaces, often behind hosted or paid tiers. Heartwood's wedge is open,
embedded, record-level provenance, policy-gated recall, and key-destruction
receipts.

## Quick start

```python
from heartwood import Heartwood, Principal, Policy

db = Heartwood(path="mem.db", tenant="tenant:acme")

db.remember("User prefers concise, technical answers.",
            subject="user:jane", created_by="agent:asst",
            kind="semantic", epistemic="user-stated",
            policy=Policy(classification="internal"))

out = db.recall("how should I communicate with Jane?",
                principal=Principal(id="agent:asst", tenant="tenant:acme",
                                    roles=("support",), clearance="internal"),
                filters={"subject": "user:jane"}, k=5)

for r in out["results"]:
    print(r["content"], r["score"], r["provenance"]["signature_valid"])

# why did I get this? (provenance + ranking signals + policy decisions)
db.explain_recall(out["recall_id"])

# Right-to-erasure workflow: crypto-shred the subject key + purge derived artifacts
db.forget("user:jane", mode="hard", reason="DSAR", legal_basis="right-to-erasure request")
```

Run the end-to-end demo: `python tests/smoke_test.py`

## Tenant-aware bulk API

```python
from heartwood import Heartwood

db = Heartwood(path="mem.db", tenant="tenant:ops")

db.remember_many([
    {
        "tenant": "acme-payments",
        "subject": "acme-payments:audit",
        "content": "Preserve audit details and provenance.",
        "classification": "internal",
        "source_uri": "doc://acme-payments/audit",
    },
    {
        "tenant": "northwind-retail",
        "subject": "northwind-retail:auth",
        "content": "Finance reviews Northwind Retail auth changes.",
        "classification": "confidential",
        "roles": ["finance"],
        "source_uri": "doc://northwind-retail/auth",
    },
])

out = db.recall_for_tenant(
    "northwind-retail",
    "who reviews auth changes?",
    roles=["finance"],
    clearance="confidential",
)
```

CLI bulk import:

```bash
heartwood bulk-remember --input records.jsonl --db mem.db --tenant tenant:ops
```

## What's implemented

| Capability | Module | Notes |
|---|---|---|
| Memory envelope + epistemic (truth/belief) classes | `envelope.py` | immutable; trust ladder; no auto `approved-canonical` |
| SQLite authoritative store | `store.py` | vector/BM25 are derived & rebuildable |
| Hybrid retrieval | `retrieval.py` | dense + BM25 (RRF) + cross-encoder rerank |
| Policy in the retrieval path | `policy.py` | tenant hard-partition, RBAC/ABAC, classification; gates the candidate set |
| Tamper-evident provenance | `provenance.py` | per-producer signatures + derivation chain |
| Crypto-shred erasure + deletion-lineage | `erasure.py` | per-subject keys (Fernet/AES); EDPB 02/2025 pattern |
| Append-only hash-chained audit | `audit.py` | erasure event retained after payload shredded |
| Cognitive verbs | `client.py` | `remember` / `recall` / `explain_recall` / `approve` / `forget` |

## Dependencies

Hard: `numpy` and `cryptography`. Install the recall/MCP extra for productized
paths: `python -m pip install "heartwood-memory[recall,mcp]"`. That extra includes
`sentence-transformers`, `sqlite-vec`, and `mcp`. Without
`sentence-transformers`, the library still runs with deterministic hashing
embeddings and a lexical reranker for local development.

## Production retrieval (implemented)

```python
from heartwood import Heartwood
from heartwood.models import embedder, reranker      # named 2026 SOTA loaders

db = Heartwood(
    path="mem.db", tenant="tenant:acme",
    index="sqlite-vec",                            # SQLite-native ANN (numpy default)
    embedder=embedder("embeddinggemma"),           # or "bge-m3" / "qwen3"
    reranker=reranker("bge-v2"),                   # or "mxbai" / "jina"
)
```

- **Vector index** → `index="sqlite-vec"` (asg017): SQLite-native ANN; numpy
  brute-force is the default. `index="auto"` tries sqlite-vec, falls back.
- **Embedder** → `heartwood.models.embedder("embeddinggemma" | "bge-m3" | "qwen3")`.
- **Reranker** → `heartwood.models.reranker("bge-v2" | "mxbai" | "jina")`.
- Still pluggable: pass any `(callable, name)` pair.

Still per-deployment: external **KMS/HSM** for encryption keys. The Python
scaffold uses **Ed25519** signatures when `cryptography` is installed, with a
random-key HMAC fallback for dependency-free local mode.

## Adapters (governed memory for standard interfaces)

`heartwood/adapters/` — make Heartwood a drop-in **governed** backend:
- **Anthropic Memory Tool** (`memory_20250818`): `MemoryToolBackend` implements all
  six `/memories` commands, adding version history, provenance, audit, semantic
  recall, and crypto-shred erasure the raw file backend lacks.
- **MCP server**: `python -m heartwood.adapters.mcp_server` exposes `remember` / `recall`
  / `explain_recall` / `forget` / `memory` to any MCP client.

See `heartwood/adapters/README.md`. Tests: `python tests/test_memory_tool.py`.

## Not in Phase 0 (deferred)

Async index build + freshness lag (the contract exists; `flush_index()` is a
no-op here), Contextual-Retrieval ingest pipeline, branching, distribution,
multimodal.
