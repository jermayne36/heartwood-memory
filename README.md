# Heartwood Memory

**Governed, source-auditable memory for AI agents, embedded beside your existing systems of record.**

Heartwood is a cryptographic trust root for agent memory: every memory is signed,
recall runs under policy before ranking, the audit log is hash-chained and
tamper-evident, and erasure emits a falsifiable per-subject key-destruction
receipt. The package ships as an embedded Python library with governed adapter
surfaces that run on your infrastructure.

> **Honest boundary.** Heartwood is managed-key: the server decrypts to serve
> recall. The receipts below are source-auditable today. Deletion is a
> per-subject key-destruction workflow, not an instantaneous deletion guarantee.
> See [Key custody and erasure](docs/security/key-custody.md).

## Install

```bash
python -m pip install "heartwood-memory[recall,mcp]"
```

## 5-minute quickstart

Remember a governed memory, recall it under policy, and emit a key-destruction
receipt:

```python
from heartwood import Heartwood, Policy, Principal, prove_crypto_erase_path

# 1. Open an embedded, tenant-scoped store.
db = Heartwood(path="./heartwood.db", tenant="tenant:acme")

# 2. Remember. The record is signed and written to a hash-chained audit log.
db.remember(
    "Customer 42 is on the Enterprise plan.",
    subject="customer:42",
    created_by="agent:support",
    policy=Policy(classification="internal"),
)

# 3. Recall. Policy gates the candidate set before ranking.
principal = Principal(
    id="agent:support",
    tenant="tenant:acme",
    roles=("support",),
    clearance="internal",
)
out = db.recall(
    "what plan is customer 42 on?",
    principal=principal,
    filters={"subject": "customer:42"},
    k=5,
)

for hit in out["results"]:
    print(hit["content"], hit["provenance"]["signature_valid"])

# 4. Forget. This crypto-shreds the per-subject key and purges derived artifacts.
receipt = db.forget(
    "customer:42",
    mode="hard",
    actor="agent:support",
    reason="right-to-erasure request",
)
db.close()

proof = prove_crypto_erase_path(
    "./heartwood.db",
    tenant="tenant:acme",
    root_present=False,
).to_dict()
print(receipt["key_shredded"], proof["content_unrecoverable"])
```

> **Keep local artifacts out of Git.** This repository's `.gitignore` does not
> propagate into downstream repositories. If you run these examples in another
> checkout, add equivalent ignores there for local Heartwood databases and
> sidecars, token/config files, root-local JSONL inputs, generated `*-report.json`
> files, and `.venv/`; alternatively, keep sensitive runtime state under an
> ignored `.heartwood/` directory. Keep deliberate fixtures in non-root paths so
> they remain reviewable.

Want governed memory for an MCP-capable agent instead of a library? See the
[governed MCP quickstart](docs/integrations/mcp-quickstart.md) and the
[Codex local-stdio quickstart](docs/integrations/codex-quickstart.md). Write
and erase verbs are not exposed by default; operators opt in by naming them
explicitly.

## What you get - five receipts

Governance you can inspect and re-run at the record level:

| Receipt | What it does | Boundary today |
|---|---|---|
| **Signed provenance** | Every memory is signed; the signature and content hash are re-verified at read and surfaced on each result. | Re-verified and surfaced, not yet enforced as a hard read failure. |
| **Tamper-evident audit** | Hash-chained append-only log; `verify_chain()` detects an in-place edit or dropped row. | Catches in-place tampering; tail-truncation needs an external anchor. |
| **Policy before ranking** | Recall is restricted to cleared records before ranking; denied records are not scored, returned, or counted. | Source-auditable; multi-tenant-at-scale validation is still in progress. |
| **Key-destruction receipt** | `forget(mode="hard")` destroys the per-subject key and purges derived artifacts. | Shows key destruction, not byte-level content deletion. |
| **Faithfulness + egress gate** | Generated memories fail closed unless they pass a faithfulness check; rejected egress requests block the external-model call. | Explicit override stores a downweighted, review-only copy. |

## Key docs

- [MCP quickstart](docs/integrations/mcp-quickstart.md)
- [Codex local-stdio quickstart](docs/integrations/codex-quickstart.md)
- [Onboarding guide](docs/integrations/onboarding-guide.md)
- [Python API reference](docs/api/python-api.md)
- [Key custody and erasure](docs/security/key-custody.md)
- [Multi-agent identity](docs/security/multi-agent-identity.md)
- [Postgres and SQLite migration guide](docs/migration/postgres-sqlite-migration-guide.md)
- [Full public documentation map](docs/README.md)

Run the console script after installation:

```bash
heartwood --help
```

## License

From version 0.2.0, Heartwood Memory is source-available under the
[Business Source License 1.1](LICENSE) (BSL 1.1) — not an OSI "open source"
license. You may read the source, run it locally, develop against it, evaluate
it, and self-host it for non-production use at no charge. Small organizations
(fewer than 100 people and less than $1M annual revenue) may also run it in
production at no charge. Larger organizations need a commercial license for
production use. Each version converts automatically to the Apache License 2.0
four years after its release.

Versions 0.1.0–0.1.2 are MIT-licensed and remain so permanently. See
[NOTICE](NOTICE) for details. Commercial support, managed key custody, and
hosted services are available separately.

## Current Bias

Prove boring trust before building ambitious cognition:

- provenance
- typed memory routing
- policy-aware recall
- temporal state
- deletion completeness
- generated-memory faithfulness
- repeatable evals

The cognitive database vision should be earned by evidence from these loops.
