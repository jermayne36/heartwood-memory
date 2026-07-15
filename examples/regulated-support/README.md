# Regulated Support Agent Demo on Governed Memory

A self-contained, runnable scenario that shows the Heartwood wedge to a regulated
buyer: an AI agent that answers a real ticket **with provenance**, under
**access governance**, and then **passes a compliance audit** — including
GDPR-grade erasure of derived data.

```bash
python examples/regulated-support/run_demo.py
# -> prints the two governed answers + 5 compliance checks
# -> writes COMPLIANCE_REPORT.md (the artifact you hand an auditor)
```

Runs with zero setup (dependency-free fallbacks) or, if installed, real models
(sentence-transformers) and real AES (cryptography/Fernet).

## The scenario

A health-plan member-support desk. The knowledge base mixes citable policy
documents, member PII records, and **one restricted clinical record**. The same
ticket — *"Is Jane Doe's ER visit covered, and any clinical considerations?"* —
is handled by two agents with different clearances.

## What it proves (the talk track)

1. **Every answer is source-attributed.** Each recalled memory carries a verified
   producer signature and a source URI — 100% provenance coverage.
2. **Access is governed in the retrieval path.** The nurse (clinical clearance)
   sees the clinical record; the intern (support clearance) does **not** — and
   its existence isn't leaked via result count, score, or latency.
3. **Derived data inherits sensitivity (high-water-mark).** The agent's drafted
   answer cites a restricted source, so the answer *itself* becomes restricted —
   the intern can't read it. This closes the "summary launders a restricted
   source" leak that the raw memory tool and every framework would allow.
4. **Erasure reaches derived data (lineage cascade).** A GDPR Art.17 request
   crypto-shreds the member's key **and** purges memories derived from her data
   (the drafted answer that quoted her diagnosis). Post-erasure, the clinical
   fact is unrecoverable — directly or via any summary. Another member's records
   are untouched (subject isolation). The erasure *event* is retained in the
   tamper-evident audit log.
5. **Read-your-writes.** Freshness is explicit (`index_lag = 0`).

The closing line of the report: *"What no current agent-memory framework
provides — every answer source-attributed, restricted data access-governed in the
retrieval path, tamper-evident audit, and verifiable crypto-shred erasure of
derived data."*

## How it maps to a real deployment

Here the agent's tool calls are scripted for determinism. In production, Claude
drives the same operations through the **MCP server / memory tool**
(`heartwood/adapters/`): the model recalls governed knowledge and writes working
notes, while Heartwood enforces provenance, policy, and erasure underneath. The demo
already uses the real `MemoryToolBackend` for the agent's working note.

## Files

| File | Role |
|---|---|
| `corpus.py` | The governed knowledge base (policies + member PII + clinical record) |
| `agent.py` | A scripted support agent: recall → cite → record governed answer → write note |
| `audit.py` | Runs the 5 compliance checks and renders the report |
| `run_demo.py` | Orchestrates ingest → two-clearance handling → audit |
| `COMPLIANCE_REPORT.md` | Generated artifact (the deliverable) |
