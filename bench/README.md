# Heartwood Trust-Receipts Benchmark (v1)

A public, reproducible benchmark that **measures** Heartwood's governance
receipts against their documented contracts — and publishes Heartwood's own
documented boundaries alongside the results, including any failures found.

It is deliberately unglamorous: it speaks in measured / evidence language, it
tests tamper-**evidence** (not tamper-prevention), and it stays inside the
documented claim scope (`content_provenance_authenticity`). The design,
threat-scenario taxonomy, scoring model, reproducibility contract, and the full
honest-limits section are in [`DESIGN.md`](DESIGN.md).

## What it covers

Five probe classes, each pairing a receipt with a concrete adversary:

1. **Forgery injection** → signed provenance (content-hash flip, signature
   forgery, strict-mode enforcement, and a metadata-edit boundary).
2. **Policy-leak probes** → policy-before-ranking (adversarial cue,
   filter-escalation attempt, cleared-reader control, and a database-write
   downgrade boundary).
3. **Audit tamper detection** → tamper-evident audit (in-place edit, interior
   drop, and tail-truncation with external anchoring).
4. **Record retirement** → recall visibility & retirement (unindex, expire,
   supersede, audit coverage, and a raw-write boundary).
5. **Erasure receipts** → key-destruction receipt (hard forget, recall
   unreachability, crypto-erase-path proof, and a root-present boundary).

Contract cases must uphold their documented behavior or the probe fails.
Boundary cases publish documented limits and never fail the run — that is the
"publish our own boundaries too" posture.

## Running it

The harness lives in `bench/` and is **not** part of the shipped wheel. It runs
against the installed Heartwood release, fully offline, with no third-party
network calls, no new credentials, and no spend.

```bash
# From a checkout with heartwood importable (e.g. an installed release):
python bench/run_benchmark.py --out bench/results/heartwood-0.2.5-baseline.json

# Print to stdout instead:
python bench/run_benchmark.py --print

# Confirm two runs produce identical probe results:
python bench/run_benchmark.py --check-deterministic
```

The exit code is non-zero if any contract / positive-control case failed or the
claim-anchor scan found a violation. Documented boundaries never fail the run.
Pass `--no-fail` for report-only mode (failures are still recorded in the JSON).

The self-tests run under the repository gate:

```bash
bash scripts/check.sh          # ruff + pytest, includes tests/test_trust_benchmark.py
```

## Reference baseline

The committed reference run is
[`results/heartwood-0.2.5-baseline.json`](results/heartwood-0.2.5-baseline.json),
produced against the pip-installed `0.2.5` release. In that run every contract
and positive-control case upholds its documented contract across all five probe
classes, and each probe publishes its documented boundary. Any future run that
surfaces a failing contract case records it in the JSON — a found failure is a
finding, reported honestly, not hidden.

## Competitors

Mem0, Zep, and Supermemory are present as **honest stubs** (`adapters/stubs.py`).
This v1 run makes zero third-party calls and requires zero signups, so **no
comparative claim about a competitor exists yet**. Each stub declares what a
real run would require (API surface, free-tier status, credential/signup needs)
and which probe classes even apply. Running any probe against a stub is
`SKIPPED`, never a fabricated comparison.

## Spend

`$0`. Standard-library plus NumPy (already a Heartwood dependency); competitor
adapters are stubs; no new runtime dependency is introduced. Installing
Heartwood's own declared dependencies from PyPI is not a third-party service
call.
