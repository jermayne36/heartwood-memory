# Rotation receipt prototype

> **PROTOTYPE ONLY.** This page describes toy-suite and deterministic-stub
> evidence. It is not production-catalog evidence.

The prototype executes an opaque, fixture-driven toy eval suite against two
in-process `ModelRoute` stubs. It converts responses and failures to closed
outcomes, bounded numbers, and fixed error categories before it calls the
public `heartwood.continuity` API. The result is a real signed, audit-bound
rotation receipt labeled `evidence_mode=prototype`.

The prototype has no provider SDK, network route, subprocess, shell tool, file
tool, or model-generated tool surface. Its run summary therefore reports
`live_routes=0`, `stub_routes=2`, and `child_processes=0`.
Replacing either bundled stub with another callable moves execution outside the
validated prototype boundary; the bundled route counts and negative-control
claims must not be reused for that run.

Run it from a repository checkout with the development dependencies installed:

```bash
prototype_dir="$(mktemp -d)"
python3.11 examples/rotation-receipt-prototype/run_prototype.py \
  --output-dir "$prototype_dir"
```

The prototype-only output contains:

- `rotation-receipt.json` — the canonical signed measured diff;
- `baseline-receipt.json` — the real signed prior baseline bound by the final
  prototype receipt;
- `run-summary.json` — fixed claim scope, route counts, verification booleans,
  and sentinel negative-control results;
- `prototype-report.md` — a visibly labeled rendered prototype receipt;
- `heartwood-prototype.db` — the throwaway local audit store used for the run.

`Continuity.verify_rotation_receipt()` verifies the detached signature, the
exact audit event binding, and the audit chain. The prototype receipt
authenticates the measured diff bytes; it does not claim that a production
provider catalog was executed or that the toy eval predicts production quality.
