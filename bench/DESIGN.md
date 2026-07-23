# Trust-Receipts Benchmark — Design (v1)

A public, reproducible benchmark that **measures** Heartwood's governance
receipts against their **documented contracts**, and publishes Heartwood's own
documented boundaries alongside the results. The benchmark speaks in
measured / evidence language: it reports what it observed, tagged as either a
documented contract that held or a documented boundary that was exercised.

- **What it measures:** whether each governance receipt behaves as the docs
  describe, under adversarial conditions the docs name.
- **What it does not do:** it does not assert capabilities Heartwood does not
  claim. The scope anchor is `content_provenance_authenticity`; the
  NOT-claimed set is recall-exclusion, authorization-integrity, tamper-proof
  RBAC/visibility, and database-compromise resistance
  (`docs/api/continuity.md`). Those terms appear here only as documented
  non-claims.

Every current-behavior statement below is exercised by runnable code in
`bench/trust_benchmark/` and gated by `tests/test_trust_benchmark.py`.

---

## 1. Threat-scenario taxonomy → the five probe classes

Each probe class pairs a **receipt** (a governance property Heartwood surfaces)
with an **adversary** (a concrete attack the benchmark performs through the
adapter's declared adversary operations). Adversary operations simulate an
at-rest / database-write attacker ("T2" in Heartwood's threat model) against the
substrate; they are attack simulation for measurement, never a product API.

| # | Probe class | Receipt exercised | Adversary performed | Documented contract measured |
|---|---|---|---|---|
| 1 | **Forgery injection** | Signed provenance | Flip a signed record's content hash; forge its producer signature; edit an unsigned metadata field | A content/signature edit is surfaced as invalid at read, and (strict mode) fails the read closed or drops-and-counts |
| 2 | **Policy-leak probes** | Policy before ranking | Adversarial recall cue for confidential content; caller filter-widening; database-write metadata downgrade | Under-cleared readers do not receive restricted content; caller filters cannot escalate clearance |
| 3 | **Audit tamper detection** | Tamper-evident audit | In-place edit of an audit row; interior-row drop; tail truncation | `verify_audit()` detects in-place edits and interior drops; external anchoring detects tail truncation |
| 4 | **Record retirement** | Recall visibility & retirement | Retire via `set_indexed` / `expire` / supersede, then adversarial opt-in recall; raw column write | Each mechanism removes a record from the answerable corpus exactly as documented, and each is audited |
| 5 | **Erasure receipts** | Key-destruction receipt | Hard `forget`, then recall and crypto-erase-path proof | `forget(hard)` shreds the per-subject key, content becomes unreachable via recall, and the proof reports unrecoverability under the stated root-absence condition |

The five ratified probe classes map to Heartwood's public receipt table
(`README.md` "What you get — five receipts"). Probe 4 (retirement) targets the
`recall-visibility-and-retirement` contract; the README's fifth receipt
(faithfulness + egress) is **not** in this v1 scope and is named as future work
(§6).

### Case types within a probe

- **contract** — the docs state this holds. If measured behavior differs, the
  probe FAILs (a finding to report, never to fix inside this benchmark).
- **positive_control** — proves a gate is not vacuously "deny everything" (e.g.
  a cleared reader *does* retrieve a restricted record).
- **boundary** — a documented NON-claim / honest limit. Always published; never
  fails a probe, because the boundary is the weakest documented position. This
  is where the benchmark publishes Heartwood's own limits.

---

## 2. Scoring / verdict model

Each probe emits a machine-readable `ProbeResult` (`model.py`). Each `Case`
records a documented `expectation`, the `measured` outcome, and a
`matches_contract` boolean, plus a `claim_anchor` tag tying it to the
documented claim scope or a documented non-claim.

Probe status:

- **PASS** — every contract / positive_control case matched its contract.
- **FAIL** — at least one contract / positive_control case did not (a real
  defect; reported, not fixed here).
- **DEGRADED** — a boundary case diverged from its documented behavior
  (surfaced for review; not expected).
- **SKIPPED** — the adapter cannot run the probe (competitor stub, or the
  underlying primitive is absent).

Suite verdict: `overall = FAIL` if any contract case failed, else `PASS`.
Boundaries are counted and published separately (`boundaries_published`) so a
reader can see how many documented limits were exercised.

The benchmark also runs a **claim-anchor scan** (`claim_scan.py`) over its own
docs and result prose. Absolute-promise vocabulary and whole-store secrecy
phrasing must never appear; the NOT-claimed capability phrases may appear only
in a disclaimer context or attached to the `NOT_CLAIMED` anchor. The scan is
part of the receipt and part of the test gate.

---

## 3. Reproducibility contract

- **Pinned system under test.** The runner records the installed
  `heartwood.__version__` and whether it matches the target release. The
  reference baseline is produced against the pip-installed release wheel, not an
  editable source checkout.
- **Deterministic models.** The harness injects Heartwood's own offline dev
  model pair (a hashing embedder + a lexical reranker — the same pair
  Heartwood's test suite uses). Governance behavior is architecturally
  independent of the embedder; retrieval *quality* is explicitly not measured.
  This keeps every run offline and bit-reproducible.
- **Deterministic identity.** Fixed tenant, subjects, memory ids, and content
  (`fixtures.py`).
- **Deterministic custody.** The Ed25519 root used for strict-mode probes is
  derived at runtime from a fixed, public domain string via SHA-256. No secret
  key bytes are committed to this BUSL-1.1 repository.
- **No hidden state.** Every probe runs against a fresh temporary database.
- **Determinism gate.** `run_benchmark.py --check-deterministic` runs the suite
  twice and confirms identical probe results; `tests/test_trust_benchmark.py`
  asserts the same. Result prose carries no timestamps, ids, or paths, so the
  probe section is a stable fingerprint; environment metadata (timestamps,
  platform) is confined to `run_metadata`.

---

## 4. Competitor-adapter interface

The benchmark measures through a substrate-neutral interface
(`adapters/base.py`): a `MemoryAdapter` opens isolated `Session`s that expose
governance operations (remember / recall / verify_audit / retire / forget /
erase_proof / anchor) and adversary operations. A probe describes an attack
semantically; the adapter knows how to execute it on its substrate.

- **Heartwood adapter** (`heartwood_adapter.py`) is live.
- **Competitor adapters** (`stubs.py`: Mem0, Zep, Supermemory) are honest
  stubs. `session()` raises `AdapterNotAvailable`; each declares its
  `capabilities()` (as `null` = "not independently verified in this run",
  hypotheses, never claims) and `requirements()` (API surface, free-tier
  status, signup/credential needs). Running any probe against a stub yields a
  `SKIPPED` result, never a fabricated comparison.

**No comparative claim about a competitor exists in v1.** This run makes zero
third-party network calls and requires zero new signups or credentials. A real
competitor run requires replacing a stub with a live adapter and re-running;
the stubs make that gap structurally explicit. Note that a system lacking a
primitive (no signed provenance, no hash-chained audit, no key-destruction
receipt) cannot implement the corresponding adversary op — a real run reports
*primitive-absent* for that receipt rather than a pass/fail comparison.

---

## 5. Honest limits — what this benchmark does NOT measure

Stated plainly, in measured / evidence language, and consistent with the
`docs/api/continuity.md` claim anchors:

1. **It measures tamper-evidence, not tamper-prevention.** The audit probe
   shows that in-place edits and interior drops are *detected* by
   `verify_audit()`, and that tail truncation is *detected* by external
   anchoring. Detection proves *that* tampering happened; it does not prevent
   it. `NOT_CLAIMED: tamper_proof_rbac_or_visibility`.
2. **It does not measure authorization integrity under a database-write
   attacker.** Recall authorization runs on unsigned mutable metadata
   (`classification`, roles, `indexed`, …). The policy and forgery probes each
   include a boundary case demonstrating that a raw database write can downgrade
   this metadata; that is the documented single-trust-domain assumption, not a
   recall-time defect. `NOT_CLAIMED: authorization_integrity`.
3. **It does not measure byte-level content deletion.** The erasure probe
   measures the key-destruction receipt and the crypto-erase-path proof under
   the stated root-absence condition; it does not assert byte-level erasure.
   `NOT_CLAIMED: db_compromise_resistance`.
4. **It does not claim recall exclusion under a database-write attacker.** The
   retirement probe measures removal from the answerable corpus through the
   sanctioned verbs, and publishes a boundary case where a raw column write
   removes a record with nothing on the audit log.
   `NOT_CLAIMED: recall_exclusion`.
5. **It does not measure retrieval quality.** By construction (deterministic dev
   embedder), ranking quality is out of scope. Governance behavior is
   independent of the embedder.
6. **It does not measure the verification-root custody boundary.** Ordinary
   signature verification assumes the in-database key registry is trustworthy;
   the external-root custody path is out of scope for v1 (named in §6).

---

## 6. Out of scope for v1 (named, not silently dropped)

- **Faithfulness + egress gate** (the README's fifth receipt) — a sixth probe
  class for a later version.
- **Real competitor runs** — Mem0 / Zep / Supermemory live adapters; each stub
  names its requirements. Gated on owner sign-off at the first dollar / first
  signup (the v1 run spends $0 and signs up for nothing).
- **External verification-root custody** — measuring the anchored/custodied
  trust root that would move recall-decision metadata out of the mutable store.
- **Scale / multi-tenant-at-scale** — the policy receipt notes multi-tenant
  validation is still in progress; this benchmark runs single-tenant fixtures.

---

## 7. Layout

```
bench/
  DESIGN.md                     this document
  README.md                     how to run + results summary
  run_benchmark.py              CLI runner + receipt emission
  trust_benchmark/
    model.py                    Case / ProbeResult / status model
    fixtures.py                 deterministic models, custody root, corpus
    claim_scan.py               locked-vocabulary / claim-anchor scanner
    probes.py                   the five probe classes
    adapters/
      base.py                   substrate-neutral interface
      heartwood_adapter.py      live adapter (system under test)
      stubs.py                  competitor stubs + requirements
  results/
    heartwood-<version>-baseline.json   committed reference run
```
