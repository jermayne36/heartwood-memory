# Changelog

All notable changes to `heartwood-memory` are documented here.

## [Unreleased]

### Added
- Dependency-free `heartwood.continuity` capability-contract schemas, privileged
  `indexed=0` contract storage, and versioned signed rotation measured diffs with
  exact audit-sequence binding.
- Closed receipt validation for opaque identifiers, bounded deltas, fixed error
  categories, observed fallbacks, prior baseline/eval/contract hashes, and
  machine-readable production or prototype status.

## [0.2.4] - 2026-07-23

### Added
- Opt-in strict provenance enforcement with `StrictMode.OFF`, `FILTER`, and `ENFORCE`. FILTER returns fewer than `k` and records reason buckets; ENFORCE raises before any recall result or explanation is returned.
- `heartwood strict-preflight` scans every stored row into reconciled terminal buckets, identifies unverifiable operator trust-import candidates, and can seal and activate an exact operator-approved cutover snapshot.
- Snapshot-sealed strict cutover artifacts bind the complete current provenance payload (`id`, `content_hash`, `source.uri`, `created_by`, and `epistemic`) through a length-safe canonical tuple hash, bind tenant separately, fingerprint exact signature bytes, use an operator-config SHA-256 pin, and emit derived-only `strict_exempt` markers for admitted pre-cutover rows.
- Pluggable `AnchorSink` custody, a locked and `fsync`-acknowledged local JSONL sink, signed count/time/close/on-demand anchor writing, `Heartwood.verify_chain_against_anchors()`, and the fail-closed `heartwood verify-audit` receipt CLI.
- Store-global anchors bind the exact audit sequence/hash tuple, chain and sink identities, created time, anchor/signing-key ids, and an externally pinned Ed25519 verification-root fingerprint. Receipts expose chain, sink, signature, freshness, and post-anchor open-window state separately.

### Changed
- The Ed25519 release manifest now covers both the wheel and source distribution, with a SHA-256 receipt for each published artifact.
- Audit iteration now exposes `seq` and `prev_hash`, and chain verification checks the stored previous-hash link as well as each row hash.
- Strict-cutover manifest digests use a signed AnchorSink pin when anchoring is configured; the exact operator-config digest remains the fallback when no sink is supplied.
- The audit module now states the non-atomic compatibility append boundary explicitly instead of implying it has the SQLite writer's concurrency guarantee.

### Governance
- Strict mode authenticates only the five-field provenance payload named above, the stored content hash, exact signature bytes, and the manifest-bound tenant. It does not authenticate `created_at`, `classification`, role/authorization metadata such as `roles_json`, or `indexed` state. A tenant-row mutation is rejected by the separate manifest tenant binding; broader versioned signed-payload coverage remains a separately reviewed migration rather than being folded into this cutover.
- Ordinary Ed25519 verification assumes the `principal_keys` verification-key registry (including its alias rows) in the same SQLite database is trustworthy. Strict mode does not externally pin that registry; replacing both a registry key and the matching stored signature remains outside this release's authenticated boundary.
- The local-file sink is an out-of-database anchor, not an independent timestamp or a separate failure domain by default. It detects database truncation at or below a persisted anchor while the sink and externally pinned signing root remain outside the attacker boundary; post-anchor rows and shared database/sink compromise remain explicit limits.

## [0.2.3] - 2026-07-22

### Added
- `POST /explain-recall` runs an authenticated recall request and returns its safe in-process explanation receipt for production semantic verification. The response includes policy metadata such as validity enforcement and hidden review states, but excludes memory contents and denied-candidate details.
- `Heartwood.expire(mem_id, at, *, actor, reason="")` — audited close (or lift) of a record's validity window. Normalizes the instant to ISO-8601 UTC, rejects an unparseable one instead of writing a value recall would read as "no expiry", and writes an `expire` audit event. `at=None` reinstates the record.
- `Heartwood.set_indexed(mem_id, indexed, *, actor, reason="")` — audited removal from, or reinstatement into, the answerable corpus. Content, provenance and the stored embedding are untouched, so it is reversible without re-embedding; writes an `index_state` audit event.
- Both verbs compare-and-swap against the value they observed and raise on a lost race; re-asserting the current state is a no-op that still writes the audit event, so an out-of-band change can be recorded after the fact.
- `scripts/check.sh` runs the Python 3.11 local quality gate (Ruff plus the full pytest suite); `scripts/install-hooks.sh` installs it as a non-destructive pre-commit hook.

### Changed
- `indexed` and `valid_until` now have sanctioned writers, so a direct `UPDATE` to either is documented as a policy violation in `docs/api/recall-visibility-and-retirement.md`. Previously the only way to move either column was a raw SQL write, which left no audit record of a record leaving recall.
- The declared `dev` extra now includes pytest and Ruff for a reproducible local quality gate.

### Fixed
- Default pytest collection now visibly skips the optional Hermes Agent provider contract when its separate `agent` and `plugins` dependencies are absent, instead of aborting the full suite.
- Consolidation now refuses retired members. `is_member_consolidatable` enforces the record's validity window and locks out every review state that default recall hides (`rejected`, `disputed`, `superseded` — previously only `disputed`). An expired or retired record could otherwise be summarized into a brand-new `proposed` memory, reintroducing content that recall had correctly stopped returning. The locked set is now derived from `DEFAULT_HIDDEN_REVIEW_STATES` so the two gates cannot drift apart.
- A validity bound that cannot be parsed is now treated as "not consolidatable" rather than "no bound", so a corrupt timestamp fails closed on the write-proposing path.
- **Licensee-facing:** the `import-markdown --update` report now names the destructive step for what it is. `superseded_count` / `superseded` are renamed to `purged_count` / `purged` (these rows are deleted, not moved to `review_state="superseded"`). The old keys are still emitted as aliases and will be **removed in 0.3.0** — update report consumers now.

### Governance
- **Authorization is unchanged and deliberately so.** The two new retirement verbs `expire` and `set_indexed` take an `actor` string and are **not** role-gated, matching `forget` and `purge`; `approve` and `transition_review` continue to require a role-bearing principal. `reason` remains optional on `expire` / `set_indexed`, as on `transition_review` — the audit event always records the actor and the before/after change regardless. Gating only the reversible, preservation-safe verbs while the destructive ones stay open would invert the risk gradient, and these verbs have no remote surface (the MCP tool set is a static fail-closed allowlist), so the actor field is audit attribution, not an authentication boundary. A single coherent authorization model across all five governance verbs — and whether to require a non-empty `reason` on recall-removing verbs — is tracked as a separate cross-cutting decision. See `docs/api/recall-visibility-and-retirement.md` § Authorization.

## [0.2.2] - 2026-07-22

### Added
- Warm recall CrossEncoder staging knobs for controlled latency/quality co-runs: `HEARTWOOD_RERANKER_MODEL_PATH`, `HEARTWOOD_RERANKER_MODEL_KEY`, `HEARTWOOD_RERANKER_MAX_LENGTH`, `HEARTWOOD_TORCH_NUM_THREADS`, and `HEARTWOOD_TORCH_INTEROP_THREADS`.

### Changed
- Named production reranker helpers now inherit the same CrossEncoder input clipping, batch-size control, and inference-mode safeguards as the warm recall daemon path.

### Fixed
- Recall now enforces validity windows and hides superseded records by default; use `include_expired` / `include_review_states` for audit views.

## [0.2.1] - 2026-07-16

### Added
- Added a release guard that rejects builds when the runtime `heartwood.__version__` and `pyproject.toml` package version differ.
- Added Official MCP Registry metadata, the required PyPI ownership marker, and a `uvx heartwood-memory` MCP server entry point with its runtime dependencies.
- Included LICENSE, NOTICE, README, and package README data explicitly in source and wheel build configuration.

### Fixed
- Synchronized package metadata and runtime version reporting at `0.2.1`.
- MCP initialization now reports the Heartwood package version instead of the MCP SDK version, and module execution no longer emits a pre-import warning.

### Changed
- The PyPI long description now carries the README authority and evidence-boundary improvements introduced in commit `a923ea6`.

## [0.2.0] — Licensing update: source-available under BSL 1.1

Starting with 0.2.0, the Heartwood Memory core is source-available under the
Business Source License 1.1 (BSL 1.1) instead of MIT. What this means:

- You can still read the source, run it locally, develop against it, evaluate
  it, and self-host it for non-production use — at no charge, at any size.
- Small organizations can also run it in production at no charge (see the
  license for the definition). Larger organizations need a commercial license
  to run it in production.
- Each release converts automatically to Apache License 2.0 four years after
  it ships.
- Versions 0.1.0–0.1.2 remain MIT-licensed, permanently. We have yanked them
  on PyPI so new installs get 0.2.0; you can still install them by exact pin.
  We are not revoking anything.

Why: it keeps the core readable and free to try and self-host while asking
larger production users to fund the project. "Source-available" is not the
same as OSI "open source," and we've updated our wording to say so accurately.

## [0.1.2] - 2026-07-03

### Fixed
- **Critical: recall daemon allocator-pressure fix.** The warm recall daemon (`heartwood.cli serve-recall`) now measures true resident process footprint where available instead of relying only on transient RSS signals.
- Recall request cleanup now runs in `finally` paths after timeout and `BrokenPipe` failures, with explicit `gc.collect()` and Linux `malloc_trim(0)` backstops to return released allocator pages.
- Cross-encoder reranker input text is clipped before native model calls so large recall batches cannot retain unbounded tokenizer/model buffers.
- The memory watchdog remains active as a defense-in-depth kill switch while production parity soaks continue.
- Markdown import now treats hidden paths relative to each scanned source root, so a memory root under a dotted ancestor such as `.claude/` is imported while hidden files inside the root remain excluded.
- `import-markdown --update` no longer purges superseded rows before a replacement has successfully imported; pinned `memory_id` updates now preflight signing capability before deleting the old row.
- Directory sources that produce zero Markdown documents are reported as import errors with per-source counts, preventing silent no-op imports from passing freshness gates.
- `import-markdown` now refuses to write into stores whose indexed embedding dimensions do not match the active import embedder, preventing mixed-dimension stores that the recall daemon cannot serve.

### Caveat
- Large-corpus Linux memory soak was validated on local Docker (Debian/glibc, aarch64); production amd64 (Fly/Railway) parity is not yet soak-verified — the memory watchdog backstop remains active.

## [0.1.1] - 2026-06-20

### Fixed
- **Critical: recall service memory leak.** The warm recall daemon (`heartwood.cli serve-recall`) could grow unbounded in resident memory under sustained load — on Apple Silicon the embedder and cross-encoder reranker auto-bound to the MPS backend, whose allocator cache was never released. Long-running daemons could reach tens of GB of RSS. **All users running the recall service should upgrade.**
  - Both models are now pinned to CPU with a bounded torch thread pool.
  - The dense vector index now caches its stacked matrix and rebuilds only on add/remove (previously re-materialized per query), removing the residual per-recall growth and cutting p95 latency substantially.
  - Cross-encoder rerank input length is bounded; per-document token lists and BM25 corpus stats are cached and invalidated on write.
  - Added a bounded LRU cache of decrypted text and a bounded `_explain` buffer.
  - Added an in-process RSS watchdog (default ceiling 4 GB) as a defense-in-depth backstop.
  - Centralized model-loader configuration so production model backends inherit the same CPU/thread/length pinning.

### Security
- Hardened the recall daemon's local memory-residency surface (core-dump suppression guidance, lowered decrypted-text cache ceiling). The bundled recall service remains **single-tenant and loopback-only by design**; do not expose it to multiple tenants or remote callers without an authorization redesign (see SECURITY notes).

### Added
- Real-model test coverage and an opt-in real-model RSS soak guard so memory regressions are detectable in CI.

## [0.1.0] - 2026-06-11
- Initial public release.
