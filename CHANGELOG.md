# Changelog

All notable changes to `heartwood-memory` are documented here.

## [Unreleased]

### Added
- Warm recall CrossEncoder staging knobs for controlled latency/quality co-runs: `HEARTWOOD_RERANKER_MODEL_PATH`, `HEARTWOOD_RERANKER_MODEL_KEY`, `HEARTWOOD_RERANKER_MAX_LENGTH`, `HEARTWOOD_TORCH_NUM_THREADS`, and `HEARTWOOD_TORCH_INTEROP_THREADS`.

### Changed
- Named production reranker helpers now inherit the same CrossEncoder input clipping, batch-size control, and inference-mode safeguards as the warm recall daemon path.

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
