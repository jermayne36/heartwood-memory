"""Trust-receipts benchmark v1 for Heartwood governed memory.

A public, reproducible benchmark that MEASURES Heartwood's governance
receipts against their documented contracts across five probe classes:
forgery injection, policy-leak probes, audit tamper detection, record
retirement, and erasure receipts. It publishes Heartwood's own documented
boundaries (honest limits), not only its guarantees.

Vocabulary is locked to measured/evidence language. The benchmark measures
tamper-EVIDENCE, policy gating at recall time, and key-destruction receipts;
it does not assert tamper-proof storage, authorization integrity under a
database-write adversary, or byte-level erasure. See ``bench/DESIGN.md`` and
the ``docs/api/continuity.md`` claim anchors.
"""

BENCHMARK_VERSION = "1.0.0"
TARGET_HEARTWOOD_VERSION = "0.2.5"

__all__ = ["BENCHMARK_VERSION", "TARGET_HEARTWOOD_VERSION"]
