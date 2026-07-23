"""Deterministic, hermetic fixtures for the trust-receipts benchmark.

Reproducibility contract
------------------------
- **Pinned system under test**: the harness asserts the installed
  ``heartwood.__version__`` matches the target release before running.
- **Deterministic models**: the benchmark injects Heartwood's own sanctioned
  offline dev model pair (a hashing embedder + a lexical reranker, the same
  pair Heartwood's test suite uses). Governance behavior is architecturally
  independent of the embedder; retrieval *quality* is explicitly NOT measured.
  This keeps every run offline and bit-reproducible.
- **Deterministic identity**: fixed tenant, subjects, memory ids, and content.
- **Deterministic custody**: the Ed25519 root used for strict-mode probes is
  derived at runtime from a fixed, public domain string via SHA-256 — no secret
  key material is committed to this BUSL-1.1 repository.
- **No hidden state**: every probe runs against a fresh temp database.
"""
from __future__ import annotations

import hashlib

# Fixed, public derivation string. NOT a secret: the strict-mode probes need a
# durable Ed25519 custody root, and deriving it deterministically keeps runs
# reproducible while committing zero key bytes to the repo.
_FIXTURE_ROOT_DOMAIN = b"heartwood-trust-benchmark/fixture-custody-root/v1"

TENANT = "tenant:trust-bench"
CUSTODY_KEY_ID = "trust-bench-fixture-root-v1"


def fixture_custody_root() -> bytes:
    """A deterministic 32-byte Ed25519 custody root for strict-mode probes."""
    return hashlib.sha256(_FIXTURE_ROOT_DOMAIN).digest()


def deterministic_models():
    """Heartwood's sanctioned offline dev model pair (embedder, reranker).

    Falls back to a self-contained hashing embedder if the internal helper is
    unavailable in a future release, so the harness never depends on network or
    model downloads.
    """
    try:
        from heartwood.importers.markdown import dev_models
        return dev_models()
    except Exception:  # pragma: no cover - defensive fallback
        return _fallback_models()


def _fallback_models():  # pragma: no cover - only used if dev_models is gone
    import numpy as np

    def embed(texts, dim: int = 256):
        vecs = np.zeros((len(texts), dim), dtype=np.float32)
        for i, text in enumerate(texts):
            for token in str(text).lower().split():
                h = int(hashlib.sha1(token.encode()).hexdigest(), 16)
                vecs[i, h % dim] += 1.0
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return vecs / norms

    def rerank(query, texts):
        q = set(str(query).lower().split())
        out = np.zeros(len(texts), dtype=np.float32)
        for i, text in enumerate(texts):
            toks = set(str(text).lower().split())
            out[i] = len(q & toks) / (len(q | toks) or 1)
        return out

    return (embed, "bench-hashing-embedder"), (rerank, "bench-lexical-reranker")


# --- Fixture corpus -------------------------------------------------------- #
# Distinctive tokens per record so a lexical cue reliably retrieves it under
# the deterministic dev embedder. Content is synthetic; no real PII.

PUBLIC_RECORD = {
    "memory_id": "mem_bench_public_kb_0001",
    "subject": "kb:public",
    "content": "Zephyr onboarding runbook: public knowledge base article alpha.",
    "cue": "zephyr onboarding runbook public knowledge base alpha",
    "classification": "internal",
    "clearance_to_read": "internal",
}

CONFIDENTIAL_RECORD = {
    "memory_id": "mem_bench_confidential_0001",
    "subject": "customer:vip-quokka",
    "content": "Quokka merger term sheet: confidential board-restricted figures.",
    "cue": "quokka merger term sheet confidential board restricted figures",
    "classification": "confidential",
    "role_gate": ("legal",),
    "clearance_to_read": "confidential",
    "role_to_read": "legal",
}

FORGERY_RECORD = {
    "memory_id": "mem_bench_forgery_0001",
    "subject": "kb:provenance",
    "content": "Nimbus provenance canary: signed governance record beta.",
    "cue": "nimbus provenance canary signed governance record beta",
    "classification": "internal",
}

RETIREMENT_RECORD = {
    "memory_id": "mem_bench_retire_0001",
    "subject": "kb:retire",
    "content": "Solstice deprecated policy snapshot gamma for retirement checks.",
    "cue": "solstice deprecated policy snapshot gamma retirement",
    "classification": "internal",
}

ERASURE_RECORD = {
    "memory_id": "mem_bench_erase_0001",
    "subject": "customer:right-to-erasure-delta",
    "content": "Marigold erasure subject delta: content that must become unrecoverable.",
    "cue": "marigold erasure subject delta content unrecoverable",
    "classification": "internal",
}
