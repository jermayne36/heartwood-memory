"""Product-level typed-ranking regressions."""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Policy, Principal  # noqa: E402
from heartwood.retrieval import _hashing_embed, tokenize  # noqa: E402
from heartwood.typed_ranking import typed_adjusted_score  # noqa: E402


TENANT = "tenant:typed-ranking"


def _rerank(query, texts):
    q = set(tokenize(query))
    scores = np.zeros(len(texts), dtype=np.float32)
    for index, text in enumerate(texts):
        d = set(tokenize(text))
        scores[index] = len(q & d) / (len(q | d) or 1)
    return scores


def _negative_rerank(query, texts):
    return np.full(len(texts), -2.0, dtype=np.float32)


def _db(reranker=_rerank) -> Heartwood:
    return Heartwood(
        path=":memory:",
        tenant=TENANT,
        embedder=(_hashing_embed, "test-hashing-embedder"),
        reranker=(reranker, "test-reranker"),
    )


def _principal() -> Principal:
    return Principal(id="agent:test", tenant=TENANT, roles=("support",), clearance="internal")


def _remember_trust_pair(db: Heartwood) -> tuple[str, str]:
    content = "Refund policy covers duplicate charges within 30 days."
    observed = db.remember(
        content,
        subject="policy:refund",
        created_by="loader",
        kind="source",
        epistemic="observed-fact",
        confidence=1.0,
        truth_status="source_observed",
        source={"uri": "doc://refund-policy"},
        source_ids=("doc://refund-policy",),
        source_spans=(
            {
                "source_id": "doc://refund-policy",
                "span_id": "doc://refund-policy#full",
                "text": content,
            },
        ),
        policy=Policy(classification="internal"),
    )
    generated = db.remember(
        content,
        subject="policy:refund",
        created_by="agent:draft",
        kind="generated",
        epistemic="model-generated",
        confidence=1.0,
        truth_status="generated_needs_review",
        policy=Policy(classification="internal"),
    )
    return observed, generated


def test_truth_status_downweights_unreviewed_generated_memory():
    db = _db()
    observed, generated = _remember_trust_pair(db)

    out = db.recall(
        "refund policy duplicate charges",
        principal=_principal(),
        filters={"typed": True, "intent": "policy"},
        k=5,
        topc=10,
    )
    ids = [result["id"] for result in out["results"]]
    assert observed in ids and generated in ids
    assert ids.index(observed) < ids.index(generated)


# @positive-control(typed-ranking-negative-base)
def test_negative_base_keeps_observed_source_above_unreviewed_generated_memory():
    db = _db(_negative_rerank)
    observed, generated = _remember_trust_pair(db)

    out = db.recall(
        "refund policy duplicate charges",
        principal=_principal(),
        filters={"typed": True, "intent": "policy"},
        k=5,
        topc=10,
    )
    ids = [result["id"] for result in out["results"]]
    assert ids.index(observed) < ids.index(generated)
    results_by_id = {result["id"]: result for result in out["results"]}
    assert results_by_id[observed]["signals"]["rerank_score"] == -2.0
    assert results_by_id[generated]["signals"]["rerank_score"] == -2.0
    assert results_by_id[observed]["signals"]["base_normalized"] == 0.1192
    assert results_by_id[generated]["signals"]["base_normalized"] == 0.1192


def test_typed_score_is_monotonic_across_cross_encoder_logit_range():
    row = {
        "kind": "semantic",
        "truth_status": "source_observed",
        "confidence": 0.8,
    }
    bases = (-12.0, -2.0, 0.0, 9.0)
    scores = [typed_adjusted_score(base, row)[0] for base in bases]
    assert scores == sorted(scores)
    assert len(set(scores)) == len(scores)


def test_probability_base_is_clamped_before_typed_weights():
    row = {
        "kind": "semantic",
        "truth_status": "source_observed",
        "confidence": 1.0,
    }
    low_score, low_signals = typed_adjusted_score(-2.0, row, base_scale="probability")
    high_score, high_signals = typed_adjusted_score(2.0, row, base_scale="probability")
    assert low_score == 0.0
    assert high_score == 1.1
    assert low_signals["base_normalized"] == 0.0
    assert high_signals["base_normalized"] == 1.0


def test_logit_normalization_handles_large_magnitudes():
    row = {
        "kind": "semantic",
        "truth_status": "source_observed",
        "confidence": 1.0,
    }
    low_score, low_signals = typed_adjusted_score(-1000.0, row)
    high_score, high_signals = typed_adjusted_score(1000.0, row)
    assert low_score == 0.0
    assert high_score == 1.1
    assert low_signals["base_normalized"] == 0.0
    assert high_signals["base_normalized"] == 1.0


def test_valid_at_drops_expired_memory():
    db = _db()
    expired = db.remember(
        "The support hotline moved to 555-0100.",
        subject="support:hotline",
        created_by="loader",
        kind="semantic",
        epistemic="observed-fact",
        truth_status="source_observed",
        valid_until="2026-01-01T00:00:00Z",
        policy=Policy(classification="internal"),
    )
    current = db.remember(
        "The support hotline moved to 555-0200.",
        subject="support:hotline",
        created_by="loader",
        kind="semantic",
        epistemic="observed-fact",
        truth_status="source_observed",
        valid_from="2026-01-01T00:00:00Z",
        policy=Policy(classification="internal"),
    )

    out = db.recall(
        "support hotline moved",
        principal=_principal(),
        filters={"typed": True, "effective_at": "2026-06-01T00:00:00Z"},
        k=5,
        topc=10,
    )
    ids = [result["id"] for result in out["results"]]
    assert expired not in ids
    assert current in ids


def main():
    test_truth_status_downweights_unreviewed_generated_memory()
    test_valid_at_drops_expired_memory()
    print("TYPED RANKING TESTS PASSED")


if __name__ == "__main__":
    main()
