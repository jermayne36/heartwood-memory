"""Product-level typed-ranking regressions."""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Policy, Principal  # noqa: E402
from heartwood.retrieval import _hashing_embed, tokenize  # noqa: E402


TENANT = "tenant:typed-ranking"


def _rerank(query, texts):
    q = set(tokenize(query))
    scores = np.zeros(len(texts), dtype=np.float32)
    for index, text in enumerate(texts):
        d = set(tokenize(text))
        scores[index] = len(q & d) / (len(q | d) or 1)
    return scores


def _db() -> Heartwood:
    return Heartwood(
        path=":memory:",
        tenant=TENANT,
        embedder=(_hashing_embed, "test-hashing-embedder"),
        reranker=(_rerank, "test-lexical-reranker"),
    )


def _principal() -> Principal:
    return Principal(id="agent:test", tenant=TENANT, roles=("support",), clearance="internal")


def test_truth_status_downweights_unreviewed_generated_memory():
    db = _db()
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
