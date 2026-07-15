"""Recall filter regressions."""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.retrieval import _hashing_embed, tokenize  # noqa: E402


TENANT = "tenant:recall-filters"


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
    return Principal(id="agent:test", tenant=TENANT, clearance="internal")


def test_epistemics_filter_limits_recall_without_changing_absent_filter_path():
    db = _db()
    user_stated = db.remember(
        "Alpha recall policy: user-stated rule must be followed.",
        subject="policy:alpha",
        created_by="agent:test",
        epistemic="user-stated",
    )
    observed_fact = db.remember(
        "Alpha recall policy: observed source fact is available.",
        subject="policy:alpha",
        created_by="agent:test",
        epistemic="observed-fact",
    )
    imported_source = db.remember(
        "Alpha recall policy: imported source document is available.",
        subject="policy:alpha",
        created_by="agent:test",
        epistemic="imported-source",
    )

    baseline = db.recall("alpha recall policy", principal=_principal(), k=10, topc=10)
    empty_filters = db.recall(
        "alpha recall policy",
        principal=_principal(),
        filters={},
        k=10,
        topc=10,
    )
    assert baseline["results"] == empty_filters["results"]

    filtered = db.recall(
        "alpha recall policy",
        principal=_principal(),
        filters={"epistemics": ["user-stated"]},
        k=10,
        topc=10,
    )
    assert [result["id"] for result in filtered["results"]] == [user_stated]
    assert {result["epistemic"] for result in filtered["results"]} == {"user-stated"}

    alias_filtered = db.recall(
        "alpha recall policy",
        principal=_principal(),
        filters={"allowed_epistemics": ["observed-fact", "imported-source"]},
        k=10,
        topc=10,
    )
    assert {result["id"] for result in alias_filtered["results"]} == {
        observed_fact,
        imported_source,
    }
    assert user_stated not in {result["id"] for result in alias_filtered["results"]}
