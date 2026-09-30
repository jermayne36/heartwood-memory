"""Candidate-aware reranking and legacy output compatibility."""
import json
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Policy, Principal  # noqa: E402
from heartwood.retrieval import RerankResult, _hashing_embed, fuse_rerank  # noqa: E402


def test_v1_reranker_golden_bytes():
    calls = []

    def rerank(query, texts):
        calls.append((query, texts))
        return np.array([0.25, 0.75, 0.5], dtype=np.float32)

    rerank.score_scale = "probability"
    ranked = fuse_rerank(
        rerank,
        "query",
        [{"id": "a", "text": "alpha"}, {"id": "b", "text": "beta"},
         {"id": "c", "text": "gamma"}],
        {"a": 0.9, "b": 0.8, "c": 0.7},
        {"a": 3.0, "b": 2.0, "c": 1.0},
        k=3,
    )
    assert calls == [("query", ["alpha", "beta", "gamma"])]
    assert json.dumps(ranked, separators=(",", ":")).encode() == (
        b'[["b",0.75,{"dense_sim":0.8,"bm25":2.0,"rrf":0.0323,'
        b'"rerank_score":0.75,"final_rank":0}],["c",0.5,{"dense_sim":0.7,'
        b'"bm25":1.0,"rrf":0.0317,"rerank_score":0.5,"final_rank":1}],'
        b'["a",0.25,{"dense_sim":0.9,"bm25":3.0,"rrf":0.0328,'
        b'"rerank_score":0.25,"final_rank":2}]]'
    )


class RecordingReranker:
    score_scale = "logit"  # The result's declared scale takes precedence.

    def __init__(self, scale="probability"):
        self.scale = scale
        self.calls = []

    def __call__(self, query, texts):
        raise AssertionError("candidate protocol must take precedence over v1")

    def rerank_candidates(self, query, candidates, context):
        self.calls.append((query, candidates, context))
        return RerankResult(
            scores=[0.9 if c["text"] == "preferred index text" else 0.1 for c in candidates],
            name="candidate-test-ranker",
            scale=self.scale,
            signals={"candidate_test": "used", "rerank_scale": "wrong",
                     "reranker_name": "wrong", "rerank_score": -999, "final_rank": -1,
                     "duplicate_collapse": "wrong"},
        )


def _db(reranker, path=":memory:"):
    return Heartwood(
        path=path,
        tenant="tenant:candidate-test",
        embedder=(_hashing_embed, "test-embedder"),
        reranker=(reranker, "configured-test-ranker"),
    )


# @positive-control(rerank-v2-policy-first)
@pytest.mark.parametrize("mode", [None, "deep"])
def test_recall_reranks_only_policy_visible_candidates(tmp_path, mode):
    ranker = RecordingReranker()
    db = _db(ranker, tmp_path / "memories.db")
    principal = Principal(id="agent:reader", tenant=db.tenant, clearance="internal")
    first = db.remember("query", subject="first", created_by="loader")
    preferred = db.remember(
        "Preferred content", index_text="preferred index text", subject="preferred",
        created_by="loader", policy=Policy(classification="public", pii=True),
        policy_scope="project:test",
    )
    denied = [db.remember(
        "query denied content", subject="denied", created_by="loader", policy=policy,
    ) for policy in (
        Policy(classification="restricted"),
        Policy(roles=("admin",)),
        Policy(role_groups=(("admin",),)),
        Policy(attrs=(("team", "private"),)),
        Policy(visibility="private"),
    )]
    other = db.with_tenant("tenant:other")
    try:
        denied.append(other.remember("query foreign", subject="foreign", created_by="loader"))
    finally:
        other.close()

    def v1(query, texts):
        return np.array([1.0 if text == "query" else 0.0 for text in texts])

    db.reranker = v1
    baseline = db.recall("query", principal=principal, k=2, topc=20)
    assert [r["id"] for r in baseline["results"]] == [first, preferred]
    db.reranker = ranker
    out = db.recall(
        "query", principal=principal, filters={} if mode is None else {"mode": mode},
        k=2, topc=20,
    )
    assert [r["id"] for r in out["results"]] == [preferred, first]
    assert len(ranker.calls) == 1
    query, candidates, context = ranker.calls[0]
    assert query == "query"
    assert context == {
        "tenant": db.tenant, "principal_id": principal.id, "mode": mode or "standard",
    }
    received = {c["id"]: c for c in candidates}
    assert set(received) == {first, preferred}
    assert set(denied).isdisjoint(received)
    assert received[preferred] == {
        "id": preferred, "text": "preferred index text", "classification": "public",
        "pii": True, "policy_scope": "project:test",
    }
    assert received[first] == {
        "id": first, "text": "query", "classification": "internal", "pii": False,
        "policy_scope": "default",
    }
    explain = db.explain_recall(out["recall_id"])
    for rank, result in enumerate(out["results"]):
        signals = explain["ranking_signals"][result["id"]]
        assert signals == result["signals"]
        assert signals["candidate_test"] == "used"
        assert signals["reranker_name"] == "candidate-test-ranker"
        assert signals["rerank_scale"] == "probability"
        assert signals["rerank_score"] == result["score"]
        assert signals["final_rank"] == rank
        assert "duplicate_collapse" not in signals
    db.close()


@pytest.mark.parametrize("scale,normalized", [("probability", 0.9), ("logit", 0.7109)])
def test_typed_recall_uses_candidate_result_scale(scale, normalized):
    db = _db(RecordingReranker(scale))
    preferred = db.remember(
        "Preferred content", index_text="preferred index text", subject="preferred",
        created_by="loader",
    )
    db.remember("query", subject="first", created_by="loader")
    out = db.recall(
        "query", principal=Principal(id="reader", tenant=db.tenant),
        filters={"typed": True}, k=2,
    )
    assert out["results"][0]["id"] == preferred
    signals = out["results"][0]["signals"]
    assert signals["base_normalized"] == normalized
    assert signals["rerank_score"] == 0.9
    assert signals["rerank_scale"] == scale
    db.close()


def test_fusion_passes_only_selected_candidates_in_score_order():
    ranker = RecordingReranker()
    candidates = [{
        "id": str(i), "text": "preferred index text" if i == 2 else "query",
        "classification": "internal", "pii": False, "policy_scope": "default",
    } for i in range(4)]
    ranked = fuse_rerank(
        ranker, "query", candidates,
        {"2": 4, "1": 3, "0": 2, "3": 1}, {"2": 4, "1": 3, "0": 2, "3": 1},
        k=2, topc=2, context={"tenant": "test", "principal_id": "reader", "mode": "standard"},
    )
    assert [c["id"] for c in ranker.calls[0][1]] == ["2", "1"]
    assert [r[0] for r in ranked] == ["2", "1"]


def test_empty_candidate_pool_does_not_invoke_reranker():
    ranker = RecordingReranker()
    assert fuse_rerank(ranker, "query", [], {}, {}) == []
    assert ranker.calls == []


# @positive-control(rerank-v2-result)
@pytest.mark.parametrize("scores,scale", [
    ([], "probability"), ([0.5, 0.6], "logit"), ([[0.5]], "logit"),
    ([float("nan")], "logit"), ([float("inf")], "logit"), ([0.5], "unknown"),
])
def test_invalid_candidate_result_is_rejected(scores, scale):
    class InvalidReranker:
        def rerank_candidates(self, query, candidates, context):
            return RerankResult(scores, "invalid", scale, {})

    with pytest.raises(ValueError):
        fuse_rerank(
            InvalidReranker(), "query", [{"id": "a", "text": "query"}], {"a": 1}, {},
            context={"tenant": "test", "principal_id": "reader", "mode": "standard"},
        )


# @positive-control(rerank-v2-context)
def test_candidate_protocol_requires_context():
    ranker = RecordingReranker()
    with pytest.raises(ValueError, match="requires context"):
        fuse_rerank(ranker, "query", [{"id": "a", "text": "query"}], {"a": 1}, {})
    assert ranker.calls == []
