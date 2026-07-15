"""Serve-time mirror-family duplicate-collapse regressions."""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.retrieval import _hashing_embed, fuse_rerank, tokenize  # noqa: E402


TENANT = "tenant:recall-dedup"


def _maps(candidates):
    count = len(candidates)
    return (
        {candidate["id"]: float(count - index) for index, candidate in enumerate(candidates)},
        {candidate["id"]: float(count - index) for index, candidate in enumerate(candidates)},
    )


def _reranker_for(scores):
    def rerank(_query, texts):
        return np.array([scores[text] for text in texts], dtype=np.float32)

    return rerank


def _fixture_candidates():
    return [
        {"id": "team", "text": "team mirror"},
        {"id": "memory", "text": "memory mirror"},
        {"id": "next", "text": "next distinct"},
    ]


def test_equal_score_mirror_pair_prefers_memory_and_backfills_slot():
    candidates = _fixture_candidates()
    dense_map, lexical_map = _maps(candidates)
    ranked = fuse_rerank(
        _reranker_for({
            "team mirror": 1.0,
            "memory mirror": 1.0,
            "next distinct": 0.5,
        }),
        "mirror query",
        candidates,
        dense_map,
        lexical_map,
        k=2,
        topc=3,
        collapse_keys={"team": "mirror:shared.md", "memory": "mirror:shared.md"},
        precedence={"team": 1, "memory": 0},
    )

    assert [item[0] for item in ranked] == ["memory", "next"]
    assert ranked[0][2]["duplicate_collapse"] == {
        "reason": "mirror-family-source-key",
        "collapse_key": "mirror:shared.md",
        "kept_id": "memory",
        "collapsed_ids": ["team"],
    }
    assert [item[2]["final_rank"] for item in ranked] == [0, 1]


def test_drifted_pair_keeps_higher_cross_encoder_score():
    candidates = _fixture_candidates()
    dense_map, lexical_map = _maps(candidates)
    ranked = fuse_rerank(
        _reranker_for({
            "team mirror": 0.9,
            "memory mirror": 0.8,
            "next distinct": 0.7,
        }),
        "mirror query",
        candidates,
        dense_map,
        lexical_map,
        k=2,
        topc=3,
        collapse_keys={"team": "mirror:shared.md", "memory": "mirror:shared.md"},
        precedence={"team": 1, "memory": 0},
    )

    assert [item[0] for item in ranked] == ["team", "next"]
    assert ranked[0][2]["duplicate_collapse"]["collapsed_ids"] == ["memory"]


def test_none_collapse_keys_preserves_pre_collapse_output():
    candidates = _fixture_candidates()
    dense_map, lexical_map = _maps(candidates)
    ranked = fuse_rerank(
        _reranker_for({
            "team mirror": 0.9,
            "memory mirror": 0.8,
            "next distinct": 0.7,
        }),
        "mirror query",
        candidates,
        dense_map,
        lexical_map,
        k=2,
        topc=3,
    )

    assert [item[0] for item in ranked] == ["team", "memory"]
    assert all("duplicate_collapse" not in item[2] for item in ranked)


def test_pool_exhaustion_returns_fewer_than_k_without_duplicates():
    candidates = _fixture_candidates()[:2]
    dense_map, lexical_map = _maps(candidates)
    ranked = fuse_rerank(
        _reranker_for({"team mirror": 1.0, "memory mirror": 1.0}),
        "mirror query",
        candidates,
        dense_map,
        lexical_map,
        k=3,
        topc=3,
        collapse_keys={"team": "mirror:shared.md", "memory": "mirror:shared.md"},
        precedence={"team": 1, "memory": 0},
    )

    assert [item[0] for item in ranked] == ["memory"]


def test_equal_score_collapse_is_deterministic():
    candidates = _fixture_candidates()
    dense_map, lexical_map = _maps(candidates)
    kwargs = {
        "k": 2,
        "topc": 3,
        "collapse_keys": {"team": "mirror:shared.md", "memory": "mirror:shared.md"},
        "precedence": {"team": 1, "memory": 0},
    }
    reranker = _reranker_for({
        "team mirror": 1.0,
        "memory mirror": 1.0,
        "next distinct": 0.5,
    })

    first = fuse_rerank(
        reranker,
        "mirror query",
        candidates,
        dense_map,
        lexical_map,
        **kwargs,
    )
    second = fuse_rerank(
        reranker,
        "mirror query",
        candidates,
        dense_map,
        lexical_map,
        **kwargs,
    )

    assert first == second


def _lexical_reranker(query, texts):
    query_tokens = set(tokenize(query))
    return np.array([
        len(query_tokens & set(tokenize(text)))
        for text in texts
    ], dtype=np.float32)


def _db_with_mirrors():
    db = Heartwood(
        path=":memory:",
        tenant=TENANT,
        embedder=(_hashing_embed, "test-hashing-embedder"),
        reranker=(_lexical_reranker, "test-lexical-reranker"),
    )
    team_source = "markdown://team-memory/shared_policy.md"
    memory_source = "markdown://memory/shared_policy.md"
    team_id = db.remember(
        "Shared recall policy mirror content.",
        subject="mirror:team",
        created_by="agent:test",
        source={"kind": "markdown", "uri": team_source},
        source_ids=(team_source,),
    )
    memory_id = db.remember(
        "Shared recall policy mirror content.",
        subject="mirror:memory",
        created_by="agent:test",
        source={"kind": "markdown", "uri": memory_source},
        source_ids=(memory_source,),
    )
    unique_id = db.remember(
        "Shared recall policy unique follow-up.",
        subject="mirror:unique",
        created_by="agent:test",
        source={"kind": "markdown", "uri": "markdown://memory/unique_policy.md"},
        source_ids=("markdown://memory/unique_policy.md",),
    )
    return db, team_id, memory_id, unique_id


def _principal():
    return Principal(id="agent:test", tenant=TENANT, clearance="internal")


def test_client_collapses_hybrid_lexical_and_typed_paths_with_explain_receipt():
    db, team_id, memory_id, unique_id = _db_with_mirrors()

    for filters in ({}, {"method": "lexical"}, {"typed": True}):
        out = db.recall(
            "shared recall policy",
            principal=_principal(),
            filters=filters,
            k=3,
            topc=3,
        )
        result_ids = [result["id"] for result in out["results"]]
        assert set(result_ids) == {memory_id, unique_id}
        assert team_id not in result_ids
        explain = db.explain_recall(out["recall_id"])
        assert explain["duplicate_collapses"] == [{
            "reason": "mirror-family-source-key",
            "collapse_key": "mirror:shared_policy.md",
            "kept_id": memory_id,
            "collapsed_ids": [team_id],
        }]
