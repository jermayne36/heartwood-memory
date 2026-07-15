"""Phase 2 Area 2 conservative consolidation tests."""
import ast
import os
import sys
import time
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Policy, Principal  # noqa: E402
from heartwood.consolidation import (  # noqa: E402
    MIN_CLUSTER,
    STALE_AGE_DAYS,
    Cluster,
    find_consolidation_clusters,
    is_member_consolidatable,
    is_safe_consolidation_cluster,
    propose_consolidation,
)
from heartwood.review import ReviewState  # noqa: E402


TENANT = "tenant:consolidation"
NOW = 2_000_000_000.0
OLD = time.time() - ((STALE_AGE_DAYS + 1) * 86400.0)


def _embed(texts):
    vecs = np.zeros((len(texts), 8), dtype=np.float32)
    for i, text in enumerate(texts):
        lowered = text.lower()
        vecs[i, 0] = 1.0
        vecs[i, 1] = float("alpha" in lowered)
        vecs[i, 2] = float("beta" in lowered)
        vecs[i, 3] = float("refund" in lowered)
        vecs[i, 4] = float("duplicate" in lowered)
        vecs[i, 5] = float("manual" in lowered)
        vecs[i, 6] = float("review" in lowered)
        vecs[i, 7] = float("lifetime" in lowered)
        norm = np.linalg.norm(vecs[i])
        if norm:
            vecs[i] = vecs[i] / norm
    return vecs


def _rerank(query, texts):
    q = set(query.lower().split())
    return np.asarray([len(q & set(text.lower().split())) for text in texts], dtype=np.float32)


def _db():
    return Heartwood(
        path=":memory:",
        tenant=TENANT,
        embedder=(_embed, "consolidation-test-embedder"),
        reranker=(_rerank, "consolidation-test-reranker"),
    )


def _principal():
    return Principal(id="agent:consolidator", tenant=TENANT, clearance="internal")


def _member(**overrides):
    member = {
        "id": overrides.pop("id", "mem_1"),
        "tenant": TENANT,
        "subject": "subject:alpha",
        "classification": "internal",
        "roles": (),
        "role_groups": (),
        "retention": "decayable",
        "epistemic": "imported-source",
        "truth_status": "source_observed",
        "review_state": None,
        "pii": False,
        "policy_scope": "default",
        "created_at": OLD,
    }
    member.update(overrides)
    return member


def _safe_cluster():
    return [_member(id=f"mem_{index}") for index in range(MIN_CLUSTER)]


def _remember(db, content, memory_id, *, subject="subject:alpha", policy=None,
              epistemic="imported-source", review_state=None, created_at=None):
    return db.remember(
        content,
        subject=subject,
        created_by="agent:test",
        epistemic=epistemic,
        policy=policy or Policy(classification="internal"),
        review_state=review_state,
        created_at=OLD if created_at is None else created_at,
        memory_id=memory_id,
    )


def test_consolidation_module_has_static_additive_only_import_guard():
    source_path = Path(__file__).resolve().parents[1] / "heartwood" / "consolidation.py"
    source = source_path.read_text()
    tree = ast.parse(source)

    forbidden_imports = {
        ("heartwood.client", "forget"),
        ("heartwood.client", "purge"),
        ("heartwood.store", "delete_memory"),
        ("heartwood.store", "delete_subject"),
    }
    imports = set()
    dangerous_attrs = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level == 1:
                module = f"heartwood.{module}"
            for alias in node.names:
                imports.add((module, alias.name))
        if isinstance(node, ast.Attribute) and node.attr in {
            "forget",
            "purge",
            "delete_memory",
            "delete_subject",
        }:
            dangerous_attrs.add(node.attr)

    assert forbidden_imports.isdisjoint(imports)
    assert dangerous_attrs == set()
    assert ".forget(" not in source
    assert ".purge(" not in source
    assert ".delete_memory(" not in source
    assert ".delete_subject(" not in source


def test_find_consolidation_clusters_detects_exact_and_near_duplicates():
    db = _db()
    for index in range(3):
        _remember(
            db,
            "Alpha exact duplicate policy memory.",
            f"exact_{index}",
            subject="subject:exact",
        )
    exact = find_consolidation_clusters(
        db,
        subject="subject:exact",
        sim_threshold=0.99,
        min_cluster=3,
    )
    assert any(cluster.reason == "content_hash" and set(cluster.ids) == {
        "exact_0",
        "exact_1",
        "exact_2",
    } for cluster in exact)

    for index, text in enumerate((
        "Alpha near duplicate memory one.",
        "Alpha near duplicate memory two.",
        "Alpha near duplicate memory three.",
    )):
        _remember(db, text, f"near_{index}", subject="subject:near")
    near = find_consolidation_clusters(
        db,
        subject="subject:near",
        sim_threshold=0.99,
        min_cluster=3,
    )
    assert any(cluster.reason == "near_duplicate" and set(cluster.ids) == {
        "near_0",
        "near_1",
        "near_2",
    } for cluster in near)


def test_safe_consolidation_predicate_matrix():
    assert not is_safe_consolidation_cluster(
        [_member(id="pinned_1", retention="pinned"), *_safe_cluster()[1:]],
        now=NOW,
    )
    assert not is_safe_consolidation_cluster(
        [_member(id="canon_1", epistemic="approved-canonical"), *_safe_cluster()[1:]],
        now=NOW,
    )
    assert not is_safe_consolidation_cluster(
        [_member(id="approved_1", truth_status="human_approved"), *_safe_cluster()[1:]],
        now=NOW,
    )
    assert not is_safe_consolidation_cluster(
        [_member(id="disputed_1", review_state="disputed"), *_safe_cluster()[1:]],
        now=NOW,
    )
    assert not is_safe_consolidation_cluster(
        [_member(id="pii_1", pii=True), *_safe_cluster()[1:]],
        now=NOW,
    )
    assert not is_safe_consolidation_cluster(
        [_member(id="tenant_1", tenant="tenant:other"), *_safe_cluster()[1:]],
        now=NOW,
    )
    assert not is_safe_consolidation_cluster(
        [_member(id="subject_1", subject="subject:other"), *_safe_cluster()[1:]],
        now=NOW,
    )
    assert not is_safe_consolidation_cluster(
        [_member(id="policy_1", classification="restricted"), *_safe_cluster()[1:]],
        now=NOW,
    )
    assert not is_safe_consolidation_cluster(_safe_cluster()[:2], now=NOW)
    assert not is_safe_consolidation_cluster(
        [
            _member(id="generated_1", epistemic="model-generated", review_state="proposed"),
            *_safe_cluster()[1:],
        ],
        now=NOW,
    )
    assert not is_safe_consolidation_cluster(
        [_member(id="fresh_1", created_at=NOW - (10 * 86400.0)), *_safe_cluster()[1:]],
        now=NOW,
    )
    assert is_safe_consolidation_cluster(_safe_cluster(), now=NOW)
    assert not is_safe_consolidation_cluster(
        [_member(id="taint_1", retention="pinned"), *_safe_cluster()[1:]],
        now=NOW,
    )

    assert not is_member_consolidatable(
        _member(epistemic="model-generated", review_state=ReviewState.PROPOSED.value),
        now=NOW,
    )
    assert is_member_consolidatable(
        _member(epistemic="model-generated", review_state=ReviewState.ACCEPTED.value),
        now=NOW,
    )


def test_red_team_unsupported_and_contradicted_summaries_reject_100_percent():
    db = _db()
    for index in range(3):
        _remember(
            db,
            "Customer 42 was denied a one-time refund and sent to manual review.",
            f"source_bad_{index}",
        )
    cluster = Cluster(
        tuple(db.store.get_meta(f"source_bad_{index}") for index in range(3)),
        reason="content_hash",
        key="red-team",
    )

    def unsupported_generator(**_kwargs):
        return {
            "summary": "Customer 999 was approved for a lifetime refund.",
            "claims": [
                {
                    "claim_id": "unsupported",
                    "text": "Customer 999 was approved for a lifetime refund.",
                }
            ],
            "model_version": "fake-red-team-v1",
        }

    def contradicted_generator(**_kwargs):
        return {
            "summary": "Customer 42 was approved for a lifetime refund.",
            "claims": [
                {
                    "claim_id": "contradicted",
                    "text": "Customer 42 was approved for a lifetime refund.",
                }
            ],
            "model_version": "fake-red-team-v1",
        }

    rejected = 0
    for generator in (unsupported_generator, contradicted_generator):
        with pytest.raises(PermissionError, match="faithfulness"):
            propose_consolidation(db, cluster, generator=generator, principal=_principal())
        rejected += 1

    assert rejected == 2
    assert db.store.conn.execute(
        "SELECT COUNT(*) FROM memories WHERE epistemic='model-generated'"
    ).fetchone()[0] == 0


def test_propose_consolidation_births_proposed_summary_with_lineage_and_preserves_sources():
    db = _db()
    source_ids = tuple(
        _remember(
            db,
            "Refund policy allows expedited review for duplicate charge.",
            f"source_good_{index}",
        )
        for index in range(3)
    )
    cluster = Cluster(
        tuple(db.store.get_meta(mem_id) for mem_id in source_ids),
        reason="content_hash",
        key="good",
    )
    before_count = db.store.conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]

    def generator(**kwargs):
        span_ids = [span["span_id"] for span in kwargs["source_spans"]]
        return {
            "summary": "Refund policy allows expedited review for duplicate charge.",
            "claims": [
                {
                    "claim_id": "summary",
                    "text": "Refund policy allows expedited review for duplicate charge.",
                    "source_span_ids": span_ids,
                    "material": True,
                }
            ],
            "model_version": "fake-consolidator-v1",
        }

    proposal = propose_consolidation(
        db,
        cluster,
        generator=generator,
        principal=_principal(),
    )

    meta = db.store.get_meta(proposal.id)
    assert proposal.review_state == ReviewState.PROPOSED.value
    assert meta["review_state"] == ReviewState.PROPOSED.value
    assert proposal.cluster_ids == source_ids
    assert set(db.store.parents(proposal.id)) == set(source_ids)
    assert all(db.store.get_meta(mem_id) is not None for mem_id in source_ids)
    assert db.store.conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0] == before_count + 1
    assert all(proposal.id in db.store.descendants([mem_id]) for mem_id in source_ids)
