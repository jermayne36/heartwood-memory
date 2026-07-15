"""Phase 2 Area 3 contextual ingestion tests."""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Policy, Principal  # noqa: E402
from heartwood.contextual_ingest import (  # noqa: E402
    CONTEXTUAL_AUX_POLICY_SCOPE,
    ContextualDocument,
    default_egress_request_builder,
    ingest_contextual,
)
from heartwood.envelope import hash_content  # noqa: E402


TENANT = "tenant:contextual"


def _embed(texts):
    vecs = np.zeros((len(texts), 8), dtype=np.float32)
    for i, text in enumerate(texts):
        lowered = text.lower()
        vecs[i, 0] = 1.0
        vecs[i, 1] = float("alpha" in lowered)
        vecs[i, 2] = float("beta" in lowered)
        vecs[i, 3] = float("retrieval" in lowered)
        vecs[i, 4] = float("anchors" in lowered)
        vecs[i, 5] = float("phasebonus" in lowered)
        vecs[i, 6] = float("legacy" in lowered)
        vecs[i, 7] = float("refund" in lowered)
    return vecs


def _rerank(query, texts):
    q = set(query.lower().split())
    return np.asarray([len(q & set(text.lower().split())) for text in texts], dtype=np.float32)


def _db():
    return Heartwood(
        path=":memory:",
        tenant=TENANT,
        embedder=(_embed, "contextual-test-embedder"),
        reranker=(_rerank, "contextual-test-reranker"),
    )


def _reader():
    return Principal(id="agent:reader", tenant=TENANT, clearance="internal")


def _generator(*, chunk, **_kwargs):
    return {
        "context": f"Alpha retrieval anchors phasebonus. {chunk.text.split()[0]}",
        "model_version": "fake-context-generator-v1",
    }


def _document(content: str, memory_id: str = "doc_ctx") -> ContextualDocument:
    return ContextualDocument(
        content=content,
        subject="subject:contextual-doc",
        subject_ids=("subject:contextual-doc", "file:contextual-doc"),
        created_by="agent:importer",
        source={"kind": "markdown", "uri": "markdown://contextual.md", "path": "contextual.md"},
        policy=Policy(classification="internal"),
        memory_id=memory_id,
        policy_scope="ops",
        source_ids=("markdown://contextual.md",),
    )


def test_contextual_ingest_indexes_context_but_recalls_original_with_valid_signature():
    db = _db()
    document = _document(
        "# Alpha\n\n"
        "Alpha retrieval anchors explain governed memory chunks.\n\n"
        "# Beta\n\n"
        "Beta section names phasebonus as a neighboring signal."
    )

    result = ingest_contextual(
        db,
        document,
        generator=_generator,
        egress_request_builder=default_egress_request_builder,
        principal=_reader(),
        target_tokens=7,
        overlap=0,
        support_threshold=0.2,
    )

    assert result.mode == "contextual"
    assert len(result.records) >= 2
    first = result.records[0]
    chunk_meta = db.store.get_meta(first.chunk_id)
    context_meta = db.store.get_meta(first.context_id)
    assert chunk_meta["epistemic"] == "imported-source"
    assert context_meta["epistemic"] == "model-generated"
    assert context_meta["policy_scope"] == CONTEXTUAL_AUX_POLICY_SCOPE
    assert context_meta["review_state"] == "proposed"
    assert db.store.conn.execute(
        "SELECT kind FROM prov_edges WHERE child=? AND parent=?",
        (first.context_id, first.chunk_id),
    ).fetchone()["kind"] == "contextualizes"
    assert db.store.conn.execute(
        "SELECT index_text_enc FROM memories WHERE id=?",
        (first.chunk_id,),
    ).fetchone()["index_text_enc"] is not None

    recall = db.recall(
        "phasebonus retrieval",
        principal=_reader(),
        filters={"method": "lexical"},
        k=5,
    )
    rows = {row["id"]: row for row in recall["results"]}
    assert first.chunk_id in rows
    assert first.context_id not in rows
    recalled = rows[first.chunk_id]
    assert recalled["content"] == first.chunk.text
    assert hash_content(recalled["content"]) == chunk_meta["content_hash"]
    assert recalled["provenance"]["content_hash_match"] is True
    assert recalled["provenance"]["signature_valid"] is True

    legacy_id = db.remember(
        "Legacy null index text byte exact.",
        subject="subject:legacy",
        created_by="agent:legacy",
        memory_id="legacy_null_index",
    )
    assert db.store.conn.execute(
        "SELECT index_text_enc FROM memories WHERE id=?",
        (legacy_id,),
    ).fetchone()["index_text_enc"] is None
    legacy = db.recall(
        "legacy byte exact",
        principal=_reader(),
        filters={"method": "lexical"},
        k=5,
    )
    legacy_row = next(row for row in legacy["results"] if row["id"] == legacy_id)
    assert legacy_row["content"] == "Legacy null index text byte exact."
    assert legacy_row["provenance"]["content_hash_match"] is True
    assert legacy_row["provenance"]["signature_valid"] is True


def test_contextual_ingest_egress_deny_falls_back_to_whole_file():
    def deny_builder(**kwargs):
        request = default_egress_request_builder(**kwargs)
        request["policy"]["allowed_providers"] = ["openai"]
        return request

    db = _db()
    document = _document(
        "# Alpha\n\nAlpha retrieval anchors explain governed memory chunks.",
        memory_id="doc_egress_deny",
    )

    result = ingest_contextual(
        db,
        document,
        generator=_generator,
        egress_request_builder=deny_builder,
        principal=_reader(),
        target_tokens=6,
        overlap=0,
    )

    assert result.mode == "fallback"
    assert result.fallback_reason == "egress:denied"
    assert result.ids == ("doc_egress_deny",)
    assert db.store.get_meta("doc_egress_deny")["epistemic"] == "imported-source"
    assert db.read_content("doc_egress_deny") == document.content
    assert db.store.conn.execute(
        "SELECT COUNT(*) FROM memories WHERE epistemic='model-generated'"
    ).fetchone()[0] == 0


def test_contextual_ingest_faithfulness_reject_falls_back_to_whole_file():
    def unfaithful_generator(**_kwargs):
        return "Customer 999 was approved for a lifetime refund."

    db = _db()
    document = _document(
        "# Refunds\n\nRefund policy says ordinary requests need manual review.",
        memory_id="doc_faithfulness_reject",
    )

    result = ingest_contextual(
        db,
        document,
        generator=unfaithful_generator,
        egress_request_builder=default_egress_request_builder,
        principal=_reader(),
        target_tokens=8,
        overlap=0,
    )

    assert result.mode == "fallback"
    assert result.fallback_reason == "faithfulness:rejected"
    assert db.read_content("doc_faithfulness_reject") == document.content
    assert db.store.conn.execute(
        "SELECT COUNT(*) FROM memories WHERE policy_scope=?",
        (CONTEXTUAL_AUX_POLICY_SCOPE,),
    ).fetchone()[0] == 0


def test_forget_purges_contextual_chunk_and_aux_context():
    db = _db()
    document = _document(
        "# Alpha\n\n"
        "Alpha retrieval anchors explain governed memory chunks.\n\n"
        "# Beta\n\n"
        "Beta section names phasebonus as a neighboring signal.",
        memory_id="doc_forget_context",
    )
    result = ingest_contextual(
        db,
        document,
        generator=_generator,
        egress_request_builder=default_egress_request_builder,
        principal=_reader(),
        target_tokens=7,
        overlap=0,
        support_threshold=0.2,
    )
    chunk_id = result.chunk_ids[0]
    context_id = result.context_ids[0]

    erased = db.forget(document.subject, actor="agent:test", reason="test cascade")

    assert erased["purged"] >= 2
    assert db.store.get_meta(chunk_id) is None
    assert db.store.get_meta(context_id) is None
    assert db.recall("phasebonus retrieval", principal=_reader(), k=5)["results"] == []
