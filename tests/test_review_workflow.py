"""Phase 2 Area 6 review-state workflow tests."""
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.review import LEGAL_TRANSITIONS, ReviewState, validate_transition  # noqa: E402


TENANT = "tenant:review"


def _embed(texts):
    vecs = np.zeros((len(texts), 6), dtype=np.float32)
    for i, text in enumerate(texts):
        lowered = text.lower()
        vecs[i, 0] = 1.0
        vecs[i, 1] = float("alpha" in lowered)
        vecs[i, 2] = float("beta" in lowered)
        vecs[i, 3] = float("policy" in lowered)
        vecs[i, 4] = float("generated" in lowered)
        vecs[i, 5] = float("legacy" in lowered)
    return vecs


def _rerank(query, texts):
    q = set(query.lower().split())
    return np.asarray([len(q & set(text.lower().split())) for text in texts], dtype=np.float32)


def _db():
    return Heartwood(
        path=":memory:",
        tenant=TENANT,
        embedder=(_embed, "test-embedder"),
        reranker=(_rerank, "test-reranker"),
    )


def _reviewer():
    return Principal(id="user:reviewer", tenant=TENANT, roles=("reviewer",), clearance="internal")


def _approver():
    return Principal(id="user:approver", tenant=TENANT, roles=("approver",), clearance="internal")


def _reader():
    return Principal(id="user:reader", tenant=TENANT, clearance="internal")


def _expect_raises(exc_type, fn, message: str):
    try:
        fn()
        raise AssertionError(message)
    except exc_type:
        return


def test_review_state_machine_legal_illegal_edges_and_role_enforcement():
    reviewer = _reviewer()
    all_states = set(ReviewState)

    for frm, legal_targets in LEGAL_TRANSITIONS.items():
        for target in legal_targets:
            assert validate_transition(frm, target.value, reviewer) == target.value

        for target in all_states - legal_targets:
            _expect_raises(
                ValueError,
                lambda frm=frm, target=target: validate_transition(frm, target, reviewer),
                f"{frm.value}->{target.value} should be illegal",
            )

    no_role = Principal(id="user:reader", tenant=TENANT, clearance="internal")
    _expect_raises(
        PermissionError,
        lambda: validate_transition(ReviewState.PROPOSED, ReviewState.ACCEPTED, no_role),
        "review transitions must require a review role",
    )
    _expect_raises(
        ValueError,
        lambda: validate_transition(None, ReviewState.ACCEPTED, reviewer),
        "NULL review_state rows are not in the review workflow",
    )


def test_transition_review_cas_queue_and_audit():
    db = _db()
    mem_id = db.remember(
        "Generated alpha policy summary.",
        subject="subject:alpha",
        created_by="agent:test",
        epistemic="model-generated",
        review_state=ReviewState.PROPOSED.value,
    )

    assert [row["id"] for row in db.store.review_queue(TENANT, ReviewState.PROPOSED)] == [mem_id]

    stale_win = db.store.update_review_state(
        mem_id,
        ReviewState.ACCEPTED.value,
        expected_from=ReviewState.PROPOSED.value,
    )
    stale_loss = db.store.update_review_state(
        mem_id,
        ReviewState.REJECTED.value,
        expected_from=ReviewState.PROPOSED.value,
    )
    assert stale_win is True
    assert stale_loss is False
    assert db.store.get_meta(mem_id)["review_state"] == ReviewState.ACCEPTED.value

    db.store.update_review_state(
        mem_id,
        ReviewState.DISPUTED.value,
        expected_from=ReviewState.ACCEPTED.value,
    )
    result = db.transition_review(
        mem_id,
        ReviewState.REJECTED.value,
        principal=_reviewer(),
        reason="unsupported edge case",
    )
    assert result == {
        "id": mem_id,
        "from": ReviewState.DISPUTED.value,
        "to": ReviewState.REJECTED.value,
    }
    actions = [row["action"] for row in db.store.iter_audit()]
    assert "review_transition" in actions


def test_transition_review_wrapper_rejects_illegal_no_role_and_cas_miss():
    db = _db()
    mem_id = db.remember(
        "Generated alpha policy summary.",
        subject="subject:alpha",
        created_by="agent:test",
        epistemic="model-generated",
        review_state=ReviewState.PROPOSED.value,
    )

    _expect_raises(
        ValueError,
        lambda: db.transition_review(mem_id, ReviewState.PROPOSED.value, principal=_reviewer()),
        "public transition wrapper should reject illegal self-transition",
    )
    _expect_raises(
        PermissionError,
        lambda: db.transition_review(mem_id, ReviewState.ACCEPTED.value, principal=_reader()),
        "public transition wrapper should reject principals without review roles",
    )

    original_update = db.store.update_review_state

    def stale_update(mem_id_arg, to_state, *, expected_from):
        original_update(mem_id_arg, ReviewState.ACCEPTED.value, expected_from=expected_from)
        return False

    db.store.update_review_state = stale_update
    try:
        _expect_raises(
            RuntimeError,
            lambda: db.transition_review(mem_id, ReviewState.REJECTED.value, principal=_reviewer()),
            "public transition wrapper should surface CAS misses",
        )
    finally:
        db.store.update_review_state = original_update


def test_recall_filter_keeps_null_and_proposed_visible_with_hide_opt_in():
    db = _db()
    legacy_id = db.remember(
        "Alpha legacy policy memory stays visible.",
        subject="subject:alpha",
        created_by="agent:test",
        created_at=1.0,
    )
    baseline = db.recall("alpha policy", principal=_reader(), k=5)
    baseline_ids = [row["id"] for row in baseline["results"]]
    assert baseline_ids == [legacy_id]
    assert baseline["results"][0]["review_state"] is None
    assert db.explain_recall(baseline["recall_id"])["review_states"] == {legacy_id: None}

    generated_id = db.remember(
        "Alpha generated policy memory is pending review.",
        subject="subject:alpha",
        created_by="agent:test",
        epistemic="model-generated",
        review_state=ReviewState.PROPOSED.value,
        created_at=2.0,
    )
    default_recall = db.recall("alpha policy generated", principal=_reader(), k=5)
    default_ids = {row["id"] for row in default_recall["results"]}
    assert default_ids == {legacy_id, generated_id}
    assert {
        row["id"]: row["review_badge"] for row in default_recall["results"]
    }[generated_id] == "unreviewed"

    hide_until_approved = db.recall(
        "alpha policy generated",
        principal=_reader(),
        filters={"hide_review_states": [ReviewState.PROPOSED.value]},
        k=5,
    )
    assert [row["id"] for row in hide_until_approved["results"]] == baseline_ids


def test_superseded_is_hidden_from_default_recall_with_explicit_opt_in():
    """`transition_review` leaves `indexed` set, so recall must hide the retired row.

    Superseded is terminal (LEGAL_TRANSITIONS) and `approve` refuses it, so a
    superseded record is never current truth and must not be returned by default.
    """
    db = _db()
    current_id = db.remember(
        "Alpha policy memory, current revision.",
        subject="subject:alpha",
        created_by="agent:test",
        review_state=ReviewState.ACCEPTED.value,
        created_at=1.0,
    )
    retired_id = db.remember(
        "Alpha policy memory, prior revision awaiting supersession.",
        subject="subject:alpha",
        created_by="agent:test",
        review_state=ReviewState.ACCEPTED.value,
        created_at=2.0,
    )
    both = db.recall("alpha policy memory revision", principal=_reader(), k=5)
    assert {row["id"] for row in both["results"]} == {current_id, retired_id}

    db.transition_review(retired_id, ReviewState.SUPERSEDED.value, _reviewer())
    # The governance path only writes review_state; the row stays indexed.
    assert db.store.get_meta(retired_id)["review_state"] == ReviewState.SUPERSEDED.value
    assert db.store.get_meta(retired_id)["indexed"]

    default_recall = db.recall("alpha policy memory revision", principal=_reader(), k=5)
    assert [row["id"] for row in default_recall["results"]] == [current_id]
    assert ReviewState.SUPERSEDED.value in db.explain_recall(
        default_recall["recall_id"]
    )["hidden_review_states"]

    audit_view = db.recall(
        "alpha policy memory revision",
        principal=_reader(),
        filters={"include_review_states": [ReviewState.SUPERSEDED.value]},
        k=5,
    )
    assert {row["id"] for row in audit_view["results"]} == {current_id, retired_id}


def test_remember_generated_births_proposed_and_default_recall_badges_it():
    db = _db()
    span = {
        "span_id": "policy#1",
        "source_id": "doc://policy",
        "classification": "internal",
        "pii_labels": [],
        "text": "Beta policy says generated summaries require review.",
    }
    stored = db.remember_generated(
        "Beta policy says generated summaries require review.",
        subject="subject:beta",
        created_by="agent:generator",
        source_spans=[span],
        claims=[
            {
                "claim_id": "claim_1",
                "text": "Beta policy says generated summaries require review.",
                "source_span_ids": ["policy#1"],
                "material": True,
            }
        ],
    )
    assert db.store.get_meta(stored["id"])["review_state"] == ReviewState.PROPOSED.value
    default_recall = db.recall("beta generated summaries", principal=_reader(), k=5)
    assert [row["id"] for row in default_recall["results"]] == [stored["id"]]
    assert default_recall["results"][0]["review_badge"] == "unreviewed"
    opt_in_hide = db.recall(
        "beta generated summaries",
        principal=_reader(),
        filters={"hide_proposed": True},
        k=5,
    )
    assert opt_in_hide["results"] == []


def test_approve_requires_accepted_or_null_review_state():
    db = _db()
    proposed_id = db.remember(
        "Generated alpha policy summary.",
        subject="subject:alpha",
        created_by="agent:test",
        epistemic="model-generated",
        review_state=ReviewState.PROPOSED.value,
    )
    _expect_raises(
        PermissionError,
        lambda: db.approve(proposed_id, _approver()),
        "approve should reject proposed rows",
    )
    assert db.store.get_meta(proposed_id)["epistemic"] == "model-generated"

    null_id = db.remember(
        "Imported alpha source can be approved directly.",
        subject="subject:alpha-null",
        created_by="agent:test",
        epistemic="imported-source",
    )
    db.approve(null_id, _approver())
    assert db.store.get_meta(null_id)["epistemic"] == "approved-canonical"

    accepted_id = db.remember(
        "Accepted generated alpha summary can become canonical.",
        subject="subject:alpha-accepted",
        created_by="agent:test",
        epistemic="model-generated",
        review_state=ReviewState.ACCEPTED.value,
    )
    db.approve(accepted_id, _approver())
    assert db.store.get_meta(accepted_id)["epistemic"] == "approved-canonical"


def test_old_schema_db_migrates_review_columns_and_keeps_legacy_rows_visible():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        current_path = root / "current.db"
        old_path = root / "old.db"
        current = Heartwood(
            path=str(current_path),
            tenant=TENANT,
            embedder=(_embed, "test-embedder"),
            reranker=(_rerank, "test-reranker"),
        )
        legacy_id = current.remember(
            "Alpha legacy policy memory survives old schema migration.",
            subject="subject:legacy-old",
            created_by="agent:test",
            memory_id="legacy_old_schema",
        )
        current.close()
        _copy_without_review_columns(current_path, old_path)

        migrated = Heartwood(
            path=str(old_path),
            tenant=TENANT,
            embedder=(_embed, "test-embedder"),
            reranker=(_rerank, "test-reranker"),
        )
        try:
            columns = {
                row["name"]
                for row in migrated.store.conn.execute("PRAGMA table_info(memories)").fetchall()
            }
            assert {"review_state", "index_text_enc"} <= columns
            meta = migrated.store.get_meta(legacy_id)
            assert meta["review_state"] is None
            row = migrated.store.conn.execute(
                "SELECT review_state, index_text_enc FROM memories WHERE id=?",
                (legacy_id,),
            ).fetchone()
            assert row["review_state"] is None
            assert row["index_text_enc"] is None
            recall = migrated.recall("alpha legacy policy", principal=_reader(), k=5)
            assert [row["id"] for row in recall["results"]] == [legacy_id]
            assert recall["results"][0]["review_state"] is None
            assert recall["results"][0]["content"] == (
                "Alpha legacy policy memory survives old schema migration."
            )
        finally:
            migrated.close()


def _copy_without_review_columns(source_path: Path, old_path: Path) -> None:
    source = sqlite3.connect(source_path)
    source.row_factory = sqlite3.Row
    target = sqlite3.connect(old_path)
    target.row_factory = sqlite3.Row
    try:
        tables = source.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        for table in tables:
            sql = table["sql"]
            if table["name"] == "memories":
                sql = sql.replace("review_state TEXT, index_text_enc BLOB,\n  ", "")
            target.execute(sql)

        for table in tables:
            name = table["name"]
            source_cols = [
                row["name"] for row in source.execute(f"PRAGMA table_info({name})").fetchall()
            ]
            target_cols = [
                row["name"] for row in target.execute(f"PRAGMA table_info({name})").fetchall()
            ]
            common_cols = [column for column in source_cols if column in target_cols]
            selected = ", ".join(common_cols)
            placeholders = ", ".join("?" for _ in common_cols)
            for row in source.execute(f"SELECT {selected} FROM {name}").fetchall():
                target.execute(
                    f"INSERT INTO {name} ({selected}) VALUES ({placeholders})",
                    tuple(row[column] for column in common_cols),
                )
        target.commit()
    finally:
        source.close()
        target.close()
