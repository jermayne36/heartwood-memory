"""Regression coverage for plaintext persistence in Heartwood's SQLite store."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
from pathlib import Path

import numpy as np

import heartwood.client as client_module
from heartwood import Heartwood, Policy, Principal
from heartwood.consolidation import Cluster, propose_consolidation
from heartwood.contextual_ingest import (
    ContextualDocument,
    default_egress_request_builder,
    ingest_contextual,
)
from heartwood.envelope import hash_content
from heartwood.source_spans import resolve_source_span_text

TENANT = "tenant:plaintext-at-rest-control"
SUBJECT = "subject:plaintext-at-rest-control"
POSITIVE_SENTINEL = "HW_POSITIVE_PLAINTEXT_CONTROL_10006706"
ENCRYPTED_ONLY_SENTINEL = "HW_ENCRYPTED_ONLY_CONTROL_10006706"
CONTEXTUAL_SENTINEL = "HW_CONTEXTUAL_SPAN_CONTROL_10006709"
FALLBACK_SENTINEL = "HW_FALLBACK_SPAN_CONTROL_10006709"
CONSOLIDATION_SENTINEL = "HW_CONSOLIDATION_SPAN_CONTROL_10006709"


def _embed(texts):
    return np.zeros((len(texts), 4), dtype=np.float32)


def _rerank(_query, texts):
    return np.zeros(len(texts), dtype=np.float32)


def _open_db(path: Path) -> Heartwood:
    return Heartwood(
        path=path,
        tenant=TENANT,
        embedder=(_embed, "plaintext-control-embedder"),
        reranker=(_rerank, "plaintext-control-reranker"),
    )


def _checkpoint(db: Heartwood) -> tuple[int, int, int]:
    result = db.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    checkpoint = tuple(int(value) for value in result)
    assert checkpoint[0] == 0, f"WAL checkpoint remained busy: {checkpoint}"
    return checkpoint


def _storage_hits(db_path: Path, sentinel: str) -> tuple[str, ...]:
    needle = sentinel.encode("utf-8")
    paths = (db_path, Path(f"{db_path}-wal"))
    return tuple(path.name for path in paths if path.exists() and needle in path.read_bytes())


def _remember_with_controls(db: Heartwood, *, memory_id: str, source_spans=()) -> str:
    positive_text = ((POSITIVE_SENTINEL + "|") * 1024)
    db.remember(
        ENCRYPTED_ONLY_SENTINEL,
        subject=f"{SUBJECT}:encrypted-only",
        created_by="agent:test",
        memory_id=f"{memory_id}_encrypted_only",
        source={"kind": "test", "uri": "test://encrypted-only"},
    )
    return db.remember(
        positive_text,
        subject=SUBJECT,
        created_by="agent:test",
        memory_id=memory_id,
        source={"kind": "test", "uri": "test://plaintext-at-rest"},
        source_ids=("test://plaintext-at-rest",),
        source_spans=source_spans,
    )


def _principal() -> Principal:
    return Principal(id="agent:plaintext-control", tenant=TENANT, clearance="internal")


def _contextual_document(content: str, memory_id: str) -> ContextualDocument:
    return ContextualDocument(
        content=content,
        subject=SUBJECT,
        created_by="agent:plaintext-control",
        source={"kind": "test", "uri": f"test://{memory_id}"},
        policy=Policy(classification="internal"),
        memory_id=memory_id,
    )


def _context_generator(*, chunk, **_kwargs):
    return {
        "context": f"Governed retrieval context for chunk {chunk.ordinal}.",
        "model_version": "plaintext-control-generator-v1",
    }


def _deny_egress_builder(**kwargs):
    request = default_egress_request_builder(**kwargs)
    request["policy"]["allowed_providers"] = ["blocked-provider"]
    return request


def _assert_raw_span_text_absent(db_path: Path, sentinel: str) -> None:
    hits = _storage_hits(db_path, sentinel)
    assert not hits, f"source-span plaintext persisted in SQLite files: {hits}"


def _assert_persisted_spans_encrypted(db: Heartwood, memory_id: str) -> None:
    row = db.store.conn.execute(
        "SELECT source_spans_json, source_spans_enc FROM memories WHERE id=?",
        (memory_id,),
    ).fetchone()
    assert row is not None
    assert row["source_spans_enc"] is not None
    persisted = json.loads(row["source_spans_json"])
    assert persisted
    assert all("text" not in span for span in persisted)
    assert all(span.get("text_ref") == "encrypted" for span in persisted)

    resolved = db.store.get_meta(memory_id)["source_spans"]
    assert len(resolved) == len(persisted)
    for span in resolved:
        text = resolve_source_span_text(span, db)
        assert isinstance(text, str)
        assert hash_content(text) == span["content_hash"]


# @positive-control(hw-plaintext-at-rest)
def test_plaintext_is_absent_from_sqlite_at_rest_and_after_hard_forget():
    """The plaintext control must fire while the ciphertext-only control stays silent."""

    observations: dict[str, object] = {"sqlite_version": sqlite3.sqlite_version}

    with tempfile.TemporaryDirectory(prefix="heartwood-plaintext-at-rest-") as temp_dir:
        scratch = Path(temp_dir)

        at_rest_path = scratch / "at-rest.db"
        at_rest = _open_db(at_rest_path)
        try:
            observations["secure_delete"] = int(
                at_rest.store.conn.execute("PRAGMA secure_delete").fetchone()[0]
            )
            observations["journal_mode"] = str(
                at_rest.store.conn.execute("PRAGMA journal_mode").fetchone()[0]
            )
            positive_text = ((POSITIVE_SENTINEL + "|") * 1024)
            _remember_with_controls(
                at_rest,
                memory_id="mem_plaintext_at_rest",
                source_spans=(
                    {
                        "source_id": "test://plaintext-at-rest",
                        "span_id": "test://plaintext-at-rest#body",
                        "text": positive_text,
                        "content_hash": hash_content(positive_text),
                    },
                ),
            )
            observations["at_rest_checkpoint"] = _checkpoint(at_rest)
        finally:
            at_rest.close()

        observations["at_rest_positive_hits"] = _storage_hits(
            at_rest_path, POSITIVE_SENTINEL
        )
        observations["at_rest_encrypted_only_hits"] = _storage_hits(
            at_rest_path, ENCRYPTED_ONLY_SENTINEL
        )

        forget_path = scratch / "after-hard-forget.db"
        forget_db = _open_db(forget_path)
        try:
            memory_id = _remember_with_controls(
                forget_db,
                memory_id="mem_plaintext_hard_forget",
            )

            # Seed the deployed legacy shape directly. This keeps the erasure
            # control load-bearing after the normal write path stops persisting
            # source-span text.
            legacy_span = json.dumps(
                [
                    {
                        "source_id": "test://plaintext-at-rest",
                        "span_id": "test://plaintext-at-rest#legacy-body",
                        "text": ((POSITIVE_SENTINEL + "|") * 1024),
                    }
                ]
            )
            forget_db.store.conn.execute(
                "UPDATE memories SET source_spans_json=? WHERE id=?",
                (legacy_span, memory_id),
            )
            forget_db.store.conn.commit()
            observations["legacy_seed_checkpoint"] = _checkpoint(forget_db)
            observations["legacy_seed_positive_hits"] = _storage_hits(
                forget_path, POSITIVE_SENTINEL
            )
            observations["legacy_seed_encrypted_only_hits"] = _storage_hits(
                forget_path, ENCRYPTED_ONLY_SENTINEL
            )

            receipt = forget_db.forget(
                SUBJECT,
                mode="hard",
                actor="agent:test",
                reason="plaintext-at-rest positive control",
            )
            observations["forget_receipt"] = {
                "purged": receipt["purged"],
                "key_shredded": receipt["key_shredded"],
            }
            observations["rows_after_forget"] = int(
                forget_db.store.conn.execute(
                    "SELECT COUNT(*) FROM memories WHERE id=?", (memory_id,)
                ).fetchone()[0]
            )
            # A VACUUM performed by the remediation writes rebuilt pages to the
            # WAL in WAL mode. Checkpoint after forget so the main-file scan sees
            # the post-remediation image rather than the pre-VACUUM image.
            observations["after_forget_checkpoint"] = _checkpoint(forget_db)
        finally:
            forget_db.close()

        observations["after_forget_positive_hits"] = _storage_hits(
            forget_path, POSITIVE_SENTINEL
        )
        observations["after_forget_encrypted_only_hits"] = _storage_hits(
            forget_path, ENCRYPTED_ONLY_SENTINEL
        )

    print("PLAINTEXT_AT_REST_CONTROL " + json.dumps(observations, sort_keys=True))

    failures = []
    if not observations["legacy_seed_positive_hits"]:
        failures.append("legacy positive-control fixture never reached the SQLite files")
    if observations["at_rest_positive_hits"]:
        failures.append("plaintext persisted after remember()")
    if observations["after_forget_positive_hits"]:
        failures.append("plaintext persisted after forget(hard)")
    for phase in ("at_rest", "legacy_seed", "after_forget"):
        if observations[f"{phase}_encrypted_only_hits"]:
            failures.append(f"ciphertext-only control leaked during {phase}")

    assert observations["forget_receipt"] == {"purged": 1, "key_shredded": True}
    assert observations["rows_after_forget"] == 0
    # @fail-closed(hw-plaintext-at-rest)
    assert not failures, "; ".join(failures)


def test_self_referenced_span_resolves_and_degrades_after_hard_forget():
    with tempfile.TemporaryDirectory(prefix="heartwood-span-resolver-") as temp_dir:
        db = _open_db(Path(temp_dir) / "resolver.db")
        try:
            content = "Refund policy allows expedited review for duplicate charges."
            memory_id = db.remember(
                content,
                subject=SUBJECT,
                created_by="agent:test",
                memory_id="mem_span_resolver",
                source_spans=(
                    {
                        "source_id": "test://resolver",
                        "span_id": "test://resolver#body",
                        "text": content,
                        "content_hash": hash_content(content),
                    },
                ),
            )
            span = db.store.get_meta(memory_id)["source_spans"][0]
            assert span["text_ref"] == "self"
            assert "text" not in span
            assert resolve_source_span_text(span, db) == content

            candidate = {
                "candidate_id": "resolver-candidate",
                "source_spans": [span],
                "claims": [
                    {
                        "claim_id": "resolver-claim",
                        "text": content,
                        "source_span_ids": [span["span_id"]],
                    }
                ],
            }
            assert db.assess_faithfulness(candidate)["decision"] == "accepted"

            request = {
                "request_id": "resolver-egress",
                "model": {
                    "runtime": "external",
                    "provider": "openai",
                    "region": "us",
                    "retention": "zero",
                    "training_opt_out": True,
                },
                "policy": {
                    "allow_external_models": True,
                    "allowed_providers": ["openai"],
                    "allowed_regions": ["us"],
                    "require_zero_retention": True,
                    "deny_classifications": [],
                    "deny_pii_labels": [],
                    "human_review_classifications": [],
                },
                "source_spans": [span],
            }
            decision = db.evaluate_egress(request)
            assert decision["payload"][0]["text"] == content

            db.forget(SUBJECT, actor="agent:test", reason="resolver degradation")
            assert resolve_source_span_text(span, db) is None
            assert db.assess_faithfulness(candidate)["decision"] == "needs_human_review"
        finally:
            db.close()


def test_encrypted_span_resolves_for_egress_and_faithfulness_then_degrades():
    with tempfile.TemporaryDirectory(prefix="heartwood-encrypted-span-resolver-") as temp_dir:
        db = _open_db(Path(temp_dir) / "encrypted-resolver.db")
        try:
            span_text = "Refund policy allows expedited review for duplicate charges."
            memory_id = db.remember(
                "Generated policy summary for support agents.",
                subject=f"{SUBJECT}:encrypted-resolver",
                created_by="agent:test",
                memory_id="mem_encrypted_span_resolver",
                source_spans=(
                    {
                        "source_id": "test://encrypted-resolver",
                        "span_id": "test://encrypted-resolver#policy",
                        "text": span_text,
                        "content_hash": hash_content(span_text),
                        "classification": "internal",
                        "pii_labels": [],
                    },
                ),
            )
            span = db.store.get_meta(memory_id)["source_spans"][0]
            assert span["text_ref"] == "encrypted"
            assert "text" not in span
            assert resolve_source_span_text(span, db) == span_text

            request = {
                "request_id": "encrypted-resolver-egress",
                "model": {
                    "runtime": "external",
                    "provider": "openai",
                    "region": "us",
                    "retention": "zero",
                    "training_opt_out": True,
                },
                "policy": {
                    "allow_external_models": True,
                    "allowed_providers": ["openai"],
                    "allowed_regions": ["us"],
                    "require_zero_retention": True,
                    "deny_classifications": [],
                    "deny_pii_labels": [],
                    "human_review_classifications": [],
                },
                "source_spans": [span],
            }
            decision = db.evaluate_egress(request)
            assert decision["decision"] == "external_model_allowed"
            assert decision["payload"][0]["text"] == span_text

            candidate = {
                "candidate_id": "encrypted-resolver-candidate",
                "source_spans": [span],
                "claims": [
                    {
                        "claim_id": "encrypted-resolver-claim",
                        "text": span_text,
                        "source_span_ids": [span["span_id"]],
                    }
                ],
            }
            assert db.assess_faithfulness(candidate)["decision"] == "accepted"

            db.forget(
                f"{SUBJECT}:encrypted-resolver",
                actor="agent:test",
                reason="encrypted resolver degradation",
            )
            assert resolve_source_span_text(span, db) is None
        finally:
            db.close()


def test_source_spans_enc_schema_migration_is_idempotent_for_existing_store():
    with tempfile.TemporaryDirectory(prefix="heartwood-span-schema-") as temp_dir:
        db_path = Path(temp_dir) / "legacy-schema.db"
        db = _open_db(db_path)
        db.close()

        connection = sqlite3.connect(db_path)
        try:
            connection.execute("ALTER TABLE memories DROP COLUMN source_spans_enc")
            connection.commit()
        finally:
            connection.close()

        migrated = _open_db(db_path)
        try:
            columns = {
                str(row["name"])
                for row in migrated.store.conn.execute(
                    "PRAGMA table_info(memories)"
                ).fetchall()
            }
            assert "source_spans_enc" in columns
        finally:
            migrated.close()

        reopened = _open_db(db_path)
        try:
            columns = [
                str(row["name"])
                for row in reopened.store.conn.execute(
                    "PRAGMA table_info(memories)"
                ).fetchall()
            ]
            assert columns.count("source_spans_enc") == 1
        finally:
            reopened.close()


# @positive-control(hw-contextual-span-encryption)
def test_contextual_window_span_text_is_absent_from_sqlite_files():
    with tempfile.TemporaryDirectory(prefix="heartwood-contextual-span-") as temp_dir:
        db_path = Path(temp_dir) / "contextual.db"
        db = _open_db(db_path)
        try:
            content = ((CONTEXTUAL_SENTINEL + " governed retrieval anchors. ") * 96)
            result = ingest_contextual(
                db,
                _contextual_document(content, "doc_contextual_span"),
                generator=_context_generator,
                egress_request_builder=default_egress_request_builder,
                principal=_principal(),
                faithfulness=False,
                target_tokens=500,
                overlap=0,
            )
            assert result.mode == "contextual"
            _checkpoint(db)
            # @fail-closed(hw-contextual-span-encryption)
            _assert_raw_span_text_absent(db_path, CONTEXTUAL_SENTINEL)
            for context_id in result.context_ids:
                _assert_persisted_spans_encrypted(db, context_id)
        finally:
            db.close()
        _assert_raw_span_text_absent(db_path, CONTEXTUAL_SENTINEL)


# @positive-control(hw-fallback-span-encryption)
def test_fallback_whole_file_span_text_is_absent_without_self_span_normalization(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="heartwood-fallback-span-") as temp_dir:
        db_path = Path(temp_dir) / "fallback.db"
        db = _open_db(db_path)
        try:
            content = ((FALLBACK_SENTINEL + " fallback source body. ") * 96)
            monkeypatch.setattr(
                client_module,
                "normalize_self_spans",
                lambda source_spans, **_kwargs: tuple(source_spans),
            )
            result = ingest_contextual(
                db,
                _contextual_document(content, "doc_fallback_span"),
                generator=_context_generator,
                egress_request_builder=_deny_egress_builder,
                principal=_principal(),
                target_tokens=500,
                overlap=0,
            )
            assert result.mode == "fallback"
            _checkpoint(db)
            # @fail-closed(hw-fallback-span-encryption)
            _assert_raw_span_text_absent(db_path, FALLBACK_SENTINEL)
            _assert_persisted_spans_encrypted(db, result.ids[0])
        finally:
            db.close()
        _assert_raw_span_text_absent(db_path, FALLBACK_SENTINEL)


# @positive-control(hw-consolidation-span-encryption)
def test_consolidation_member_span_text_is_absent_from_sqlite_files():
    with tempfile.TemporaryDirectory(prefix="heartwood-consolidation-span-") as temp_dir:
        db_path = Path(temp_dir) / "consolidation.db"
        db = _open_db(db_path)
        try:
            member_text = (
                (CONSOLIDATION_SENTINEL + " refund policy duplicate charge review. ") * 96
            )
            member_ids = tuple(
                db.remember(
                    member_text,
                    subject=SUBJECT,
                    created_by="agent:plaintext-control",
                    created_at=time.time() - (91 * 86400),
                    memory_id=f"consolidation_source_{index}",
                )
                for index in range(3)
            )
            cluster = Cluster(
                tuple(db.store.get_meta(memory_id) for memory_id in member_ids),
                reason="content_hash",
                key="plaintext-control",
            )

            def generator(**kwargs):
                return {
                    "summary": "Refund policy allows review for duplicate charge.",
                    "claims": [
                        {
                            "claim_id": "summary",
                            "text": "Refund policy allows review for duplicate charge.",
                            "source_span_ids": [
                                span["span_id"] for span in kwargs["source_spans"]
                            ],
                        }
                    ],
                    "model_version": "plaintext-control-consolidator-v1",
                }

            proposal = propose_consolidation(
                db,
                cluster,
                generator=generator,
                principal=_principal(),
            )
            assert proposal.cluster_ids == member_ids
            _checkpoint(db)
            # @fail-closed(hw-consolidation-span-encryption)
            _assert_raw_span_text_absent(db_path, CONSOLIDATION_SENTINEL)
            _assert_persisted_spans_encrypted(db, proposal.id)
        finally:
            db.close()
        _assert_raw_span_text_absent(db_path, CONSOLIDATION_SENTINEL)


# @positive-control(hw-nonself-span-encryption)
def test_contextual_and_consolidation_share_one_clean_sqlite_store():
    observations: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="heartwood-nonself-span-") as temp_dir:
        db_path = Path(temp_dir) / "nonself-spans.db"
        db = _open_db(db_path)
        try:
            contextual_content = (
                (CONTEXTUAL_SENTINEL + " governed retrieval anchors. ") * 96
            )
            contextual = ingest_contextual(
                db,
                _contextual_document(contextual_content, "doc_combined_contextual"),
                generator=_context_generator,
                egress_request_builder=default_egress_request_builder,
                principal=_principal(),
                faithfulness=False,
                target_tokens=500,
                overlap=0,
            )
            assert contextual.mode == "contextual"

            member_text = (
                (CONSOLIDATION_SENTINEL + " refund policy duplicate charge review. ") * 96
            )
            member_ids = tuple(
                db.remember(
                    member_text,
                    subject=SUBJECT,
                    created_by="agent:plaintext-control",
                    created_at=time.time() - (91 * 86400),
                    memory_id=f"combined_consolidation_source_{index}",
                )
                for index in range(3)
            )
            cluster = Cluster(
                tuple(db.store.get_meta(memory_id) for memory_id in member_ids),
                reason="content_hash",
                key="combined-plaintext-control",
            )

            def generator(**kwargs):
                return {
                    "summary": "Refund policy allows review for duplicate charge.",
                    "claims": [
                        {
                            "claim_id": "summary",
                            "text": "Refund policy allows review for duplicate charge.",
                            "source_span_ids": [
                                span["span_id"] for span in kwargs["source_spans"]
                            ],
                        }
                    ],
                }

            proposal = propose_consolidation(
                db,
                cluster,
                generator=generator,
                principal=_principal(),
            )
            observations["checkpoint"] = _checkpoint(db)
            observations["rows"] = int(
                db.store.conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
            )
            observations["plaintext_json_rows"] = int(
                db.store.conn.execute(
                    "SELECT COUNT(*) FROM memories WHERE source_spans_json LIKE '%\"text\"%'"
                ).fetchone()[0]
            )
            memory_columns = {
                str(row["name"])
                for row in db.store.conn.execute("PRAGMA table_info(memories)").fetchall()
            }
            observations["encrypted_span_rows"] = (
                int(
                    db.store.conn.execute(
                        "SELECT COUNT(*) FROM memories WHERE source_spans_enc IS NOT NULL"
                    ).fetchone()[0]
                )
                if "source_spans_enc" in memory_columns
                else -1
            )
            observations["contextual_raw_hits"] = len(
                _storage_hits(db_path, CONTEXTUAL_SENTINEL)
            )
            observations["consolidation_raw_hits"] = len(
                _storage_hits(db_path, CONSOLIDATION_SENTINEL)
            )
            wal_path = Path(f"{db_path}-wal")
            observations["wal_bytes"] = wal_path.stat().st_size if wal_path.exists() else 0

            print("NONSELF_SPAN_RAW_SCAN " + json.dumps(observations, sort_keys=True))
            # @fail-closed(hw-nonself-span-encryption)
            assert observations["contextual_raw_hits"] == 0
            assert observations["consolidation_raw_hits"] == 0
            assert observations["plaintext_json_rows"] == 0
            assert observations["wal_bytes"] == 0
            assert observations["encrypted_span_rows"] >= 2

            for context_id in contextual.context_ids:
                _assert_persisted_spans_encrypted(db, context_id)
            _assert_persisted_spans_encrypted(db, proposal.id)
        finally:
            db.close()
