"""Regression coverage for plaintext persistence in Heartwood's SQLite store."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

import numpy as np

from heartwood import Heartwood
from heartwood.envelope import hash_content

TENANT = "tenant:plaintext-at-rest-control"
SUBJECT = "subject:plaintext-at-rest-control"
POSITIVE_SENTINEL = "HW_POSITIVE_PLAINTEXT_CONTROL_10006706"
ENCRYPTED_ONLY_SENTINEL = "HW_ENCRYPTED_ONLY_CONTROL_10006706"


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
    content = f"{positive_text}\n{ENCRYPTED_ONLY_SENTINEL}"
    return db.remember(
        content,
        subject=SUBJECT,
        created_by="agent:test",
        memory_id=memory_id,
        source={"kind": "test", "uri": "test://plaintext-at-rest"},
        source_ids=("test://plaintext-at-rest",),
        source_spans=source_spans,
    )


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
