"""Verify hard erasure on the live SQLite files, before any connection closes."""

import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from heartwood import Heartwood, LocalKmsCustodian, RawKeyCustodian
from heartwood.importers.markdown import dev_models

SUBJECT = "customer:wal-erasure"
ENTITY = "entity:wal-erasure-positive-control"


def _client(path: Path, custodian) -> Heartwood:
    embedder, reranker = dev_models()
    return Heartwood(path=path, embedder=embedder, reranker=reranker, key_custodian=custodian)


@pytest.mark.parametrize("wrapped", [False, True], ids=["raw", "wrapped"])
def test_hard_forget_removes_bytes_before_close(tmp_path, wrapped):
    db_path = tmp_path / "heartwood.db"
    wal_path = Path(f"{db_path}-wal")
    custodian = LocalKmsCustodian(secrets.token_bytes(32)) if wrapped else RawKeyCustodian()
    with closing(_client(db_path, custodian)) as db:
        kept_id = db.remember("Keep this unrelated note", subject="customer:keep", created_by="agent:test")
        mem_id = db.remember(
            "Sensitive sentinel note", subject=SUBJECT, entities=(ENTITY,), created_by="agent:test",
        )
        envelope, state = db.store.get_key(db.tenant, SUBJECT)
        ciphertext, _ = db.store.get_content_enc(mem_id)
        assert state == "active"
        needles = {"stored DEK": envelope, "ciphertext head": ciphertext[:32], "entity": ENTITY.encode()}
        before = wal_path.read_bytes()
        assert [label for label, needle in needles.items() if needle in before] == list(needles)

        receipt = db.forget(SUBJECT, mode="hard")

        residue = []
        for path in (db_path, wal_path):
            data = path.read_bytes() if path.exists() else b""
            residue.extend(f"{path.name}: {label}" for label, needle in needles.items() if needle in data)
        # @positive-control(erasure-wal-truncated)
        assert residue == [], f"Erased material still present: {', '.join(residue)}"
        assert not wal_path.exists() or wal_path.stat().st_size == 0
        assert receipt["wal_residue_cleared"] is True
        assert db.read_content(kept_id) == "Keep this unrelated note"


@pytest.mark.parametrize("release_on_retry", [False, True], ids=["reader-stays", "reader-releases"])
def test_hard_forget_retries_when_reader_holds_wal_snapshot(tmp_path, release_on_retry):
    db_path = tmp_path / "heartwood.db"
    wal_path = Path(f"{db_path}-wal")
    with closing(_client(db_path, RawKeyCustodian())) as db, closing(sqlite3.connect(db_path)) as reader:
        mem_id = db.remember(
            "Sensitive sentinel note", subject=SUBJECT, entities=(ENTITY,), created_by="agent:test",
        )
        reader.execute("BEGIN")
        assert reader.execute("SELECT id FROM memories WHERE id=?", (mem_id,)).fetchone() == (mem_id,)
        attempts = []

        def trace_checkpoint(statement: str) -> None:
            if "wal_checkpoint" in statement.lower():
                attempts.append(statement)
                if release_on_retry and len(attempts) == 2:
                    reader.rollback()

        db.store.conn.execute("PRAGMA busy_timeout=987")
        db.store.conn.set_trace_callback(trace_checkpoint)
        try:
            receipt = db.forget(SUBJECT, mode="hard")
        finally:
            db.store.conn.set_trace_callback(None)

        assert receipt["key_shredded"] is True
        assert receipt["purged"] == 1
        assert db.store.get_meta(mem_id) is None
        assert receipt["wal_residue_cleared"] is release_on_retry
        assert len(attempts) >= 2
        assert db.store.conn.execute("PRAGMA busy_timeout").fetchone()[0] == 987
        assert (ENTITY.encode() in wal_path.read_bytes()) is not release_on_retry
