"""Hard erasure stays final while another process writes to the same store.

The documented importer-plus-daemon deployment opens one store from two
processes. Each test here does the same: a hook in this process starts a second
OS process at one exact point inside a write or an erasure, so the interleaving
is deterministic instead of timing-dependent.
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from heartwood import Heartwood, LocalKmsCustodian  # noqa: E402
from heartwood.importers.markdown import dev_models  # noqa: E402
from heartwood.key_lifecycle import rewrap_tenant_keys  # noqa: E402
from heartwood.store import load_sqlite_vec  # noqa: E402

TENANT = "tenant:concurrent-erasure"
CUSTODY_ROOT_HEX = (bytes([59]) * 32).hex()
CUSTODY_KEY_ID = "concurrent-erasure-root-v1"
PEER_TIMEOUT_SECONDS = 120

# Runs in the second process: opens the same store with the same custody root,
# performs one remember or hard forget, and prints a JSON result line.
_PEER = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from heartwood import Heartwood, LocalKmsCustodian
from heartwood.importers.markdown import dev_models
spec = json.loads(sys.argv[3])
embedder, reranker = dev_models()
custodian = LocalKmsCustodian(
    bytes.fromhex(spec["root"]), key_id=spec["key_id"], retention_floor_seconds=0,
)
db = Heartwood(path=sys.argv[2], tenant=spec["tenant"], embedder=embedder,
               reranker=reranker, index=spec["index"], key_custodian=custodian)
try:
    if spec["op"] == "forget":
        out = db.forget(spec["subject"], mode="hard", actor="agent:peer-eraser",
                        reason="concurrency test")
        result = {"key_shredded": out["key_shredded"], "purged": out["purged"]}
    else:
        mem_id = db.remember(spec["content"], subject=spec["subject"],
                             created_by="agent:peer-writer",
                             derived_from=tuple(spec["derived_from"]))
        result = {"id": mem_id}
finally:
    db.close()
print(json.dumps(result))
"""


def _client(db_path: Path, *, index: str = "numpy") -> Heartwood:
    embedder, reranker = dev_models()
    custodian = LocalKmsCustodian(
        bytes.fromhex(CUSTODY_ROOT_HEX), key_id=CUSTODY_KEY_ID, retention_floor_seconds=0,
    )
    return Heartwood(path=db_path, tenant=TENANT, embedder=embedder, reranker=reranker,
                     index=index, key_custodian=custodian)


def _peer(db_path: Path, op: str, subject: str, *, content: str = "",
          derived_from: tuple[str, ...] = (), index: str = "numpy") -> dict:
    spec = {
        "op": op, "subject": subject, "content": content,
        "derived_from": list(derived_from), "index": index, "tenant": TENANT,
        "root": CUSTODY_ROOT_HEX, "key_id": CUSTODY_KEY_ID,
    }
    done = subprocess.run(
        [sys.executable, "-c", _PEER, str(ROOT), str(db_path), json.dumps(spec)],
        capture_output=True, text=True, timeout=PEER_TIMEOUT_SECONDS,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def _before_first_call(owner, name: str, action) -> list[bool]:
    """Run ``action`` once, just before the first call to ``owner.name``."""
    real = getattr(owner, name)
    fired: list[bool] = []

    def wrapper(*args, **kwargs):
        if not fired:
            fired.append(True)
            action()
        return real(*args, **kwargs)

    setattr(owner, name, wrapper)
    return fired


def _after_first_call(owner, name: str, action) -> list[bool]:
    """Run ``action`` once, just after the first call to ``owner.name`` returns."""
    real = getattr(owner, name)
    fired: list[bool] = []

    def wrapper(*args, **kwargs):
        result = real(*args, **kwargs)
        if not fired:
            fired.append(True)
            action()
        return result

    setattr(owner, name, wrapper)
    return fired


def _after_key_found_missing(store, subject: str, action) -> list[bool]:
    """Run ``action`` once, right after a key lookup finds no key for ``subject``."""
    real = store.get_key
    fired: list[bool] = []

    def get_key(tenant, looked_up):
        found = real(tenant, looked_up)
        if looked_up == subject and found == (None, None) and not fired:
            fired.append(True)
            action()
        return found

    store.get_key = get_key
    return fired


def _query(db_path: Path, sql: str, args: tuple = ()) -> list[tuple]:
    with closing(sqlite3.connect(db_path)) as conn:
        return conn.execute(sql, args).fetchall()


def _rows_naming(db_path: Path, subject: str) -> list[str]:
    """Memory ids whose primary subject or any subject_ids alias is ``subject``."""
    return [row[0] for row in _query(
        db_path,
        "SELECT id FROM memories WHERE subject=? OR EXISTS (SELECT 1 FROM "
        "json_each(COALESCE(memories.subject_ids_json, '[]')) WHERE value=?) ORDER BY id",
        (subject, subject),
    )]


def _row_exists(db_path: Path, mem_id: str) -> bool:
    return bool(_query(db_path, "SELECT 1 FROM memories WHERE id=?", (mem_id,)))


def _lineage(db_path: Path, subject: str) -> list[str]:
    return [row[0] for row in _query(
        db_path,
        "SELECT artifact_id FROM deletion_lineage WHERE tenant=? AND subject=?",
        (TENANT, subject),
    )]


def _key_state(db_path: Path, subject: str) -> list[tuple]:
    return _query(
        db_path,
        "SELECT state, dek IS NULL FROM keys WHERE tenant=? AND subject=?",
        (TENANT, subject),
    )


def _vector_ids(db_path: Path) -> list[str]:
    sqlite_vec = pytest.importorskip("sqlite_vec")
    with closing(sqlite3.connect(db_path)) as conn:
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
        try:
            return [row[0] for row in conn.execute("SELECT memid FROM heartwood_vec")]
        except sqlite3.OperationalError:
            return []


def _assert_erased(db_path: Path, subject: str) -> None:
    assert _rows_naming(db_path, subject) == []
    assert _lineage(db_path, subject) == []
    assert _key_state(db_path, subject) == [("shredded", 1)]


# -- a write that overlaps an erasure -------------------------------------- #
# @positive-control(erasure-final-for-writes)
def test_write_in_flight_when_another_process_erases_is_refused(tmp_path):
    db_path, subject = tmp_path / "heartwood.db", "customer:in-flight"
    writer = _client(db_path)
    try:
        writer.remember("first fact", subject=subject, created_by="agent:writer")
        fired = _before_first_call(
            writer.cipher, "encrypt", lambda: _peer(db_path, "forget", subject),
        )
        with pytest.raises(KeyError, match="has been erased"):
            writer.remember("second fact, prepared while erasure ran", subject=subject,
                            created_by="agent:writer")
        assert fired
    finally:
        writer.close()
    _assert_erased(db_path, subject)


def test_erasure_of_a_new_subject_is_not_undone_by_its_first_write(tmp_path):
    db_path, subject = tmp_path / "heartwood.db", "customer:new-subject"
    writer = _client(db_path)
    try:
        fired = _after_key_found_missing(
            writer.store, subject, lambda: _peer(db_path, "forget", subject),
        )
        with pytest.raises(KeyError, match="has been erased"):
            writer.remember("first fact for a subject erased mid-write", subject=subject,
                            created_by="agent:writer")
        assert fired
    finally:
        writer.close()
    _assert_erased(db_path, subject)


def test_write_naming_an_alias_erased_mid_write_is_refused(tmp_path):
    db_path, alias = tmp_path / "heartwood.db", "customer:alias"
    writer = _client(db_path)
    try:
        fired = _before_first_call(
            writer.cipher, "encrypt", lambda: _peer(db_path, "forget", alias),
        )
        with pytest.raises(KeyError, match="customer:alias has been erased"):
            writer.remember("fact naming an erased alias", subject="customer:primary",
                            subject_ids=("customer:primary", alias),
                            created_by="agent:writer")
        assert fired
    finally:
        writer.close()
    _assert_erased(db_path, alias)


def test_write_naming_an_already_erased_alias_is_refused(tmp_path):
    db = _client(tmp_path / "heartwood.db")
    try:
        db.forget("customer:alias", mode="hard", actor="agent:eraser", reason="test")
        with pytest.raises(KeyError, match="customer:alias has been erased"):
            db.remember("fact naming an erased alias", subject="customer:primary",
                        subject_ids=("customer:primary", "customer:alias"),
                        created_by="agent:writer")
        assert _rows_naming(tmp_path / "heartwood.db", "customer:primary") == []
    finally:
        db.close()


def test_derived_write_whose_parent_is_erased_mid_write_is_refused(tmp_path):
    db_path = tmp_path / "heartwood.db"
    writer = _client(db_path)
    try:
        parent = writer.remember("parent fact", subject="customer:parent",
                                 created_by="agent:writer")
        fired = _before_first_call(
            writer.cipher, "encrypt", lambda: _peer(db_path, "forget", "customer:parent"),
        )
        with pytest.raises(RuntimeError, match="derived_from parent was removed"):
            writer.remember("summary of the parent", subject="summary:derived",
                            created_by="agent:writer", derived_from=(parent,))
        assert fired
    finally:
        writer.close()
    _assert_erased(db_path, "customer:parent")
    assert _rows_naming(db_path, "summary:derived") == []


# -- an erasure that overlaps a write -------------------------------------- #
# @positive-control(erasure-purge-after-shred)
def test_write_committed_before_the_key_shred_is_purged(tmp_path):
    db_path, subject = tmp_path / "heartwood.db", "customer:late-commit"
    eraser = _client(db_path)
    late: dict = {}
    try:
        eraser.remember("first fact", subject=subject, created_by="agent:writer")
        fired = _before_first_call(eraser.keys, "shred", lambda: late.update(_peer(
            db_path, "remember", subject, content="committed after the erasure selected rows",
        )))
        receipt = eraser.forget(subject, mode="hard", actor="agent:eraser", reason="test")
        assert fired
    finally:
        eraser.close()
    assert receipt["purged"] == 2
    assert not _row_exists(db_path, late["id"])
    _assert_erased(db_path, subject)


def test_derived_write_committed_between_shred_and_purge_is_purged(tmp_path):
    db_path, subject = tmp_path / "heartwood.db", "customer:parent"
    eraser = _client(db_path)
    child: dict = {}
    try:
        parent = eraser.remember("parent fact", subject=subject, created_by="agent:writer")
        real_shred = eraser.keys.shred

        def shred_then_derive(tenant, erased):
            real_shred(tenant, erased)
            child.update(_peer(db_path, "remember", "summary:derived",
                               content="summary derived from the parent",
                               derived_from=(parent,)))

        eraser.keys.shred = shred_then_derive
        receipt = eraser.forget(subject, mode="hard", actor="agent:eraser", reason="test")
    finally:
        eraser.close()
    assert child, "the derived write did not run"
    assert not _row_exists(db_path, child["id"])
    assert (receipt["purged"], receipt["cascade"]) == (2, 1)
    _assert_erased(db_path, subject)


# -- key creation and key rewrap -------------------------------------------- #
def test_two_writers_creating_one_subject_key_keep_both_rows_readable(tmp_path):
    db_path, subject = tmp_path / "heartwood.db", "customer:shared-new"
    writer = _client(db_path)
    peer: dict = {}
    try:
        fired = _after_key_found_missing(writer.store, subject, lambda: peer.update(
            _peer(db_path, "remember", subject, content="fact written by the peer"),
        ))
        mine = writer.remember("fact written here", subject=subject, created_by="agent:writer")
        assert fired
    finally:
        writer.close()
    reader = _client(db_path)
    try:
        assert reader.read_content(peer["id"]) == "fact written by the peer"
        assert reader.read_content(mine) == "fact written here"
    finally:
        reader.close()


# @positive-control(erasure-tombstone-final)
def test_put_key_never_reactivates_a_shredded_subject(tmp_path):
    db = _client(tmp_path / "heartwood.db")
    try:
        db.store.shred_key(TENANT, "customer:erased")
        assert db.store.put_key(TENANT, "customer:erased", b"replacement-envelope") is False
        assert db.store.get_key(TENANT, "customer:erased") == (None, "shredded")
    finally:
        db.close()


def test_rewrap_does_not_reactivate_a_key_shredded_after_it_was_listed(tmp_path):
    db_path, subject = tmp_path / "heartwood.db", "customer:rewrap"
    db = _client(db_path)
    try:
        db.remember("fact", subject=subject, created_by="agent:writer")
        listed = db.store.iter_keys(TENANT)
        db.forget(subject, mode="hard", actor="agent:eraser", reason="test")
        db.store.iter_keys = lambda tenant: listed
        report = rewrap_tenant_keys(
            db.store, tenant=TENANT, old_custodian=db.keys.custodian,
            new_custodian=LocalKmsCustodian(bytes([60]) * 32, key_id="concurrent-erasure-v2",
                                            retention_floor_seconds=0),
        )
    finally:
        db.close()
    assert (report.migrated, report.skipped_shredded) == (0, 1)
    assert _key_state(db_path, subject) == [("shredded", 1)]


# -- the sqlite-vec index lives in the shared database file ----------------- #
def test_sqlite_vec_vector_added_after_its_row_was_erased_is_not_kept(tmp_path):
    pytest.importorskip("sqlite_vec")
    db_path, subject = tmp_path / "heartwood.db", "customer:vector"
    writer = _client(db_path, index="sqlite-vec")
    try:
        # The row has committed; its vector has not been indexed yet.
        fired = _after_first_call(writer.store, "insert_memory_superseding", lambda: _peer(
            db_path, "forget", subject, index="sqlite-vec",
        ))
        writer.remember("fact whose vector lands late", subject=subject,
                        created_by="agent:writer")
        assert fired
    finally:
        writer.close()
    assert _vector_ids(db_path) == []
    _assert_erased(db_path, subject)


def test_sqlite_vec_erasure_by_a_process_opened_before_the_write(tmp_path):
    pytest.importorskip("sqlite_vec")
    db_path, subject = tmp_path / "heartwood.db", "customer:vector"
    eraser = _client(db_path, index="sqlite-vec")
    try:
        _peer(db_path, "remember", subject, content="fact written by another process",
              index="sqlite-vec")
        assert len(_vector_ids(db_path)) == 1
        eraser.forget(subject, mode="hard", actor="agent:eraser", reason="test")
    finally:
        eraser.close()
    assert _vector_ids(db_path) == []
    _assert_erased(db_path, subject)


class _ProcessDied(BaseException):
    """Stands in for a crash: nothing in Heartwood catches a BaseException."""


def _die() -> None:
    raise _ProcessDied


# @positive-control(erasure-vectors-purged)
def test_sqlite_vec_vectors_are_gone_when_the_eraser_dies_right_after_the_purge(tmp_path):
    pytest.importorskip("sqlite_vec")
    db_path, subject = tmp_path / "heartwood.db", "customer:vector"
    eraser = _client(db_path, index="sqlite-vec")
    try:
        eraser.remember("fact with a stored vector", subject=subject, created_by="agent:writer")
        fired = _after_first_call(eraser.store, "purge_subject", _die)
        with pytest.raises(_ProcessDied):
            eraser.forget(subject, mode="hard", actor="agent:eraser", reason="test")
        assert fired
    finally:
        eraser.close()
    assert _vector_ids(db_path) == []
    _assert_erased(db_path, subject)


def test_a_failed_purge_keeps_rows_and_vectors_together(tmp_path):
    pytest.importorskip("sqlite_vec")
    db_path, subject = tmp_path / "heartwood.db", "customer:vector"
    eraser = _client(db_path, index="sqlite-vec")
    try:
        mem_id = eraser.remember("fact with a stored vector", subject=subject,
                                 created_by="agent:writer")

        def fail(*_args):
            raise sqlite3.OperationalError("simulated failure inside the purge")

        eraser.store._delete_memory_rows = fail
        with pytest.raises(sqlite3.OperationalError, match="simulated failure"):
            eraser.forget(subject, mode="hard", actor="agent:eraser", reason="test")
        # The vector delete rolled back with the row delete.
        assert (_rows_naming(db_path, subject), _vector_ids(db_path)) == ([mem_id], [mem_id])
        del eraser.store._delete_memory_rows
        eraser.forget(subject, mode="hard", actor="agent:eraser", reason="retry")
    finally:
        eraser.close()
    assert _vector_ids(db_path) == []
    _assert_erased(db_path, subject)


def test_numpy_eraser_removes_vectors_a_sqlite_vec_process_stored(tmp_path):
    pytest.importorskip("sqlite_vec")
    db_path, subject = tmp_path / "heartwood.db", "customer:vector"
    eraser = _client(db_path, index="numpy")
    try:
        _peer(db_path, "remember", subject, content="fact indexed by another process",
              index="sqlite-vec")
        assert len(_vector_ids(db_path)) == 1
        receipt = eraser.forget(subject, mode="hard", actor="agent:eraser", reason="test")
    finally:
        eraser.close()
    assert receipt["purged"] == 1
    assert _vector_ids(db_path) == []
    _assert_erased(db_path, subject)


# @positive-control(erasure-needs-sqlite-vec)
def test_eraser_without_sqlite_vec_refuses_before_the_shred(tmp_path, monkeypatch):
    pytest.importorskip("sqlite_vec")
    db_path, subject = tmp_path / "heartwood.db", "customer:vector"
    peer = _peer(db_path, "remember", subject, content="fact indexed by another process",
                 index="sqlite-vec")
    eraser = _client(db_path, index="numpy")
    try:
        with monkeypatch.context() as patched:
            patched.setitem(sys.modules, "sqlite_vec", None)
            with pytest.raises(RuntimeError, match="recall extra"):
                eraser.forget(subject, mode="hard", actor="agent:eraser", reason="test")
    finally:
        eraser.close()
    # Refused before anything changed: the key is live, the row and vector remain.
    assert _key_state(db_path, subject) == [("active", 0)]
    assert (_rows_naming(db_path, subject), _vector_ids(db_path)) == ([peer["id"]], [peer["id"]])


def test_vector_table_created_during_erasure_without_sqlite_vec_fails_closed(
    tmp_path, monkeypatch,
):
    pytest.importorskip("sqlite_vec")
    db_path, subject = tmp_path / "heartwood.db", "customer:vector"
    eraser = _client(db_path, index="numpy")
    peer: dict = {}
    try:
        mine = eraser.remember("fact written before the vector table existed", subject=subject,
                               created_by="agent:writer")
        with monkeypatch.context() as patched:
            patched.setitem(sys.modules, "sqlite_vec", None)
            # The vector table appears after the pre-shred check passed.
            fired = _before_first_call(eraser.keys, "shred", lambda: peer.update(_peer(
                db_path, "remember", subject, content="fact indexed by another process",
                index="sqlite-vec",
            )))
            with pytest.raises(RuntimeError, match="recall extra"):
                eraser.forget(subject, mode="hard", actor="agent:eraser", reason="test")
            assert fired
        # The key is gone, so the rows are unreadable, but nothing reported success.
        assert _key_state(db_path, subject) == [("shredded", 1)]
        assert _rows_naming(db_path, subject) == sorted([mine, peer["id"]])
        # The peer's rebuild indexed both rows; both vectors survive the rollback.
        assert sorted(_vector_ids(db_path)) == sorted([mine, peer["id"]])
        receipt = eraser.forget(subject, mode="hard", actor="agent:eraser", reason="retry")
    finally:
        eraser.close()
    assert receipt["purged"] == 2
    assert _vector_ids(db_path) == []
    _assert_erased(db_path, subject)


def test_sqlite_vec_loader_refuses_a_sqlite3_that_cannot_load_extensions():
    pytest.importorskip("sqlite_vec")

    class ConnectionWithoutExtensions:
        """sqlite3 built without extension loading has no enable_load_extension."""

    with pytest.raises(RuntimeError, match="can load extensions"):
        load_sqlite_vec(ConnectionWithoutExtensions(), "hard erasure")


# -- vectors orphaned before vector removal joined the purge ---------------- #
def _orphan_a_vector(db_path: Path, mem_id: str) -> None:
    """Delete a memory row but not its vector, as a crash after the old purge did."""
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("DELETE FROM memories WHERE id=?", (mem_id,))
        conn.commit()


# @positive-control(vector-orphans-dropped)
@pytest.mark.parametrize("keep_live_row", [True, False])
def test_reopening_with_sqlite_vec_drops_vectors_whose_rows_are_gone(tmp_path, keep_live_row):
    pytest.importorskip("sqlite_vec")
    db_path = tmp_path / "heartwood.db"
    db = _client(db_path, index="sqlite-vec")
    try:
        orphan = db.remember("fact whose purge left its vector", subject="customer:old",
                             created_by="agent:writer")
        live = (db.remember("fact that stays", subject="customer:live",
                            created_by="agent:writer") if keep_live_row else None)
    finally:
        db.close()
    _orphan_a_vector(db_path, orphan)
    assert orphan in _vector_ids(db_path)
    _client(db_path, index="sqlite-vec").close()
    assert _vector_ids(db_path) == ([live] if keep_live_row else [])
