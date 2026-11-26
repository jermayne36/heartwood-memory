"""Phase 1 B5 key-custody tests."""
import os
import sys
import tempfile
from contextlib import closing
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import (  # noqa: E402
    Heartwood,
    KeyCustodian,
    LocalKmsCustodian,
    Principal,
    RawKeyCustodian,
    provision_tenant_root,
    prove_crypto_erase_path,
    rewrap_tenant_keys,
    rotate_tenant_root,
)
from heartwood.erasure import new_key  # noqa: E402
from heartwood.importers.markdown import dev_models  # noqa: E402
from heartwood.key_custody import envelope_key_id, is_wrapped_key  # noqa: E402
from heartwood.store import Store  # noqa: E402


TENANT = "tenant:acme"
NO_ROOT_ERROR = r"HEARTWOOD_KEY_CUSTODY_ROOT_B64.*HEARTWOOD_KEY_CUSTODY_KEY_ID"


def _db(path: Path, root_byte: int = 7) -> Heartwood:
    embedder, reranker = dev_models()
    return Heartwood(
        path=path,
        tenant=TENANT,
        embedder=embedder,
        reranker=reranker,
        key_custodian=LocalKmsCustodian(bytes([root_byte]) * 32, key_id=f"test-root-{root_byte}"),
    )


@pytest.fixture
def without_custody_env(monkeypatch):
    monkeypatch.delenv("HEARTWOOD_KEY_CUSTODY_ROOT_B64", raising=False)
    monkeypatch.delenv("HEARTWOOD_KEY_CUSTODY_KEY_ID", raising=False)


def _db_from_env(path: Path) -> Heartwood:
    embedder, reranker = dev_models()
    return Heartwood(path=path, tenant=TENANT, embedder=embedder, reranker=reranker)


# @positive-control(raw-custodian-wrapped-dek)
def test_no_root_reader_reports_missing_custody(tmp_path, without_custody_env):
    path = tmp_path / "heartwood.db"
    with closing(_db(path)) as writer:
        mem_id = writer.remember("Wrapped test memory", subject="subject:test", created_by="agent:writer")
    with closing(_db_from_env(path)) as reader:
        principal = Principal(id="agent:reader", tenant=TENANT)
        with pytest.raises(RuntimeError, match=NO_ROOT_ERROR):
            reader.recall("Wrapped test memory", principal=principal)
        with pytest.raises(RuntimeError, match=NO_ROOT_ERROR):
            reader.read_content(mem_id)


# @positive-control(raw-custodian-wrapped-dek)
@pytest.mark.parametrize("custodian", [None, KeyCustodian()], ids=["from-env", "base-custodian"])
def test_no_root_writer_refuses_wrapped_subject(tmp_path, without_custody_env, monkeypatch, custodian):
    path = tmp_path / "heartwood.db"
    subject = "subject:test"
    with closing(_db(path)) as writer:
        mem_id = writer.remember("Wrapped test memory", subject=subject, created_by="agent:writer")

    def unexpected_encryption(*_args):
        pytest.fail("Wrapped subject without custody reached encryption")

    embedder, reranker = dev_models()
    with closing(Heartwood(
        path=path, tenant=TENANT, embedder=embedder, reranker=reranker, key_custodian=custodian,
    )) as writer:
        monkeypatch.setattr(writer.cipher, "encrypt", unexpected_encryption)
        with pytest.raises(RuntimeError, match=NO_ROOT_ERROR):
            writer.remember("Refused test memory", subject=subject, created_by="agent:other-writer")
        assert writer.store.subject_ids(TENANT, subject) == [mem_id]
    with closing(_db(path)) as reader:
        assert reader.store.subject_ids(TENANT, subject) == [mem_id]
        assert reader.read_content(mem_id) == "Wrapped test memory"


def test_raw_local_store_works_without_custody(tmp_path, without_custody_env):
    path = tmp_path / "heartwood.db"
    with closing(_db_from_env(path)) as writer:
        mem_id = writer.remember("Raw test memory", subject="subject:test", created_by="agent:writer")
        envelope, state = writer.store.get_key(TENANT, "subject:test")
        assert state == "active"
        assert envelope is not None and not is_wrapped_key(envelope)
    with closing(_db_from_env(path)) as reader:
        result = reader.recall("Raw test memory", principal=Principal(id="agent:reader", tenant=TENANT))
        assert [row["id"] for row in result["results"]] == [mem_id]


def test_hard_forget_purges_memory_encrypted_outside_custody(tmp_path, without_custody_env):
    path = tmp_path / "heartwood.db"
    wal_path = Path(f"{path}-wal")
    subject = "subject:test"
    with closing(_db(path)) as writer:
        mem_id = writer.remember("Wrapped test memory", subject=subject, created_by="agent:writer")
        kept_id = writer.remember("Unrelated test memory", subject="subject:keep", created_by="agent:writer")
        # Model a legacy row whose ciphertext is independent of the subject DEK.
        # Only payload bytes change in this temporary store; the purge sees normal metadata.
        ciphertext = writer.cipher.encrypt("Out-of-custody test memory", new_key())
        with writer.store.conn:
            writer.store.conn.execute("UPDATE memories SET content_enc=? WHERE id=?", (ciphertext, mem_id))
        assert writer.store.subject_ids(TENANT, subject) == [mem_id]
        assert writer.read_content(mem_id) is None
        assert ciphertext in wal_path.read_bytes()

        with closing(_db_from_env(path)) as eraser:
            result = eraser.forget(subject, mode="hard")
            assert result["purged"] == 1
            assert result["key_shredded"] is True
            assert result["wal_residue_cleared"] is True
            assert eraser.store.get_meta(mem_id) is None
            assert eraser.store.get_key(TENANT, subject) == (None, "shredded")
            assert ciphertext not in path.read_bytes()
            assert not wal_path.exists() or wal_path.stat().st_size == 0
        assert writer.read_content(kept_id) == "Unrelated test memory"


def test_wrapped_dek_survives_restart_and_fails_closed_with_wrong_root():
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "heartwood.db"
        db = _db(path)
        try:
            mem_id = db.remember(
                "Customer 42 prefers email support updates.",
                subject="customer:42",
                created_by="agent:test",
                source={"uri": "doc://customers/42"},
            )
            envelope, state = db.store.get_key(TENANT, "customer:42")
            assert state == "active"
            assert is_wrapped_key(envelope)
            info = db.key_custody_info("customer:42")
            assert info["mode"] == "hkdf-aeskw-local"
            assert info["algorithm"] == "HKDF-SHA256+A256KW"
            assert db.read_content(mem_id).startswith("Customer 42")
        finally:
            db.close()

        reopened = _db(path)
        try:
            out = reopened.recall(
                "email support updates",
                principal=Principal(id="agent:test", tenant=TENANT),
                k=3,
            )
            assert [row["id"] for row in out["results"]] == [mem_id]
            assert out["results"][0]["provenance"]["signature_valid"] is True
        finally:
            reopened.close()

        wrong_root = _db(path, root_byte=8)
        try:
            try:
                wrong_root.read_content(mem_id)
                raise AssertionError("wrong key-custody root must not decrypt content")
            except Exception:
                pass
        finally:
            wrong_root.close()


def test_provisioned_tenant_root_writes_wrapped_envelopes():
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "heartwood.db"
        material = provision_tenant_root(
            TENANT,
            root_key=bytes([21]) * 32,
            key_id="tenant-acme-root-v1",
        )
        assert material.env()["HEARTWOOD_KEY_CUSTODY_KEY_ID"] == "tenant-acme-root-v1"
        db = Heartwood(
            path=path,
            tenant=TENANT,
            embedder=dev_models()[0],
            reranker=dev_models()[1],
            key_custodian=material.custodian(),
        )
        try:
            db.remember(
                "Provisioned tenant roots write wrapped DEKs.",
                subject="customer:provisioned",
                created_by="agent:test",
                source={"uri": "doc://provisioned"},
            )
            envelope, state = db.store.get_key(TENANT, "customer:provisioned")
            assert state == "active"
            assert is_wrapped_key(envelope)
            assert envelope_key_id(envelope) == "tenant-acme-root-v1"
        finally:
            db.close()


# @positive-control(default-unwrap-wrapped-dek)
@pytest.mark.parametrize(
    ("old_key_id", "expected_remainder"), [("old-a", 0), ("old-ab", 1)],
    ids=["aligned", "unaligned"],
)
@pytest.mark.parametrize("old_custodian", [RawKeyCustodian(), None], ids=["raw", "omitted"])
def test_rewrap_refuses_wrapped_key_without_old_custody(
    tmp_path, monkeypatch, old_key_id, expected_remainder, old_custodian,
):
    path = tmp_path / "heartwood.db"
    subject = "subject:test"
    old = LocalKmsCustodian(bytes([21]) * 32, key_id=old_key_id)
    new = LocalKmsCustodian(bytes([31]) * 32, key_id="new-root")
    envelope = old.wrap(tenant=TENANT, subject=subject, dek=new_key())
    remainder = len(envelope) % 8
    assert remainder == expected_remainder

    def unexpected_put_key(*_args):
        pytest.fail("Rewrap without the old custody reached put_key")

    with closing(Store(str(path))) as store:
        assert store.create_key(TENANT, subject, envelope) == (envelope, "active")
        monkeypatch.setattr(store, "put_key", unexpected_put_key)
        with pytest.raises(RuntimeError, match=NO_ROOT_ERROR):
            rewrap_tenant_keys(
                store, tenant=TENANT, old_custodian=old_custodian, new_custodian=new,
            )
    with closing(Store(str(path))) as store:
        assert store.get_key(TENANT, subject) == (envelope, "active")


def test_rewrap_migrator_raw_to_wrapped_is_resumable_and_idempotent():
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "heartwood.db"
        embedder, reranker = dev_models()
        raw = Heartwood(path=path, tenant=TENANT, embedder=embedder, reranker=reranker)
        try:
            raw.remember(
                "Alpha raw-local memory migrates to wrapped custody.",
                subject="customer:alpha",
                created_by="agent:test",
                source={"uri": "doc://alpha"},
            )
            raw.remember(
                "Beta raw-local memory migrates on the resume pass.",
                subject="customer:beta",
                created_by="agent:test",
                source={"uri": "doc://beta"},
            )
            for subject in ("customer:alpha", "customer:beta"):
                envelope, _state = raw.store.get_key(TENANT, subject)
                assert not is_wrapped_key(envelope)
        finally:
            raw.close()

        new_custodian = LocalKmsCustodian(bytes([31]) * 32, key_id="tenant-acme-root-v1")
        store = Store(str(path))
        try:
            first = rewrap_tenant_keys(
                store,
                tenant=TENANT,
                old_custodian=RawKeyCustodian(),
                new_custodian=new_custodian,
                max_updates=1,
            )
            assert first.migrated == 1
            assert first.raw_migrated == 1
            assert first.complete is False
            assert first.remaining == 1

            second = rewrap_tenant_keys(
                store,
                tenant=TENANT,
                old_custodian=RawKeyCustodian(),
                new_custodian=new_custodian,
            )
            assert second.migrated == 1
            assert second.raw_migrated == 1
            assert second.complete is True
            assert second.remaining == 0

            third = rewrap_tenant_keys(
                store,
                tenant=TENANT,
                old_custodian=RawKeyCustodian(),
                new_custodian=new_custodian,
            )
            assert third.migrated == 0
            assert third.already_current == 2
            assert third.complete is True
        finally:
            store.close()

        reopened = Heartwood(
            path=path,
            tenant=TENANT,
            embedder=embedder,
            reranker=reranker,
            key_custodian=new_custodian,
        )
        try:
            assert reopened.read_content(
                next(row["id"] for row in reopened.store.candidate_meta(TENANT) if row["subject"] == "customer:alpha")
            ).startswith("Alpha raw-local")
            for subject in ("customer:alpha", "customer:beta"):
                envelope, _state = reopened.store.get_key(TENANT, subject)
                assert is_wrapped_key(envelope)
                assert envelope_key_id(envelope) == "tenant-acme-root-v1"
        finally:
            reopened.close()


def test_rotate_root_rewraps_deks_and_preserves_historical_provenance():
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "heartwood.db"
        embedder, reranker = dev_models()
        old_custodian = LocalKmsCustodian(bytes([41]) * 32, key_id="tenant-acme-root-v1")
        new_custodian = LocalKmsCustodian(bytes([42]) * 32, key_id="tenant-acme-root-v2")
        old = Heartwood(
            path=path,
            tenant=TENANT,
            embedder=embedder,
            reranker=reranker,
            key_custodian=old_custodian,
        )
        try:
            mem_id = old.remember(
                "Rotation preserves audit provenance for customer Alpha.",
                subject="customer:alpha",
                created_by="agent:writer",
                source={"uri": "doc://rotation"},
            )
            old_envelope, _state = old.store.get_key(TENANT, "customer:alpha")
            old_dek = old_custodian.unwrap(
                tenant=TENANT,
                subject="customer:alpha",
                envelope=old_envelope,
            )
            assert old.verify_audit() is True
            before = old.recall(
                "audit provenance Alpha",
                principal=Principal(id="agent:reader", tenant=TENANT),
                k=1,
            )
            assert before["results"][0]["provenance"]["signature_valid"] is True
        finally:
            old.close()

        store = Store(str(path))
        try:
            report = rotate_tenant_root(
                store,
                tenant=TENANT,
                old_custodian=old_custodian,
                new_custodian=new_custodian,
            )
            assert report.keys.complete is True
            assert report.keys.rewrapped == 1
            assert report.provenance.legacy_aliases_registered == 1
            assert report.provenance.new_aliases_registered == 1
            new_envelope, _state = store.get_key(TENANT, "customer:alpha")
            assert envelope_key_id(new_envelope) == "tenant-acme-root-v2"
            assert new_custodian.unwrap(
                tenant=TENANT,
                subject="customer:alpha",
                envelope=new_envelope,
            ) == old_dek
        finally:
            store.close()

        rotated = Heartwood(
            path=path,
            tenant=TENANT,
            embedder=embedder,
            reranker=reranker,
            key_custodian=new_custodian,
        )
        try:
            historical = rotated.recall(
                "audit provenance Alpha",
                principal=Principal(id="agent:reader", tenant=TENANT),
                k=1,
            )
            assert [row["id"] for row in historical["results"]] == [mem_id]
            assert historical["results"][0]["provenance"]["signature_valid"] is True
            assert rotated.verify_audit() is True

            new_mem_id = rotated.remember(
                "Post-rotation signatures use the new custody root.",
                subject="customer:beta",
                created_by="agent:writer",
                source={"uri": "doc://rotation/new"},
            )
            after = rotated.recall(
                "rotation signatures",
                principal=Principal(id="agent:reader", tenant=TENANT),
                k=5,
            )
            by_id = {row["id"]: row for row in after["results"]}
            assert by_id[mem_id]["provenance"]["signature_valid"] is True
            assert by_id[new_mem_id]["provenance"]["signature_valid"] is True
        finally:
            rotated.close()


def test_crypto_erase_proof_rejects_raw_deks_and_proves_wrapped_or_destroyed_data_unrecoverable():
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "heartwood.db"
        embedder, reranker = dev_models()
        raw = Heartwood(path=path, tenant=TENANT, embedder=embedder, reranker=reranker)
        try:
            mem_id = raw.remember(
                "Raw DEKs are still recoverable without a custody root.",
                subject="customer:erase",
                created_by="agent:test",
                source={"uri": "doc://erase"},
            )
            raw_proof = raw.crypto_erase_proof(root_present=False)
            assert raw_proof.proved is False
            assert raw_proof.raw_active_key_count == 1
        finally:
            raw.close()

        new_custodian = LocalKmsCustodian(bytes([51]) * 32, key_id="tenant-acme-root-v1")
        store = Store(str(path))
        try:
            report = rewrap_tenant_keys(
                store,
                tenant=TENANT,
                old_custodian=RawKeyCustodian(),
                new_custodian=new_custodian,
            )
            assert report.complete is True
            wrapped_proof = prove_crypto_erase_path(path, tenant=TENANT, root_present=False)
            assert wrapped_proof.proved is True
            assert wrapped_proof.raw_active_key_count == 0
            assert wrapped_proof.wrapped_active_key_count == 1
        finally:
            store.close()

        wrong_root = Heartwood(
            path=path,
            tenant=TENANT,
            embedder=embedder,
            reranker=reranker,
            key_custodian=LocalKmsCustodian(bytes([52]) * 32, key_id="tenant-acme-root-v2"),
        )
        try:
            try:
                recovered = wrong_root.read_content(mem_id)
            except Exception:
                recovered = None
            assert recovered is None
        finally:
            wrong_root.close()

        for candidate in (
            path,
            path.with_name(f"{path.name}-wal"),
            path.with_name(f"{path.name}-shm"),
        ):
            if candidate.exists():
                candidate.unlink()
        destroyed = prove_crypto_erase_path(path, tenant=TENANT, root_present=False)
        assert destroyed.proved is True
        assert destroyed.data_store_present is False


def main():
    test_wrapped_dek_survives_restart_and_fails_closed_with_wrong_root()
    test_provisioned_tenant_root_writes_wrapped_envelopes()
    test_rewrap_migrator_raw_to_wrapped_is_resumable_and_idempotent()
    test_rotate_root_rewraps_deks_and_preserves_historical_provenance()
    test_crypto_erase_proof_rejects_raw_deks_and_proves_wrapped_or_destroyed_data_unrecoverable()
    print("KEY CUSTODY TESTS PASSED")


if __name__ == "__main__":
    main()
