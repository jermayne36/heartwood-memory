"""A vanished provenance root must not expose previously fetched content."""
from __future__ import annotations

import pytest

import heartwood.client as recall_module
from heartwood import Heartwood, LocalKmsCustodian, Principal, StrictSignatureError
from heartwood.importers.markdown import dev_models


def open_memory(path, mode):
    embedding, ranking = dev_models()
    return Heartwood(
        path=path,
        tenant="tenant:verification",
        embedder=embedding,
        reranker=ranking,
        strict_signatures=mode,
        key_custodian=LocalKmsCustodian(b"v" * 32, key_id="verification-fixture"),
    )


@pytest.fixture(params=["off", "filter", "enforce"])
def memories(tmp_path, request):
    db = open_memory(tmp_path / "records.db", request.param)
    try:
        target = db.remember(
            "Verification record awaiting removal.",
            subject="subject:remove",
            created_by="writer",
        )
        kept = db.remember(
            "Verification record retained for the reader.",
            subject="subject:keep",
            created_by="writer",
        )
        reader = Principal(id="reader", tenant=db.tenant)
        yield db, reader, target, kept, request.param
    finally:
        db.close()


class RejectExemption:
    def match(self, **_arguments):
        pytest.fail("An unavailable provenance root reached the exemption matcher")


# @positive-control(recall-vanished-root)
def test_delete_after_fetch_before_provenance(memories, monkeypatch, tmp_path):
    db, reader, target, kept, mode = memories
    expected = db.recall("Verification record", principal=reader, k=10)["results"]
    assert {item["id"] for item in expected} == {target, kept}
    expected_kept = next(item for item in expected if item["id"] == kept)
    real_chain = recall_module.chain
    observed = []
    writer = open_memory(tmp_path / "records.db", mode)
    monkeypatch.setattr(db, "_strict_cutover", RejectExemption())

    def provenance_after_removal(store, memory_id, signer):
        if memory_id == target:
            deletion = writer.forget(
                "subject:remove", actor="eraser", reason="interleaving test", legal_basis="test"
            )
            assert deletion["purged"] == 1
            node = real_chain(store, memory_id, signer)
            assert node.get("missing") is True
            observed.append(memory_id)
            return node
        return real_chain(store, memory_id, signer)

    monkeypatch.setattr(recall_module, "chain", provenance_after_removal)
    try:
        result = db.recall("Verification record", principal=reader, k=10)
    finally:
        writer.close()
    assert observed == [target]
    assert result["results"] == [expected_kept]
    assert db.explain_recall(result["recall_id"])["strict_exempt_ids"] == []


def test_invalid_signature_still_obeys_strict_mode(memories):
    db, reader, target, kept, mode = memories
    db.store.conn.execute("UPDATE memories SET producer_sig = ? WHERE id = ?", ("bad", target))
    db.store.conn.commit()
    if mode == "enforce":
        with pytest.raises(StrictSignatureError) as rejected:
            db.recall("Verification record", principal=reader, k=10)
        assert rejected.value.ids == (target,)
    else:
        items = db.recall("Verification record", principal=reader, k=10)["results"]
        by_id = {item["id"]: item for item in items}
        assert by_id[kept]["provenance"]["signature_valid"] is True
        if mode == "filter":
            assert set(by_id) == {kept}
        else:
            assert set(by_id) == {target, kept}
            assert by_id[target]["provenance"]["signature_valid"] is False


# @positive-control(recall-incomplete-root)
@pytest.mark.parametrize("interruption", ["cycle", "depth"])
def test_incomplete_root_cannot_be_exempted(memories, monkeypatch, interruption):
    db, reader, target, kept, mode = memories
    real_chain = recall_module.chain
    monkeypatch.setattr(db, "_strict_cutover", RejectExemption())

    def interrupted_provenance(store, memory_id, signer):
        if memory_id == target:
            options = {"_seen": {target}} if interruption == "cycle" else {"_depth": 17}
            node = real_chain(store, memory_id, signer, **options)
            assert node.get("cycle_or_depth_cut") is True
            return node
        return real_chain(store, memory_id, signer)

    monkeypatch.setattr(recall_module, "chain", interrupted_provenance)
    if mode == "enforce":
        with pytest.raises(StrictSignatureError) as rejected:
            db.recall("Verification record", principal=reader, k=10)
        assert rejected.value.ids == (target,)
    else:
        items = db.recall("Verification record", principal=reader, k=10)["results"]
        assert [item["id"] for item in items] == [kept]
