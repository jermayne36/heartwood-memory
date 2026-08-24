"""Positive controls for signed recall/erasure receipts and offline verification."""
from __future__ import annotations

import copy
import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from heartwood import Heartwood, LocalFileAnchorSink, LocalKmsCustodian, Policy
from heartwood.anchors import anchor_root_fingerprint
from heartwood.audit_bundle import export_audit_bundle
from heartwood.cli import main as cli_main
from heartwood.importers.markdown import dev_models
from heartwood.provenance import _payload
from heartwood.receipts import (
    b64e,
    expected_receipt_hash,
    producer_payload_v1,
    producer_signature_parts,
    receipt_signable,
    verify_erasure_receipt,
    verify_erasure_store,
    verify_recall_receipt,
)
from heartwood.store import Store

ROOT = bytes([73]) * 32
CUSTODIAN = LocalKmsCustodian(ROOT, key_id="receipt-test-root-v1")


def _db(tmp_path, tenant="tenant:receipts"):
    db_path = tmp_path / "receipts.db"
    anchors_path = tmp_path / "anchors.jsonl"
    bootstrap = Store(db_path)
    sink = LocalFileAnchorSink(anchors_path)
    fingerprint = anchor_root_fingerprint(
        CUSTODIAN, chain_id=bootstrap.chain_id(), sink_id=sink.sink_id,
    )
    bootstrap.close()
    embedder, reranker = dev_models()
    db = Heartwood(
        path=db_path, tenant=tenant, embedder=embedder, reranker=reranker,
        key_custodian=CUSTODIAN, anchor_sink=sink,
        anchor_root_fingerprints=fingerprint, anchor_every_n_rows=1,
    )
    return db, db_path, anchors_path, fingerprint


def _bundle(db, db_path, anchors_path, fingerprint, tmp_path):
    db._anchor_writer.anchor()
    bundle = tmp_path / "audit-bundle.tar.gz"
    exported = export_audit_bundle(
        db_path=db_path, anchors_path=anchors_path, out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )
    return bundle, exported["latest_anchor_id"]


def _resign(receipt, writer, kind):
    changed = copy.deepcopy(receipt)
    changed["receipt_hash"] = expected_receipt_hash(changed)
    changed["signature"] = (
        writer.sign_recall_receipt(receipt_signable(changed))
        if kind == "recall"
        else writer.sign_erasure_receipt(receipt_signable(changed))
    )
    return changed


def test_recall_receipt_passes_and_named_mutations_fail(tmp_path):
    db, db_path, anchors_path, fingerprint = _db(tmp_path)
    try:
        db.remember(
            "renewal policy alpha", subject="subject:alpha",
            created_by="agent:producer", source={"uri": "doc://renewal"},
            source_ids=("doc://renewal",), policy=Policy(),
        )
        response = db.recall(
            "renewal policy", principal=db.principal("agent:buyer"), k=1,
        )
        receipt = response["receipt"]
        assert receipt is not None
        export_path = tmp_path / "principal-keys.json"
        cli_main([
            "export-principal-keys", "--db", str(db_path),
            "--tenant", db.tenant, "--output", str(export_path),
        ])
        exported_key = json.loads(export_path.read_text())["keys"][0]["public_key_b64"]
        producer_public, _producer_signature = producer_signature_parts(
            response["results"][0]["producer_sig"]
        )
        assert exported_key == b64e(producer_public)
        bundle, checkpoint = _bundle(
            db, db_path, anchors_path, fingerprint, tmp_path,
        )
        kwargs = {
            "trusted_root_fingerprints": [fingerprint],
            "results": response["results"], "audit_bundle": str(bundle),
            "expected_latest_anchor_id": checkpoint,
        }
        assert verify_recall_receipt(receipt, **kwargs)["status"] == "PASS"

        # @positive-control(receipt-signature)
        signature_byte = copy.deepcopy(receipt)
        signature_byte["signature"] = (
            "A" if signature_byte["signature"][0] != "A" else "B"
        ) + signature_byte["signature"][1:]
        assert verify_recall_receipt(signature_byte, **kwargs)["first_failure"] == "receipt_signature"

        # @positive-control(receipt-hash)
        content_hash = copy.deepcopy(receipt)
        content_hash["results"][0]["content_hash"] = "sha256:" + "0" * 64
        assert verify_recall_receipt(content_hash, **kwargs)["first_failure"] == "receipt_hash_mismatch"

        # @positive-control(producer-key-registration)
        self_key = copy.deepcopy(receipt)
        attacker = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        self_key["principal_keys"][0]["public_key_b64"] = b64e(attacker)
        self_key = _resign(self_key, db._anchor_writer, "recall")
        assert verify_recall_receipt(self_key, **kwargs)["first_failure"] == "producer_key_not_registered"

        # @positive-control(recall-content-binding)
        changed_results = copy.deepcopy(response["results"])
        changed_results[0]["content"] += " tampered"
        changed_kwargs = {**kwargs, "results": changed_results}
        assert verify_recall_receipt(receipt, **changed_kwargs)["first_failure"] == "content_hash_mismatch"

        # @positive-control(receipt-external-root)
        no_root = verify_recall_receipt(receipt, **{**kwargs, "trusted_root_fingerprints": []})
        assert no_root["status"] == "UNTRUSTED_SELF_CONSISTENT"

        # @positive-control(receipt-audit-row): a valid deployment signature over
        # a swapped row hash still cannot bind to the exported row.
        row_swap = copy.deepcopy(receipt)
        row_swap["audit_row_hash"] = "0" * 64
        row_swap = _resign(row_swap, db._anchor_writer, "recall")
        assert verify_recall_receipt(row_swap, **kwargs)["first_failure"] == "audit_binding_mismatch"

        audit_hash = copy.deepcopy(receipt)
        audit_hash["query_hash"] = "sha256:" + "1" * 64
        audit_hash = _resign(audit_hash, db._anchor_writer, "recall")
        assert verify_recall_receipt(audit_hash, **kwargs)["first_failure"] == "audit_binding_mismatch"

        cross_domain = copy.deepcopy(receipt)
        cross_domain["signature"] = db._anchor_writer.sign_erasure_receipt(
            receipt_signable(cross_domain)
        )
        assert verify_recall_receipt(cross_domain, **kwargs)["first_failure"] == "receipt_signature"

        receipt_path = tmp_path / "recall-receipt.json"
        result_path = tmp_path / "results.json"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        result_path.write_text(json.dumps(response["results"]), encoding="utf-8")
        cli_args = [
            "verify-recall-receipt", "--receipt", str(receipt_path),
            "--results", str(result_path), "--audit-bundle", str(bundle),
            "--anchor-root-fingerprint", fingerprint,
            "--expected-latest-anchor-id", checkpoint,
        ]
        cli_main(cli_args)
        receipt_path.write_text(json.dumps(signature_byte), encoding="utf-8")
        with pytest.raises(SystemExit) as failed:
            cli_main(cli_args)
        assert failed.value.code == 2
    finally:
        db.close()


def test_producer_v1_preserves_null_none_collision():
    base = {
        "id": "mem_collision", "content_hash": "sha256:" + "1" * 64,
        "created_by": "agent:producer", "epistemic": "user-stated",
    }
    null_payload = producer_payload_v1({**base, "source_uri": None})
    literal_payload = producer_payload_v1({**base, "source_uri": "None"})
    assert null_payload == literal_payload
    assert null_payload == _payload(
        base["id"], base["content_hash"], None,
        base["created_by"], base["epistemic"],
    )


def test_receipt_cache_is_principal_bound_ttl_and_count_capped(tmp_path, monkeypatch):
    import heartwood.client as client_module

    monkeypatch.setattr(client_module, "_RECEIPT_CACHE_LIMIT", 1)
    db, _db_path, _anchors_path, _fingerprint = _db(tmp_path)
    now = [100.0]
    monkeypatch.setattr(client_module.time, "monotonic", lambda: now[0])
    try:
        db.remember(
            "cache receipt", subject="subject:cache", created_by="agent:producer",
            policy=Policy(),
        )
        principal = db.principal("agent:cache-reader")
        first = db.recall("cache", principal=principal, k=1)
        assert db.recall_receipt(principal.id, first["recall_id"]) == first["receipt"]
        assert db.recall_receipt("agent:different", first["recall_id"]) is None
        second = db.recall("cache", principal=principal, k=1)
        assert db.recall_receipt(principal.id, first["recall_id"]) is None
        assert db.recall_receipt(principal.id, second["recall_id"]) == second["receipt"]
        now[0] += client_module._RECEIPT_CACHE_TTL_SECONDS + 1
        assert db.recall_receipt(principal.id, second["recall_id"]) is None
    finally:
        db.close()


def test_secondary_subject_selector_purges_record_and_descendant(tmp_path):
    db, _db_path, _anchors_path, _fingerprint = _db(tmp_path)
    try:
        parent = db.remember(
            "secondary subject data", subject="subject:primary",
            subject_ids=("subject:primary", "subject:secondary"),
            created_by="agent:producer", policy=Policy(),
        )
        child = db.remember(
            "derived secondary data", subject="subject:derived",
            created_by="agent:producer", derived_from=(parent,), policy=Policy(),
        )
        receipt = db.forget("subject:secondary", actor="agent:privacy")
        # @positive-control(erasure-secondary-subject-selector)
        assert receipt["proof_status"] == "AVAILABLE"
        assert receipt["receipt"]["purge"]["purged_memory_ids"] == sorted([parent, child])
        assert db.store.get_meta(parent) is None
        assert db.store.get_meta(child) is None
        assert db.store.conn.execute(
            "SELECT 1 FROM prov_edges WHERE child=? OR parent=?", (child, parent),
        ).fetchone() is None
    finally:
        db.close()


def test_malformed_secondary_subject_metadata_stops_before_key_shred(tmp_path):
    db, _db_path, _anchors_path, _fingerprint = _db(tmp_path)
    try:
        mem_id = db.remember(
            "protected malformed alias", subject="subject:protected",
            created_by="agent:producer", policy=Policy(),
        )
        db.store.conn.execute(
            "UPDATE memories SET subject_ids_json='not-json' WHERE id=?", (mem_id,),
        )
        db.store.conn.commit()
        with pytest.raises(ValueError, match="subject_ids_json"):
            db.forget("subject:protected", actor="agent:privacy")
        _envelope, state = db.store.get_key(db.tenant, "subject:protected")
        assert state == "active"
        assert db.store.conn.execute(
            "SELECT 1 FROM memories WHERE id=?", (mem_id,),
        ).fetchone() is not None
    finally:
        db.close()


def test_erasure_receipt_and_store_controls(tmp_path):
    db, db_path, anchors_path, fingerprint = _db(tmp_path)
    try:
        db.remember(
            "erase me", subject="subject:erase", created_by="agent:producer",
            policy=Policy(),
        )
        response = db.forget("subject:erase", actor="agent:privacy")
        receipt = response["receipt"]
        bundle, checkpoint = _bundle(
            db, db_path, anchors_path, fingerprint, tmp_path,
        )
        kwargs = {
            "trusted_root_fingerprints": [fingerprint],
            "audit_bundle": str(bundle), "expected_latest_anchor_id": checkpoint,
        }
        assert verify_erasure_receipt(receipt, **kwargs)["status"] == "PASS"
        assert verify_erasure_store(receipt, db_path=db_path)["status"] == "PASS"

        cross_domain = copy.deepcopy(receipt)
        cross_domain["signature"] = db._anchor_writer.sign_recall_receipt(
            receipt_signable(cross_domain)
        )
        assert verify_erasure_receipt(cross_domain, **kwargs)["first_failure"] == "receipt_signature"
    finally:
        db.close()

    preforget_db = tmp_path / "preforget.db"
    conn = sqlite3.connect(preforget_db)
    try:
        conn.executescript("""
          CREATE TABLE keys (tenant TEXT, subject TEXT, dek BLOB, state TEXT);
          CREATE TABLE memories (id TEXT, tenant TEXT, subject TEXT, subject_ids_json TEXT);
          CREATE TABLE prov_edges (child TEXT, parent TEXT);
          CREATE TABLE deletion_lineage (artifact_id TEXT, tenant TEXT, subject TEXT);
        """)
        conn.execute(
            "INSERT INTO keys VALUES (?,?,?,?)",
            (receipt["tenant"], receipt["subject_id"], b"raw", "active"),
        )
        conn.commit()
    finally:
        conn.close()
    # @positive-control(erasure-key-tombstone)
    assert verify_erasure_store(receipt, db_path=preforget_db)["first_failure"] == "key_not_shredded"

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO memories (id,tenant,subject,subject_ids_json) VALUES (?,?,?,?)",
            ("mem_reingested", receipt["tenant"], "subject:new", json.dumps([receipt["subject_id"]])),
        )
        conn.commit()
    finally:
        conn.close()
    # @positive-control(erasure-exact-subject)
    assert verify_erasure_store(receipt, db_path=db_path)["first_failure"] == "subject_rows_present"


def test_missing_signer_and_post_erasure_signing_failure_emit_no_receipt(tmp_path, monkeypatch):
    embedder, reranker = dev_models()
    unsigned = Heartwood(
        path=tmp_path / "unsigned.db", tenant="tenant:unsigned",
        embedder=embedder, reranker=reranker,
    )
    try:
        unsigned.remember(
            "unsigned recall", subject="subject:u", created_by="agent:p", policy=Policy(),
        )
        recalled = unsigned.recall(
            "unsigned", principal=unsigned.principal("agent:r"), k=1,
        )
        # @positive-control(recall-receipt-signing)
        assert recalled["receipt"] is None
        assert recalled["receipt_unavailable_reason"] == "no_durable_signing_root"
    finally:
        unsigned.close()

    signed_path = tmp_path / "signed"
    signed_path.mkdir()
    db, _db_path, _anchors_path, _fingerprint = _db(signed_path)
    try:
        db.remember(
            "post failure", subject="subject:failure", created_by="agent:p", policy=Policy(),
        )
        monkeypatch.setattr(
            db._anchor_writer, "sign_erasure_receipt",
            lambda _payload: (_ for _ in ()).throw(RuntimeError("signing unavailable")),
        )
        erased = db.forget("subject:failure", actor="agent:privacy")
        # @positive-control(post-erasure-receipt-failure)
        assert erased["receipt"] is None
        assert erased["proof_status"] == "UNAVAILABLE"
        failure = db.store.conn.execute(
            "SELECT failure_stage,error_class FROM receipt_failures"
        ).fetchone()
        assert tuple(failure) == ("audit_or_signing", "RuntimeError")
    finally:
        db.close()
