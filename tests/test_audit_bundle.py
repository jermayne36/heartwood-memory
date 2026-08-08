"""Portable signed audit export and offline verification tests."""
from __future__ import annotations

import json
import tarfile

import pytest

from heartwood import Heartwood, LocalFileAnchorSink, LocalKmsCustodian, Policy
from heartwood.anchors import AnchorWriter, anchor_root_fingerprint
from heartwood.audit import AuditLog
from heartwood.audit_bundle import export_audit_bundle, verify_audit_bundle
from heartwood.cli import main as cli_main
from heartwood.importers.markdown import dev_models
from heartwood.store import Store

ROOT = bytes([117]) * 32
CUSTODIAN = LocalKmsCustodian(ROOT, key_id="audit-bundle-test-root-v1")


def _anchored_store(tmp_path):
    db_path = tmp_path / "heartwood.db"
    anchors_path = tmp_path / "anchors.jsonl"
    store = Store(db_path)
    sink = LocalFileAnchorSink(anchors_path)
    fingerprint = anchor_root_fingerprint(
        CUSTODIAN,
        chain_id=store.chain_id(),
        sink_id=sink.sink_id,
    )
    writer = AnchorWriter(
        store=store,
        sink=sink,
        custodian=CUSTODIAN,
        trusted_root_fingerprints=fingerprint,
        every_n_rows=1,
        interval_s=300,
    )
    audit = AuditLog(store, after_append=writer.maybe_anchor)
    audit.append(
        "tenant:audit",
        "agent:test",
        "remember",
        "memory:1",
        {"classification": "internal"},
    )
    writer.close()
    store.close()
    return db_path, anchors_path, fingerprint


def test_export_cli_and_offline_verifier_report_chain_range_and_fingerprint(
    tmp_path, capsys
):
    db_path, anchors_path, fingerprint = _anchored_store(tmp_path)
    bundle = tmp_path / "bundle.tar.gz"

    cli_main(
        [
            "export-audit",
            "--db",
            str(db_path),
            "--anchors",
            str(anchors_path),
            "--anchor-root-fingerprint",
            fingerprint,
            "--out",
            str(bundle),
        ]
    )
    exported = json.loads(capsys.readouterr().out)
    assert exported["status"] == "PASS"
    assert exported["chain_range"] == "1-1"
    assert exported["source_mutated"] is False

    cli_main(
        [
            "verify-audit-bundle",
            str(bundle),
            "--anchor-root-fingerprint",
            fingerprint,
        ]
    )
    verified = json.loads(capsys.readouterr().out)
    assert verified["status"] == "PASS"
    assert verified["chain_range"] == "1-1"
    assert verified["anchor_fingerprints"] == [fingerprint]
    assert verified["trust_source"] == "external"


def test_tampered_bundle_byte_fails_closed(tmp_path):
    # @positive-control(audit-bundle-verification)
    db_path, anchors_path, fingerprint = _anchored_store(tmp_path)
    bundle = tmp_path / "bundle.tar.gz"
    export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )
    tampered = bytearray(bundle.read_bytes())
    tampered[len(tampered) // 2] ^= 0x01
    tampered_path = tmp_path / "tampered.tar.gz"
    tampered_path.write_bytes(tampered)

    receipt = verify_audit_bundle(
        tampered_path,
        trusted_root_fingerprints=fingerprint,
    )
    assert receipt["status"] == "FAIL"
    assert receipt["ok"] is False
    assert receipt["first_failure"] == "bundle_verification_failed"


def test_exported_bundle_spanning_crypto_shred_erasure_verifies_offline(tmp_path):
    db_path = tmp_path / "erasure.db"
    anchors_path = tmp_path / "erasure-anchors.jsonl"
    bootstrap = Store(db_path)
    sink = LocalFileAnchorSink(anchors_path)
    fingerprint = anchor_root_fingerprint(
        CUSTODIAN,
        chain_id=bootstrap.chain_id(),
        sink_id=sink.sink_id,
    )
    bootstrap.close()
    embedder, reranker = dev_models()
    db = Heartwood(
        path=db_path,
        tenant="tenant:erasure",
        embedder=embedder,
        reranker=reranker,
        key_custodian=CUSTODIAN,
        anchor_sink=sink,
        anchor_root_fingerprints=fingerprint,
        anchor_every_n_rows=1,
        anchor_interval_s=300,
    )
    try:
        db.remember(
            "This content is destroyed during the test.",
            subject="customer:erased",
            created_by="agent:test",
            policy=Policy(classification="internal"),
        )
        erased = db.forget(
            "customer:erased",
            mode="hard",
            actor="dpo:test",
            reason="positive erasure invariant",
            legal_basis="test",
        )
        assert erased["key_shredded"] is True
        db.remember(
            "A post-erasure event keeps the chain moving.",
            subject="customer:retained",
            created_by="agent:test",
            policy=Policy(classification="internal"),
        )
    finally:
        db.close()

    bundle = tmp_path / "erasure-bundle.tar.gz"
    export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )
    receipt = verify_audit_bundle(bundle, trusted_root_fingerprints=fingerprint)
    assert receipt["status"] == "PASS"

    with tarfile.open(bundle, "r:gz") as archive:
        stream = archive.extractfile("audit.jsonl")
        assert stream is not None
        rows = [json.loads(line) for line in stream.read().splitlines()]
    actions = [row["action"] for row in rows]
    forget_index = actions.index("forget")
    assert forget_index > 0
    assert forget_index < len(actions) - 1
    assert rows[forget_index]["body"].find("customer:erased") >= 0


def test_export_is_read_only_and_excludes_unanchored_tail(tmp_path):
    db_path, anchors_path, fingerprint = _anchored_store(tmp_path)
    before_db = db_path.read_bytes()
    before_anchors = anchors_path.read_bytes()
    store = Store(db_path)
    AuditLog(store).append(
        "tenant:audit", "agent:test", "tail", "event:2", {"anchored": False}
    )
    store.close()
    db_with_tail = db_path.read_bytes()

    bundle = tmp_path / "tail-bundle.tar.gz"
    exported = export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )
    assert exported["excluded_unanchored_rows"] == 1
    assert db_path.read_bytes() == db_with_tail
    assert anchors_path.read_bytes() == before_anchors
    assert before_db != db_with_tail


def test_offline_verifier_cli_exits_two_on_failure(tmp_path, capsys):
    bad = tmp_path / "not-a-bundle.tar.gz"
    bad.write_bytes(b"not a tar archive")
    with pytest.raises(SystemExit) as failed:
        cli_main(["verify-audit-bundle", str(bad)])
    assert failed.value.code == 2
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["status"] == "FAIL"
