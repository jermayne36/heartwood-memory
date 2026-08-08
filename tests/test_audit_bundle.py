"""Portable signed audit export and offline verification tests."""
from __future__ import annotations

import hashlib
import json
import tarfile

import pytest

from heartwood import Heartwood, LocalFileAnchorSink, LocalKmsCustodian, Policy
from heartwood import audit_bundle as audit_bundle_module
from heartwood.audit import AuditLog
from heartwood.anchors import AnchorWriter, anchor_root_fingerprint
from heartwood.audit_bundle import export_audit_bundle, verify_audit_bundle
from heartwood.cli import main as cli_main
from heartwood.importers.markdown import dev_models
from heartwood.store import Store

ROOT = bytes([117]) * 32
CUSTODIAN = LocalKmsCustodian(ROOT, key_id="audit-bundle-test-root-v1")


def _write_bundle(path, manifest, rows, records):
    audit_bytes = audit_bundle_module._jsonl_bytes(rows)
    anchor_bytes = audit_bundle_module._jsonl_bytes(records)
    manifest["files"] = {
        "audit.jsonl": audit_bundle_module._file_receipt(audit_bytes),
        "anchors.jsonl": audit_bundle_module._file_receipt(anchor_bytes),
    }
    audit_bundle_module._write_archive_atomic(
        path,
        {
            "manifest.json": audit_bundle_module._canonical_bytes(manifest) + b"\n",
            "audit.jsonl": audit_bytes,
            "anchors.jsonl": anchor_bytes,
        },
    )


def _anchored_store(tmp_path, *, actions=("remember",)):
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
    for index, action in enumerate(actions, start=1):
        audit.append(
            "tenant:audit",
            "agent:test",
            action,
            f"memory:{index}",
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
    expected_latest_anchor_id = exported["latest_anchor_id"]

    cli_main(
        [
            "verify-audit-bundle",
            str(bundle),
            "--anchor-root-fingerprint",
            fingerprint,
            "--expected-latest-anchor-id",
            expected_latest_anchor_id,
        ]
    )
    verified = json.loads(capsys.readouterr().out)
    assert verified["status"] == "PASS"
    assert verified["chain_range"] == "1-1"
    assert verified["anchor_fingerprints"] == [fingerprint]
    assert verified["trust_source"] == "external"
    assert verified["freshness_source"] == "external_latest_anchor_checkpoint"


def test_external_root_and_checkpoint_are_required_for_pass(tmp_path, capsys):
    # @positive-control(audit-bundle-external-trust)
    # @positive-control(audit-bundle-checkpoint)
    db_path, anchors_path, fingerprint = _anchored_store(tmp_path)
    bundle = tmp_path / "bundle.tar.gz"
    exported = export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )

    self_consistent = verify_audit_bundle(bundle)
    assert self_consistent["status"] == "UNTRUSTED_SELF_CONSISTENT"
    assert self_consistent["ok"] is False
    assert self_consistent["first_failure"] == "external_trust_root_required"

    with pytest.raises(SystemExit) as no_root:
        cli_main(["verify-audit-bundle", str(bundle)])
    assert no_root.value.code == 2
    cli_self_consistent = json.loads(capsys.readouterr().out)
    assert cli_self_consistent["status"] == "UNTRUSTED_SELF_CONSISTENT"
    assert cli_self_consistent["ok"] is False

    no_checkpoint = verify_audit_bundle(
        bundle,
        trusted_root_fingerprints=fingerprint,
    )
    assert no_checkpoint["status"] == "FRESHNESS_UNVERIFIED"
    assert no_checkpoint["ok"] is False
    assert (
        no_checkpoint["first_failure"]
        == "external_latest_anchor_checkpoint_required"
    )

    verified = verify_audit_bundle(
        bundle,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert verified["status"] == "PASS"
    assert verified["ok"] is True


def test_checkpoint_env_fallback_allows_verified_pass(tmp_path, monkeypatch, capsys):
    db_path, anchors_path, fingerprint = _anchored_store(tmp_path)
    bundle = tmp_path / "bundle.tar.gz"
    exported = export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )
    monkeypatch.setenv("HEARTWOOD_ANCHOR_ROOT_FINGERPRINT", fingerprint)
    monkeypatch.setenv(
        "HEARTWOOD_EXPECTED_LATEST_ANCHOR_ID", exported["latest_anchor_id"]
    )

    cli_main(["verify-audit-bundle", str(bundle)])

    receipt = json.loads(capsys.readouterr().out)
    assert receipt["status"] == "PASS"
    assert receipt["ok"] is True


def test_correctly_hash_chained_unsigned_tail_fails_closed(tmp_path):
    # @positive-control(audit-bundle-unanchored-tail)
    db_path, anchors_path, fingerprint = _anchored_store(tmp_path)
    bundle = tmp_path / "bundle.tar.gz"
    exported = export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )
    members = audit_bundle_module._read_archive(bundle)
    manifest = audit_bundle_module._load_canonical_json(
        members["manifest.json"], "manifest.json"
    )
    rows = audit_bundle_module._parse_jsonl(members["audit.jsonl"], "audit.jsonl")
    records = audit_bundle_module._parse_jsonl(
        members["anchors.jsonl"], "anchors.jsonl"
    )
    body = json.dumps(
        {
            "action": "forged-tail",
            "detail": {},
            "principal": "agent:attacker",
            "target": "event:unsigned",
            "tenant": "tenant:audit",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    timestamp = float(rows[-1]["ts"])
    previous_hash = rows[-1]["row_hash"]
    forged = {
        "seq": int(rows[-1]["seq"]) + 1,
        "ts": timestamp,
        "tenant": "tenant:audit",
        "principal": "agent:attacker",
        "action": "forged-tail",
        "target": "event:unsigned",
        "body": body,
        "prev_hash": previous_hash,
        "row_hash": hashlib.sha256(
            (previous_hash + body + repr(timestamp)).encode()
        ).hexdigest(),
    }
    rows.append(forged)
    manifest["chain"].update(
        {
            "last_seq": forged["seq"],
            "row_count": len(rows),
            "last_row_hash": forged["row_hash"],
            "source_current_seq": forged["seq"],
            "excluded_unanchored_rows": 0,
        }
    )
    forged_bundle = tmp_path / "forged-tail.tar.gz"
    _write_bundle(forged_bundle, manifest, rows, records)

    receipt = verify_audit_bundle(
        forged_bundle,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert receipt["ok"] is False
    assert receipt["first_failure"] == "unsigned_rows_after_latest_anchor"
    assert receipt["rows_since_success"] == 1
    assert receipt["last_success_seq"] == 1


def test_earlier_signed_prefix_fails_against_external_latest_checkpoint(tmp_path):
    # @positive-control(audit-bundle-checkpoint-mismatch)
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
    audit.append("tenant:audit", "agent:test", "first", "event:1", {})
    audit.append("tenant:audit", "agent:test", "adverse", "event:2", {})
    writer.close()
    store.close()

    full_bundle = tmp_path / "full.tar.gz"
    exported = export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=full_bundle,
        trusted_root_fingerprints=fingerprint,
    )
    members = audit_bundle_module._read_archive(full_bundle)
    manifest = audit_bundle_module._load_canonical_json(
        members["manifest.json"], "manifest.json"
    )
    rows = audit_bundle_module._parse_jsonl(members["audit.jsonl"], "audit.jsonl")
    records = audit_bundle_module._parse_jsonl(
        members["anchors.jsonl"], "anchors.jsonl"
    )
    first_anchor = next(
        record for record in records if record["record_type"] == "audit_anchor"
    )
    prefix_rows = rows[: int(first_anchor["seq"])]
    prefix_records = records[: records.index(first_anchor) + 1]
    prefix_audit_bytes = audit_bundle_module._jsonl_bytes(prefix_rows)
    prefix_anchor_bytes = audit_bundle_module._jsonl_bytes(prefix_records)
    manifest["chain"].update(
        {
            "last_seq": int(prefix_rows[-1]["seq"]),
            "row_count": len(prefix_rows),
            "last_row_hash": prefix_rows[-1]["row_hash"],
            "excluded_unanchored_rows": (
                int(manifest["chain"]["source_current_seq"])
                - int(prefix_rows[-1]["seq"])
            ),
        }
    )
    manifest["anchors"].update(
        {
            "sink_head_digest": "sha256:"
            + hashlib.sha256(
                audit_bundle_module._canonical_bytes(prefix_records[-1])
            ).hexdigest(),
            "records_count": len(prefix_records),
            "latest_anchor_id": first_anchor["anchor_id"],
            "latest_anchor_seq": int(first_anchor["seq"]),
        }
    )
    manifest["files"] = {
        "audit.jsonl": audit_bundle_module._file_receipt(prefix_audit_bytes),
        "anchors.jsonl": audit_bundle_module._file_receipt(prefix_anchor_bytes),
    }
    prefix_bundle = tmp_path / "earlier-prefix.tar.gz"
    audit_bundle_module._write_archive_atomic(
        prefix_bundle,
        {
            "manifest.json": audit_bundle_module._canonical_bytes(manifest) + b"\n",
            "audit.jsonl": prefix_audit_bytes,
            "anchors.jsonl": prefix_anchor_bytes,
        },
    )

    genuine_prefix = verify_audit_bundle(
        prefix_bundle,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=first_anchor["anchor_id"],
    )
    assert genuine_prefix["status"] == "PASS"

    rolled_back = verify_audit_bundle(
        prefix_bundle,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert rolled_back["status"] == "FAIL"
    assert rolled_back["ok"] is False
    assert (
        rolled_back["first_failure"]
        == "expected_latest_anchor_checkpoint_mismatch"
    )


def test_modified_audit_row_fails_closed(tmp_path):
    db_path, anchors_path, fingerprint = _anchored_store(tmp_path)
    bundle = tmp_path / "bundle.tar.gz"
    exported = export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )
    genuine = verify_audit_bundle(
        bundle,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert genuine["status"] == "PASS"

    members = audit_bundle_module._read_archive(bundle)
    manifest = audit_bundle_module._load_canonical_json(
        members["manifest.json"], "manifest.json"
    )
    rows = audit_bundle_module._parse_jsonl(members["audit.jsonl"], "audit.jsonl")
    records = audit_bundle_module._parse_jsonl(
        members["anchors.jsonl"], "anchors.jsonl"
    )
    body = json.loads(rows[0]["body"])
    body["detail"]["classification"] = "forged"
    rows[0]["body"] = json.dumps(body, sort_keys=True, separators=(",", ":"))
    modified = tmp_path / "modified-row.tar.gz"
    _write_bundle(modified, manifest, rows, records)

    receipt = verify_audit_bundle(
        modified,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert receipt["ok"] is False
    assert receipt["first_failure"] == "audit_rows_invalid"


def test_wrong_external_root_reports_anchor_failure_family(tmp_path):
    db_path, anchors_path, fingerprint = _anchored_store(tmp_path)
    bundle = tmp_path / "bundle.tar.gz"
    exported = export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )

    receipt = verify_audit_bundle(
        bundle,
        trusted_root_fingerprints="sha256:" + ("0" * 64),
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert receipt["ok"] is False
    assert receipt["first_failure"] == "anchor_set_invalid"


def test_substituted_validly_signed_anchor_fails_closed(tmp_path):
    db_path, anchors_path, fingerprint = _anchored_store(
        tmp_path, actions=("first", "second")
    )
    bundle = tmp_path / "bundle.tar.gz"
    exported = export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )
    genuine = verify_audit_bundle(
        bundle,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert genuine["status"] == "PASS"

    members = audit_bundle_module._read_archive(bundle)
    manifest = audit_bundle_module._load_canonical_json(
        members["manifest.json"], "manifest.json"
    )
    rows = audit_bundle_module._parse_jsonl(members["audit.jsonl"], "audit.jsonl")
    records = audit_bundle_module._parse_jsonl(
        members["anchors.jsonl"], "anchors.jsonl"
    )
    assert len(records) == 2
    records[1] = dict(records[0])
    manifest["anchors"].update(
        {
            "sink_head_digest": "sha256:"
            + hashlib.sha256(
                audit_bundle_module._canonical_bytes(records[-1])
            ).hexdigest(),
            "latest_anchor_id": records[-1]["anchor_id"],
            "latest_anchor_seq": records[-1]["seq"],
        }
    )
    substituted = tmp_path / "substituted-anchor.tar.gz"
    _write_bundle(substituted, manifest, rows, records)

    receipt = verify_audit_bundle(
        substituted,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert receipt["ok"] is False
    assert receipt["first_failure"] == "anchor_set_invalid"


def test_reordered_audit_rows_fail_closed(tmp_path):
    db_path, anchors_path, fingerprint = _anchored_store(
        tmp_path, actions=("first", "second")
    )
    bundle = tmp_path / "bundle.tar.gz"
    exported = export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )
    genuine = verify_audit_bundle(
        bundle,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert genuine["status"] == "PASS"

    members = audit_bundle_module._read_archive(bundle)
    manifest = audit_bundle_module._load_canonical_json(
        members["manifest.json"], "manifest.json"
    )
    rows = audit_bundle_module._parse_jsonl(members["audit.jsonl"], "audit.jsonl")
    records = audit_bundle_module._parse_jsonl(
        members["anchors.jsonl"], "anchors.jsonl"
    )
    rows.reverse()
    reordered = tmp_path / "reordered-rows.tar.gz"
    _write_bundle(reordered, manifest, rows, records)

    receipt = verify_audit_bundle(
        reordered,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert receipt["ok"] is False
    assert receipt["first_failure"] == "audit_rows_invalid"


def test_tampered_bundle_byte_fails_closed(tmp_path):
    # @positive-control(audit-bundle-verification)
    db_path, anchors_path, fingerprint = _anchored_store(tmp_path)
    bundle = tmp_path / "bundle.tar.gz"
    exported = export_audit_bundle(
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
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
    assert receipt["status"] == "FAIL"
    assert receipt["ok"] is False
    assert receipt["first_failure"] in {
        "audit_rows_invalid",
        "anchor_set_invalid",
        "bundle_structure_invalid",
    }


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
    exported = export_audit_bundle(
        db_path=db_path,
        anchors_path=anchors_path,
        out_path=bundle,
        trusted_root_fingerprints=fingerprint,
    )
    receipt = verify_audit_bundle(
        bundle,
        trusted_root_fingerprints=fingerprint,
        expected_latest_anchor_id=exported["latest_anchor_id"],
    )
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
