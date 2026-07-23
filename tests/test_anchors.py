"""External audit-anchor security, cadence, restart, CLI, and pinning tests."""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
from pathlib import Path

import pytest

from heartwood import (
    AnchorWriteError,
    Heartwood,
    LocalFileAnchorSink,
    LocalKmsCustodian,
    StrictMode,
    anchor_root_fingerprint,
    verify_chain_against_anchors,
)
from heartwood.anchors import AnchorWriter
from heartwood.audit import AuditLog
from heartwood.cli import main as cli_main
from heartwood.importers.markdown import dev_models
from heartwood.store import Store

ROOT = bytes([91]) * 32
CUSTODIAN = LocalKmsCustodian(ROOT, key_id="anchor-test-root-v1")


def _sink_and_root(
    store: Store,
    path: Path,
    *,
    sink_id: str | None = None,
):
    sink = LocalFileAnchorSink(path, sink_id=sink_id)
    fingerprint = anchor_root_fingerprint(
        CUSTODIAN,
        chain_id=store.chain_id(),
        sink_id=sink.sink_id,
    )
    return sink, fingerprint


def _writer(
    store: Store,
    anchor_path: Path,
    *,
    interval_s: float = 300,
    every_n_rows: int = 1000,
    clock=lambda: 1_700_000_000.0,
):
    sink, fingerprint = _sink_and_root(store, anchor_path)
    writer = AnchorWriter(
        store=store,
        sink=sink,
        custodian=CUSTODIAN,
        trusted_root_fingerprints=fingerprint,
        interval_s=interval_s,
        every_n_rows=every_n_rows,
        clock=clock,
        retry_backoff_s=0.001,
        retry_backoff_max_s=0.002,
    )
    return writer, sink, fingerprint


def _append(audit: AuditLog, number: int) -> str:
    return audit.append(
        "store-global",
        "agent:anchor-test",
        "anchor_test",
        f"event:{number}",
        {"number": number},
    )


def test_seal_verify_roundtrip_and_close_anchor(tmp_path):
    store = Store(tmp_path / "roundtrip.db")
    writer, sink, fingerprint = _writer(store, tmp_path / "anchors.jsonl")
    audit = AuditLog(store, after_append=writer.maybe_anchor)
    try:
        _append(audit, 1)
        first = writer.verify()
        assert first["ok"] is True
        assert first["anchors_checked"] == 1
        assert first["undetectable_window_rows"] == 0

        _append(audit, 2)
        open_window = writer.verify()
        assert open_window["ok"] is True
        assert open_window["undetectable_window_rows"] == 1

        closed = writer.close()
        assert closed["ok"] is True
        assert closed["last_success_seq"] == 2
        assert closed["wrote_anchor"] is True
    finally:
        store.close()

    reopened = Store(tmp_path / "roundtrip.db")
    try:
        receipt = verify_chain_against_anchors(
            reopened,
            sink,
            trusted_root_fingerprints=fingerprint,
        )
        assert receipt["ok"] is True
        assert receipt["chain_ok"] is True
        assert receipt["anchors_ok"] is True
        assert receipt["anchor_fresh"] is True
        assert receipt["sink_healthy"] is True
    finally:
        reopened.close()


def test_truncation_at_latest_anchor_is_detected_while_chain_prefix_passes(tmp_path):
    db_path = tmp_path / "truncate.db"
    store = Store(db_path)
    writer, sink, fingerprint = _writer(store, tmp_path / "anchors.jsonl")
    audit = AuditLog(store, after_append=writer.maybe_anchor)
    try:
        _append(audit, 1)
        _append(audit, 2)
        _append(audit, 3)
        anchored = writer.anchor()
        assert anchored["last_success_seq"] == 3
    finally:
        store.close()

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM audit_log WHERE seq=3")
        conn.commit()
    finally:
        conn.close()

    shortened = Store(db_path)
    try:
        assert AuditLog(shortened).verify_chain() is True
        receipt = verify_chain_against_anchors(
            shortened,
            sink,
            trusted_root_fingerprints=fingerprint,
        )
        assert receipt["ok"] is False
        assert receipt["anchors_ok"] is False
        assert receipt["first_failure"].startswith("anchored_row_missing:")
    finally:
        shortened.close()


def test_post_anchor_tail_loss_remains_the_explicit_open_window_limit(tmp_path):
    db_path = tmp_path / "post-anchor.db"
    store = Store(db_path)
    writer, sink, fingerprint = _writer(store, tmp_path / "anchors.jsonl")
    audit = AuditLog(store, after_append=writer.maybe_anchor)
    try:
        _append(audit, 1)
        _append(audit, 2)
        before_tamper = writer.verify()
        assert before_tamper["ok"] is True
        assert before_tamper["undetectable_window_rows"] == 1
    finally:
        store.close()

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM audit_log WHERE seq=2")
        conn.commit()
    finally:
        conn.close()

    shortened = Store(db_path)
    try:
        receipt = verify_chain_against_anchors(
            shortened,
            sink,
            trusted_root_fingerprints=fingerprint,
        )
        assert receipt["ok"] is True
        assert receipt["last_success_seq"] == 1
        assert receipt["undetectable_window_rows"] == 0
    finally:
        shortened.close()


def test_missing_partial_and_stale_anchors_fail_closed(tmp_path):
    db_path = tmp_path / "fail-closed.db"
    store = Store(db_path)
    AuditLog(store).append(
        "store-global",
        "agent:test",
        "event",
        "one",
        {"value": 1},
    )
    missing_sink, fingerprint = _sink_and_root(store, tmp_path / "missing.jsonl")
    missing = verify_chain_against_anchors(
        store,
        missing_sink,
        trusted_root_fingerprints=fingerprint,
    )
    assert missing["ok"] is False
    assert missing["sink_healthy"] is False
    assert missing["first_failure"] == "anchor_sink_missing"

    clock = [1_700_000_000.0]
    writer, sink, fingerprint = _writer(
        store,
        tmp_path / "anchors.jsonl",
        interval_s=10,
        every_n_rows=100,
        clock=lambda: clock[0],
    )
    writer.anchor()
    AuditLog(store).append(
        "store-global",
        "agent:test",
        "event",
        "two",
        {"value": 2},
    )
    clock[0] += 11
    stale = writer.verify()
    assert stale["ok"] is False
    assert stale["anchor_fresh"] is False
    assert stale["anchor_due"] is True
    assert stale["first_failure"] == "latest_anchor_stale"
    store.close()

    with sink.path.open("ab") as handle:
        handle.write(b'{"partial":')
    malformed_store = Store(db_path)
    try:
        malformed = verify_chain_against_anchors(
            malformed_store,
            sink,
            trusted_root_fingerprints=fingerprint,
        )
        assert malformed["ok"] is False
        assert malformed["sink_healthy"] is False
        assert malformed["first_failure"] == "anchor_sink_unhealthy"
    finally:
        malformed_store.close()


class _FailingSink:
    sink_id = "test:failing-anchor-sink"

    def append(self, record):
        raise OSError("synthetic sink outage")

    def read_records(self):
        return []


class _SwitchableSink:
    def __init__(self, delegate: LocalFileAnchorSink):
        self.delegate = delegate
        self.fail_writes = False

    @property
    def sink_id(self):
        return self.delegate.sink_id

    def append(self, record):
        if self.fail_writes:
            raise OSError("synthetic close-time outage")
        self.delegate.append(record)

    def read_records(self):
        return self.delegate.read_records()


def test_cadence_failure_is_observable_and_restart_recomputes_degraded_state(tmp_path):
    db_path = tmp_path / "restart.db"
    store = Store(db_path)
    sink = _FailingSink()
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
        retry_backoff_s=0.001,
        retry_backoff_max_s=0.002,
    )
    audit = AuditLog(store, after_append=writer.maybe_anchor)
    _append(audit, 1)
    degraded = writer.verify()
    assert degraded["ok"] is False
    assert degraded["anchor_due"] is True
    assert degraded["last_sanitized_error_class"] == "OSError"
    with pytest.raises(AnchorWriteError) as explicit:
        writer.anchor()
    assert explicit.value.receipt["anchor_status"] == "degraded"
    with pytest.raises(AnchorWriteError):
        writer.close()
    store.close()

    restarted = Store(db_path)
    try:
        restarted_writer = AnchorWriter(
            store=restarted,
            sink=_FailingSink(),
            custodian=CUSTODIAN,
            trusted_root_fingerprints=fingerprint,
            every_n_rows=1,
            interval_s=300,
        )
        recomputed = restarted_writer.verify()
        assert recomputed["ok"] is False
        assert recomputed["anchor_due"] is True
        assert recomputed["current_seq"] == 1
        assert recomputed["last_sanitized_error_class"] == "OSError"
        assert recomputed["first_failure"] in {
            "anchor_sink_head_unrecorded",
            "no_anchors",
            "prior_anchor_write_failed",
        }
    finally:
        restarted.close()


def test_close_failure_receipt_survives_restart_until_verified_anchor(tmp_path):
    db_path = tmp_path / "close-restart.db"
    store = Store(db_path)
    local, fingerprint = _sink_and_root(store, tmp_path / "anchors.jsonl")
    sink = _SwitchableSink(local)
    writer = AnchorWriter(
        store=store,
        sink=sink,
        custodian=CUSTODIAN,
        trusted_root_fingerprints=fingerprint,
        every_n_rows=100,
        interval_s=300,
    )
    audit = AuditLog(store, after_append=writer.maybe_anchor)
    _append(audit, 1)
    _append(audit, 2)
    sink.fail_writes = True
    with pytest.raises(AnchorWriteError):
        writer.close()
    store.close()

    restarted = Store(db_path)
    recovered_sink = _SwitchableSink(local)
    restarted_writer = AnchorWriter(
        store=restarted,
        sink=recovered_sink,
        custodian=CUSTODIAN,
        trusted_root_fingerprints=fingerprint,
        every_n_rows=100,
        interval_s=300,
    )
    try:
        degraded = restarted_writer.verify()
        assert degraded["ok"] is False
        assert degraded["anchor_due"] is False
        assert degraded["first_failure"] == "prior_anchor_write_failed"
        assert degraded["last_sanitized_error_class"] == "OSError"

        recovered = restarted_writer.anchor()
        assert recovered["ok"] is True
        assert recovered["last_success_seq"] == 2
        assert restarted_writer.verify()["last_sanitized_error_class"] is None
    finally:
        restarted.close()


def test_count_and_time_cadence_write_at_the_designed_thresholds(tmp_path):
    count_store = Store(tmp_path / "count.db")
    count_writer, _sink, _fingerprint = _writer(
        count_store,
        tmp_path / "count.jsonl",
        every_n_rows=1,
    )
    count_audit = AuditLog(count_store, after_append=count_writer.maybe_anchor)
    _append(count_audit, 1)
    first_anchor = count_writer.verify()["last_success_anchor_id"]
    _append(count_audit, 2)
    second = count_writer.verify()
    assert second["last_success_seq"] == 2
    assert second["last_success_anchor_id"] != first_anchor
    count_store.close()

    clock = [1_700_000_000.0]
    time_store = Store(tmp_path / "time.db")
    time_writer, _sink, _fingerprint = _writer(
        time_store,
        tmp_path / "time.jsonl",
        interval_s=10,
        every_n_rows=100,
        clock=lambda: clock[0],
    )
    time_audit = AuditLog(time_store, after_append=time_writer.maybe_anchor)
    _append(time_audit, 1)
    initial = time_writer.verify()["last_success_anchor_id"]
    clock[0] += 1
    _append(time_audit, 2)
    assert time_writer.verify()["last_success_anchor_id"] == initial
    clock[0] += 10
    _append(time_audit, 3)
    timed = time_writer.verify()
    assert timed["last_success_seq"] == 3
    assert timed["last_success_anchor_id"] != initial
    time_store.close()


def test_background_time_cadence_anchors_without_another_audit_write(tmp_path):
    store = Store(tmp_path / "background.db")
    sink, fingerprint = _sink_and_root(store, tmp_path / "background.jsonl")
    writer = AnchorWriter(
        store=store,
        sink=sink,
        custodian=CUSTODIAN,
        trusted_root_fingerprints=fingerprint,
        interval_s=0.05,
        every_n_rows=100,
        background_time_cadence=True,
    )
    audit = AuditLog(store, after_append=writer.maybe_anchor)
    _append(audit, 1)
    _append(audit, 2)
    deadline = time.time() + 1.0
    while time.time() < deadline:
        if writer.verify()["last_success_seq"] == 2:
            break
        time.sleep(0.01)
    assert writer.verify()["last_success_seq"] == 2
    writer.close()
    store.close()


def test_file_rollback_and_reordering_cannot_produce_overall_ok(tmp_path):
    store = Store(tmp_path / "rollback.db")
    writer, sink, fingerprint = _writer(store, tmp_path / "anchors.jsonl")
    audit = AuditLog(store, after_append=writer.maybe_anchor)
    _append(audit, 1)
    prefix = sink.path.read_bytes()
    _append(audit, 2)
    writer.anchor()
    complete = sink.path.read_bytes()
    assert complete != prefix

    sink.path.write_bytes(prefix)
    rollback = writer.verify()
    assert rollback["ok"] is False
    assert rollback["first_failure"] == "anchor_sink_rollback_or_divergence"

    sink.path.write_bytes(complete)
    lines = complete.splitlines(keepends=True)
    sink.path.write_bytes(b"".join(reversed(lines)))
    reordered = writer.verify()
    assert reordered["ok"] is False
    assert reordered["first_failure"] == "duplicate_or_reordered_anchor_seq"
    store.close()


def test_local_sink_uses_safe_permissions_and_rejects_forged_record(tmp_path):
    store = Store(tmp_path / "forged.db")
    writer, sink, fingerprint = _writer(store, tmp_path / "anchors.jsonl")
    _append(AuditLog(store, after_append=writer.maybe_anchor), 1)
    assert stat.S_IMODE(sink.path.stat().st_mode) == 0o600

    record = json.loads(sink.path.read_text().strip())
    signature = record["signature"]
    record["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    sink.path.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    )
    os.chmod(sink.path, 0o600)
    forged = verify_chain_against_anchors(
        store,
        sink,
        trusted_root_fingerprints=fingerprint,
    )
    assert forged["ok"] is False
    assert forged["sink_healthy"] is False
    store.close()


def test_unhashed_display_column_tamper_cannot_produce_chain_ok(tmp_path):
    store = Store(tmp_path / "display-tamper.db")
    writer, sink, fingerprint = _writer(store, tmp_path / "anchors.jsonl")
    _append(AuditLog(store, after_append=writer.maybe_anchor), 1)
    store.conn.execute(
        "UPDATE audit_log SET action='forged-display-action' WHERE seq=1"
    )
    store.conn.commit()
    receipt = verify_chain_against_anchors(
        store,
        sink,
        trusted_root_fingerprints=fingerprint,
    )
    assert receipt["ok"] is False
    assert receipt["chain_ok"] is False
    assert receipt["first_failure"] == "audit_chain_invalid"
    store.close()


def test_strict_manifest_pin_prefers_anchor_sink_with_config_fallback(tmp_path):
    db_path = tmp_path / "pin.db"
    manifest_path = tmp_path / "strict-cutover.json"
    anchor_path = tmp_path / "anchors.jsonl"
    bootstrap = Store(db_path)
    sink, fingerprint = _sink_and_root(bootstrap, anchor_path)
    bootstrap.close()
    embedder, reranker = dev_models()
    db = Heartwood(
        path=db_path,
        tenant="tenant:pin",
        embedder=embedder,
        reranker=reranker,
        key_custodian=CUSTODIAN,
        anchor_sink=sink,
        anchor_root_fingerprints=fingerprint,
    )
    try:
        report = db.strict_preflight()
        sealed = db.seal_strict_cutover(
            approved_report_digest=report["report_digest"],
            manifest_path=str(manifest_path),
            operator="operator:pin-test",
            reason="anchor pin migration",
        )
        assert sealed["pin"]["pin_source"] == "anchor_sink"
        activated = db.activate_strict_cutover(
            manifest_path=str(manifest_path),
            operator="operator:pin-test",
        )
        assert activated["pin_source"] == "anchor_sink"
    finally:
        db.close()

    anchored = Heartwood(
        path=db_path,
        tenant="tenant:pin",
        embedder=embedder,
        reranker=reranker,
        key_custodian=CUSTODIAN,
        strict_signatures=StrictMode.ENFORCE,
        strict_legacy_exemption="manifest",
        strict_cutover_path=str(manifest_path),
        anchor_sink=sink,
        anchor_root_fingerprints=fingerprint,
    )
    anchored.close()

    fallback = Heartwood(
        path=db_path,
        tenant="tenant:pin",
        embedder=embedder,
        reranker=reranker,
        key_custodian=CUSTODIAN,
        strict_signatures=StrictMode.ENFORCE,
        strict_legacy_exemption="manifest",
        strict_cutover_path=str(manifest_path),
        strict_cutover_digest=sealed["manifest_digest"],
    )
    fallback.close()


def test_verify_audit_cli_emits_receipt_and_exits_nonzero_on_failure(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    anchor_path = tmp_path / "anchors.jsonl"
    store = Store(db_path)
    writer, _sink, fingerprint = _writer(store, anchor_path)
    _append(AuditLog(store, after_append=writer.maybe_anchor), 1)
    store.close()

    cli_main(
        [
            "verify-audit",
            "--db",
            str(db_path),
            "--anchors",
            str(anchor_path),
            "--anchor-root-fingerprint",
            fingerprint,
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is True
    assert output["anchors_checked"] == 1

    anchor_path.write_bytes(b'{"partial":')
    with pytest.raises(SystemExit) as failed:
        cli_main(
            [
                "verify-audit",
                "--db",
                str(db_path),
                "--anchors",
                str(anchor_path),
                "--anchor-root-fingerprint",
                fingerprint,
            ]
        )
    assert failed.value.code == 2
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is False
    assert output["first_failure"] == "anchor_sink_unhealthy"


def test_manifest_pin_rejects_conflicting_digest(tmp_path):
    store = Store(tmp_path / "pin-conflict.db")
    writer, _sink, _fingerprint = _writer(store, tmp_path / "anchors.jsonl")
    _append(AuditLog(store, after_append=writer.maybe_anchor), 1)
    manifest_id = "sct_" + ("1" * 24)
    writer.pin_manifest(manifest_id, "sha256:" + ("2" * 64))
    with pytest.raises(AnchorWriteError) as conflict:
        writer.pin_manifest(manifest_id, "sha256:" + ("3" * 64))
    assert conflict.value.receipt["last_sanitized_error_class"] == "AnchorSinkError"
    store.close()
