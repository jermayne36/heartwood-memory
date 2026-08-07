"""Signed, audited Markdown metadata refresh regression tests."""
import base64
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from heartwood import Heartwood
from heartwood.client import _SUBSTRATE_METADATA_SIGNATURE_DOMAIN
from heartwood.importers.markdown import dev_models, import_markdown_corpus


def _set_custody_env(monkeypatch):
    root = base64.urlsafe_b64encode(bytes([43]) * 32).decode("ascii").rstrip("=")
    monkeypatch.setenv("HEARTWOOD_KEY_CUSTODY_ROOT_B64", root)
    monkeypatch.setenv("HEARTWOOD_KEY_CUSTODY_KEY_ID", "metadata-refresh-test-root")


def _frontmatter(*, valid_from=None, valid_until=None, entities=None, truth_status=None):
    lines = ["---", "epistemic: model-generated"]
    if valid_from is not None:
        lines.append(f"valid_from: {valid_from}")
    if valid_until is not None:
        lines.append(f"valid_until: {valid_until}")
    if entities is not None:
        lines.append(f"entities: [{', '.join(entities)}]")
    if truth_status is not None:
        lines.append(f"truth_status: {truth_status}")
    lines.extend(["---", "# Metadata fixture", "", "The body stays byte-for-byte stable."])
    return "\n".join(lines)


def _client(db_path):
    embedder, reranker = dev_models()
    return Heartwood(
        path=str(db_path),
        tenant="tenant:ops",
        embedder=embedder,
        reranker=reranker,
    )


def _import(memory, db_path, **kwargs):
    embedder, reranker = dev_models()
    return import_markdown_corpus(
        [memory],
        db_path=db_path,
        created_by="agent:markdown-importer",
        embedder=embedder,
        reranker=reranker,
        **kwargs,
    )


def test_frontmatter_only_refresh_preserves_id_edges_and_writes_signed_audit(tmp_path, monkeypatch):
    _set_custody_env(monkeypatch)
    memory = tmp_path / "memory"
    memory.mkdir()
    source = memory / "project_metadata_fixture.md"
    source.write_text(_frontmatter(), encoding="utf-8")
    db_path = tmp_path / "heartwood.db"

    first = _import(memory, db_path)
    mem_id = first["imported"][0]["id"]
    db = _client(db_path)
    try:
        parent_id = db.remember(
            "A provenance parent used to pin the edge invariant.",
            subject="fixture:parent",
            created_by="agent:markdown-importer",
        )
        db.add_provenance_edge(mem_id, parent_id)
        edge_count_before = db.store.conn.execute("SELECT COUNT(*) FROM prov_edges").fetchone()[0]
    finally:
        db.close()

    source.write_text(
        _frontmatter(
            valid_from="2026-01-15",
            entities=["Heartwood", "OpenAI"],
            truth_status="generated_needs_review",
        ),
        encoding="utf-8",
    )
    refreshed = _import(memory, db_path, update=True, stop_on_error=True)

    assert refreshed["imported_count"] == 0
    assert refreshed["updated_count"] == 1
    assert refreshed["purged_count"] == 0
    assert refreshed["memory_row_count_delta"] == 0
    assert refreshed["updated"][0]["id"] == mem_id

    db = _client(db_path)
    try:
        meta = db.store.get_meta(mem_id)
        assert meta["id"] == mem_id
        assert meta["valid_from"] == "2026-01-15T00:00:00+00:00"
        assert meta["entities"] == ("Heartwood", "OpenAI")
        assert meta["truth_status"] == "generated_needs_review"
        edge_count_after = db.store.conn.execute("SELECT COUNT(*) FROM prov_edges").fetchone()[0]
        assert edge_count_after == edge_count_before
        events = db.store.audit_rows_for_target(mem_id)
        event = next(row for row in events if row["action"] == "substrate_metadata")
        payload = json.loads(event["body"])
        detail = payload["detail"]
        signature = detail.pop("update_signature")
        signed_bytes = json.dumps(
            detail,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        assert db.signer.verify_detached(
            signature,
            "agent:markdown-importer",
            signed_bytes,
            domain=_SUBSTRATE_METADATA_SIGNATURE_DOMAIN,
        )
        assert db.verify_audit() is True
    finally:
        db.close()


def test_absent_valid_until_preserves_a_separately_audited_expiry(tmp_path, monkeypatch):
    _set_custody_env(monkeypatch)
    memory = tmp_path / "memory"
    memory.mkdir()
    source = memory / "project_expiry_fixture.md"
    source.write_text(_frontmatter(), encoding="utf-8")
    db_path = tmp_path / "heartwood.db"
    first = _import(memory, db_path)
    mem_id = first["imported"][0]["id"]
    future_expiry = datetime.now(timezone.utc) + timedelta(days=30)

    db = _client(db_path)
    try:
        stored_expiry = db.expire(
            mem_id,
            future_expiry,
            actor="agent:lifecycle-operator",
            reason="separate lifecycle decision",
        )["to"]
    finally:
        db.close()

    source.write_text(_frontmatter(entities=["Heartwood"]), encoding="utf-8")
    refreshed = _import(memory, db_path, update=True, stop_on_error=True)
    assert refreshed["updated_count"] == 1

    db = _client(db_path)
    try:
        assert db.store.get_meta(mem_id)["valid_until"] == stored_expiry
    finally:
        db.close()

    source.write_text(
        _frontmatter(valid_until="null", entities=["Heartwood"]),
        encoding="utf-8",
    )
    cleared = _import(memory, db_path, update=True, stop_on_error=True)
    assert cleared["updated_count"] == 1
    db = _client(db_path)
    try:
        assert db.store.get_meta(mem_id)["valid_until"] is None
        assert db.verify_audit() is True
    finally:
        db.close()


def test_unknown_and_human_approved_truth_status_fail_closed(tmp_path, monkeypatch):
    _set_custody_env(monkeypatch)
    memory = tmp_path / "memory"
    memory.mkdir()
    source = memory / "project_truth_fixture.md"
    db_path = tmp_path / "heartwood.db"

    for invalid in ("mostly_true", "human_approved"):
        source.write_text(_frontmatter(truth_status=invalid), encoding="utf-8")
        report = _import(memory, db_path)
        assert report["ok"] is False
        assert report["imported_count"] == 0
        if invalid == "mostly_true":
            assert "truth_status must be one of" in report["errors"][0]["error"]
        else:
            assert "approve()" in report["errors"][0]["error"]


def test_metadata_update_rejects_invalid_values_without_row_or_audit_change(tmp_path, monkeypatch):
    _set_custody_env(monkeypatch)
    db = _client(tmp_path / "heartwood.db")
    try:
        mem_id = db.remember(
            "Fail-closed metadata fixture.",
            subject="fixture:fail-closed",
            created_by="agent:writer",
        )
        before = db.store.get_meta(mem_id)
        audit_before = len(db.store.audit_rows_for_target(mem_id))
        bad_updates = (
            {"valid_from": "not-a-date", "entities": ()},
            {"valid_from": None, "entities": "Heartwood"},
            {"valid_from": None, "entities": ("",)},
        )
        for bad in bad_updates:
            with pytest.raises((TypeError, ValueError)):
                db.update_substrate_metadata(
                    mem_id,
                    valid_from=bad["valid_from"],
                    valid_until=None,
                    entities=bad["entities"],
                    actor="agent:writer",
                )
        assert db.store.get_meta(mem_id) == before
        assert len(db.store.audit_rows_for_target(mem_id)) == audit_before
        with pytest.raises(PermissionError, match="approval lifecycle"):
            db.update_substrate_metadata(
                mem_id,
                valid_from=None,
                valid_until=None,
                entities=(),
                truth_status="human_approved",
                actor="agent:writer",
            )
        assert db.store.get_meta(mem_id) == before
        assert len(db.store.audit_rows_for_target(mem_id)) == audit_before
    finally:
        db.close()


def test_future_valid_from_positive_control_fails_the_write(tmp_path, monkeypatch):
    """@positive-control(substrate-metadata-future-valid-from)"""
    _set_custody_env(monkeypatch)
    db = _client(tmp_path / "heartwood.db")
    try:
        mem_id = db.remember(
            "Future-date positive-control fixture.",
            subject="fixture:future-date",
            created_by="agent:writer",
        )
        before = db.store.get_meta(mem_id)
        audit_before = len(db.store.audit_rows_for_target(mem_id))
        with pytest.raises(ValueError, match="cannot be in the future"):
            db.update_substrate_metadata(
                mem_id,
                valid_from="2999-01-01",
                valid_until=None,
                entities=("Heartwood",),
                actor="agent:writer",
            )
        assert db.store.get_meta(mem_id) == before
        assert len(db.store.audit_rows_for_target(mem_id)) == audit_before
    finally:
        db.close()


def test_human_approved_demotion_fails_direct_and_markdown_paths(tmp_path, monkeypatch):
    """@positive-control(human-approved-boundary)"""
    _set_custody_env(monkeypatch)
    memory = tmp_path / "memory"
    memory.mkdir()
    source = memory / "project_approved_fixture.md"
    source.write_text(_frontmatter(), encoding="utf-8")
    db_path = tmp_path / "heartwood.db"
    first = _import(memory, db_path)
    mem_id = first["imported"][0]["id"]

    db = _client(db_path)
    try:
        db.approve(
            mem_id,
            db.principal("user:approver", roles=("approver",)),
        )
        approved = db.store.get_meta(mem_id)
        audit_count = len(db.store.audit_rows_for_target(mem_id))
        with pytest.raises(PermissionError, match="approval lifecycle"):
            db.update_substrate_metadata(
                mem_id,
                valid_from=approved["valid_from"],
                valid_until=approved["valid_until"],
                entities=approved["entities"],
                truth_status="inferred",
                actor="agent:markdown-importer",
            )
        assert db.store.get_meta(mem_id) == approved
        assert len(db.store.audit_rows_for_target(mem_id)) == audit_count
    finally:
        db.close()

    source.write_text(_frontmatter(truth_status="inferred"), encoding="utf-8")
    report = _import(memory, db_path, update=True)
    assert report["ok"] is False
    assert report["updated_count"] == 0
    assert report["purged_count"] == 0
    assert "approval lifecycle" in report["errors"][0]["error"]

    db = _client(db_path)
    try:
        assert db.store.get_meta(mem_id) == approved
        assert len(db.store.audit_rows_for_target(mem_id)) == audit_count
    finally:
        db.close()


def _contextual_refresh_fixture(
    tmp_path,
    monkeypatch,
):
    _set_custody_env(monkeypatch)
    memory = tmp_path / "memory"
    memory.mkdir()
    source = memory / "project_contextual_fixture.md"
    source.write_text(_frontmatter(), encoding="utf-8")
    db_path = tmp_path / "heartwood.db"

    def fake_generator(**_kwargs):
        return "Metadata fixture context supported by the source."

    contextual = {
        "contextual_threshold_tokens": 1,
        "contextual_generator": fake_generator,
        "contextual_target_tokens": 7,
        "contextual_overlap": 0,
    }
    first = _import(memory, db_path, **contextual)
    chunk_ids = tuple(row["id"] for row in first["imported"])
    context_ids = tuple(row["context_id"] for row in first["imported"])
    assert chunk_ids

    db = _client(db_path)
    try:
        edges_before = tuple(
            db.store.conn.execute(
                "SELECT child, parent, kind FROM prov_edges ORDER BY child, parent, kind"
            ).fetchall()
        )
    finally:
        db.close()

    source.write_text(
        _frontmatter(
            valid_from="2026-01-15",
            entities=["Heartwood", "Contextual"],
            truth_status="inferred",
        ),
        encoding="utf-8",
    )
    refreshed = _import(memory, db_path, update=True, **contextual)

    db = _client(db_path)
    try:
        chunk_meta = tuple(db.store.get_meta(chunk_id) for chunk_id in chunk_ids)
        context_meta = tuple(db.store.get_meta(context_id) for context_id in context_ids)
        edges_after = tuple(
            db.store.conn.execute(
                "SELECT child, parent, kind FROM prov_edges ORDER BY child, parent, kind"
            ).fetchall()
        )
    finally:
        db.close()
    return {
        "chunk_ids": chunk_ids,
        "context_ids": context_ids,
        "chunk_meta": chunk_meta,
        "context_meta": context_meta,
        "edges_before": edges_before,
        "edges_after": edges_after,
        "refreshed": refreshed,
    }


def test_contextual_rows_receive_validity_and_entities_refresh(tmp_path, monkeypatch):
    result = _contextual_refresh_fixture(tmp_path, monkeypatch)
    refreshed = result["refreshed"]
    assert refreshed["imported_count"] == 0
    assert refreshed["updated_count"] == len(result["chunk_ids"]) + len(result["context_ids"])
    assert refreshed["purged_count"] == 0
    for meta in result["chunk_meta"] + result["context_meta"]:
        assert meta["valid_from"] == "2026-01-15T00:00:00+00:00"
        assert meta["entities"] == ("Heartwood", "Contextual")
    assert result["edges_after"] == result["edges_before"]


def test_contextual_truth_status_is_not_overwritten(tmp_path, monkeypatch):
    result = _contextual_refresh_fixture(tmp_path, monkeypatch)
    assert all(meta["truth_status"] == "inferred" for meta in result["chunk_meta"])
    assert all(
        meta["truth_status"] == "generated_supported"
        for meta in result["context_meta"]
    )


def test_contextual_pinned_memory_id_reimports_instead_of_metadata_refresh(tmp_path, monkeypatch):
    _set_custody_env(monkeypatch)
    memory = tmp_path / "memory"
    memory.mkdir()
    source = memory / "project_contextual_pinned_fixture.md"
    source.write_text(
        _frontmatter().replace(
            "epistemic: model-generated",
            "epistemic: model-generated\nmemory_id: contextual_pinned_fixture",
        ),
        encoding="utf-8",
    )
    db_path = tmp_path / "heartwood.db"

    def fake_generator(**_kwargs):
        return "Metadata fixture context supported by the source."

    contextual = {
        "contextual_threshold_tokens": 1,
        "contextual_generator": fake_generator,
        "contextual_target_tokens": 7,
        "contextual_overlap": 0,
    }
    first = _import(memory, db_path, **contextual)
    first_ids = {
        item_id
        for row in first["imported"]
        for item_id in (row["id"], row["context_id"])
    }
    refreshed = _import(memory, db_path, update=True, **contextual)

    assert refreshed["updated_count"] == 0
    assert refreshed["purged_count"] == len(first_ids)
    assert refreshed["imported_count"] == len(first["imported"])
    assert {
        item_id
        for row in refreshed["imported"]
        for item_id in (row["id"], row["context_id"])
    } == first_ids


def test_audit_append_failure_rolls_back_metadata_update(tmp_path, monkeypatch):
    _set_custody_env(monkeypatch)
    db = _client(tmp_path / "heartwood.db")
    try:
        mem_id = db.remember(
            "Atomic audit rollback fixture.",
            subject="fixture:atomic-audit",
            created_by="agent:writer",
        )
        before = db.store.get_meta(mem_id)
        original = db.store.append_audit_in_transaction

        def fail_audit(*_args, **_kwargs):
            raise RuntimeError("injected audit failure")

        db.store.append_audit_in_transaction = fail_audit
        try:
            with pytest.raises(RuntimeError, match="injected audit failure"):
                db.update_substrate_metadata(
                    mem_id,
                    valid_from="2026-01-01",
                    valid_until=None,
                    entities=("Heartwood",),
                    actor="agent:writer",
                )
        finally:
            db.store.append_audit_in_transaction = original
        assert db.store.get_meta(mem_id) == before
    finally:
        db.close()


def test_schema_has_no_trigger_that_writes_provenance_edges(tmp_path):
    db_path = tmp_path / "heartwood.db"
    db = _client(db_path)
    db.close()
    conn = sqlite3.connect(db_path)
    try:
        triggers = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND sql LIKE '%prov_edges%'"
        ).fetchall()
        assert triggers == []
    finally:
        conn.close()
