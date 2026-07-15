"""Markdown/frontmatter importer tests for generic Phase 1 ingestion."""
import base64
import os
import sys
import tempfile
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.contextual_ingest import CONTEXTUAL_AUX_POLICY_SCOPE  # noqa: E402
from heartwood.importers.markdown import dev_models, import_markdown_corpus  # noqa: E402


def _set_custody_env(root_byte: int = 11, key_id: str = "test-root-v1"):
    old = {
        "HEARTWOOD_KEY_CUSTODY_ROOT_B64": os.environ.get("HEARTWOOD_KEY_CUSTODY_ROOT_B64"),
        "HEARTWOOD_KEY_CUSTODY_KEY_ID": os.environ.get("HEARTWOOD_KEY_CUSTODY_KEY_ID"),
    }
    os.environ["HEARTWOOD_KEY_CUSTODY_ROOT_B64"] = (
        base64.urlsafe_b64encode(bytes([root_byte]) * 32).decode("ascii").rstrip("=")
    )
    os.environ["HEARTWOOD_KEY_CUSTODY_KEY_ID"] = key_id
    return old


def _clear_custody_env():
    old = {
        "HEARTWOOD_KEY_CUSTODY_ROOT_B64": os.environ.get("HEARTWOOD_KEY_CUSTODY_ROOT_B64"),
        "HEARTWOOD_KEY_CUSTODY_KEY_ID": os.environ.get("HEARTWOOD_KEY_CUSTODY_KEY_ID"),
    }
    os.environ.pop("HEARTWOOD_KEY_CUSTODY_ROOT_B64", None)
    os.environ.pop("HEARTWOOD_KEY_CUSTODY_KEY_ID", None)
    return old


def _restore_env(old):
    for key, value in old.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def test_markdown_importer_infers_tenant_epistemic_and_policy():
    embedder, reranker = dev_models()
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = root / "memory"
        memory.mkdir()
        team_memory = root / "team-memory"
        team_memory.mkdir()
        (memory / "feedback_acme_owner_guidance.md").write_text(
            "# Acme Payments guidance\n\nAlways preserve audit details.",
            encoding="utf-8",
        )
        (team_memory / "feedback_team_guidance.md").write_text(
            "# Team guidance\n\nEscalate product-memory changes to the operator.",
            encoding="utf-8",
        )
        (memory / "reference_northwind_auth.md").write_text(
            "---\n"
            "tenant: northwind-retail\n"
            "classification: confidential\n"
            "roles: [finance]\n"
            "subject: northwind-retail:auth\n"
            "subject_ids: [northwind-retail, auth]\n"
            "---\n"
            "# Northwind Retail Auth\n\nNorthwind Retail auth incidents require finance review.",
            encoding="utf-8",
        )
        (memory / "project_gpt55_token_efficiency_hypothesis.md").write_text(
            "# GPT-5.5 token efficiency hypothesis\n\nToken savings may improve review throughput.",
            encoding="utf-8",
        )

        db_path = root / "heartwood.db"
        report = import_markdown_corpus(
            [memory, team_memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )

        assert report["imported_count"] == 4
        assert report["skipped_count"] == 0
        assert report["tenant_counts"] == {
            "tenant:acme-payments": 1,
            "tenant:northwind-retail": 1,
            "tenant:ops": 2,
        }
        paths = {row["path"] for row in report["imported"]}
        assert "memory/feedback_acme_owner_guidance.md" in paths
        assert "team-memory/feedback_team_guidance.md" in paths

        second = import_markdown_corpus(
            [memory, team_memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )
        assert second["imported_count"] == 0
        assert second["skipped_count"] == 4

        northwind_id = next(row["id"] for row in report["imported"] if row["tenant"] == "tenant:northwind-retail")
        northwind = Heartwood(path=str(db_path), tenant="tenant:northwind-retail", embedder=embedder, reranker=reranker)
        try:
            meta = northwind.store.get_meta(northwind_id)
            assert meta is not None
            assert meta["epistemic"] == "imported-source"
            assert meta["kind"] == "source"
            assert meta["classification"] == "confidential"
            assert meta["roles"] == ("finance",)
            assert meta["subject"] == "northwind-retail:auth"
            assert meta["subject_ids"] == ("northwind-retail", "auth")

            no_role = Principal(id="agent:ops", tenant="tenant:northwind-retail", roles=(), clearance="confidential")
            assert northwind.recall("finance review auth incident", principal=no_role, k=5)["results"] == []

            finance = Principal(id="agent:finance", tenant="tenant:northwind-retail", roles=("finance",), clearance="confidential")
            out = northwind.recall("finance review auth incident", principal=finance, k=5)
            assert [result["id"] for result in out["results"]] == [northwind_id]
        finally:
            northwind.store.close()

        ops_id = next(row["id"] for row in report["imported"] if row["path"].endswith("project_gpt55_token_efficiency_hypothesis.md"))
        ops = Heartwood(path=str(db_path), tenant="tenant:ops", embedder=embedder, reranker=reranker)
        try:
            assert ops.store.get_meta(ops_id)["epistemic"] == "hypothesis"
        finally:
            ops.store.close()


def test_markdown_importer_scans_roots_under_hidden_ancestors():
    embedder, reranker = dev_models()
    old_env = _set_custody_env(root_byte=31, key_id="test-root-hidden")
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            memory = root / ".claude" / "projects" / "memory"
            hidden_dir = memory / ".private"
            hidden_dir.mkdir(parents=True)
            (memory / "reference_visible.md").write_text(
                "Visible row under a dotted ancestor must import.",
                encoding="utf-8",
            )
            (memory / ".hidden_file.md").write_text(
                "Hidden files inside the scan root stay excluded.",
                encoding="utf-8",
            )
            (hidden_dir / "reference_hidden.md").write_text(
                "Hidden directories inside the scan root stay excluded.",
                encoding="utf-8",
            )
            db_path = root / "heartwood.db"

            report = import_markdown_corpus(
                [memory],
                db_path=db_path,
                embedder=embedder,
                reranker=reranker,
            )

            assert report["ok"] is True
            assert report["source_count"] == 1
            assert report["source_counts"][str(memory)] == 1
            assert report["imported_count"] == 1
            assert report["imported"][0]["path"] == "memory/reference_visible.md"
    finally:
        _restore_env(old_env)


def test_markdown_importer_reports_directory_noop_as_error():
    embedder, reranker = dev_models()
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = root / ".claude" / "projects" / "memory"
        memory.mkdir(parents=True)
        db_path = root / "heartwood.db"

        report = import_markdown_corpus(
            [memory],
            db_path=db_path,
            embedder=embedder,
            reranker=reranker,
        )

        assert report["ok"] is False
        assert report["source_count"] == 0
        assert report["source_counts"][str(memory)] == 0
        assert report["failed_count"] == 1
        assert report["errors"][0]["path"] == str(memory)
        assert "zero markdown documents" in report["errors"][0]["error"]


def test_markdown_importer_refuses_embedding_dimension_mismatch():
    embedder, reranker = dev_models()

    def embed_384(texts):
        vectors = np.zeros((len(texts), 384), dtype=np.float32)
        vectors[:, 0] = 1.0
        return vectors

    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = root / "memory"
        memory.mkdir()
        (memory / "reference_alpha.md").write_text(
            "Alpha row establishes the dev-model embedding dimension.",
            encoding="utf-8",
        )
        db_path = root / "heartwood.db"

        first = import_markdown_corpus(
            [memory],
            db_path=db_path,
            embedder=embedder,
            reranker=reranker,
        )
        assert first["ok"] is True
        assert first["memory_row_count_after"] == 1

        (memory / "reference_beta.md").write_text(
            "Beta row must not contaminate the store with a second dimension.",
            encoding="utf-8",
        )
        mismatched = import_markdown_corpus(
            [memory],
            db_path=db_path,
            embedder=(embed_384, "test-embedder-384"),
            reranker=reranker,
        )

        assert mismatched["ok"] is False
        assert mismatched["imported_count"] == 0
        assert mismatched["failed_count"] == 1
        assert mismatched["memory_row_count_before"] == 1
        assert mismatched["memory_row_count_after"] == 1
        assert mismatched["errors"][0]["code"] == "embedding_dimension_mismatch"
        assert "existing indexed rows have dimensions [256]" in mismatched["errors"][0]["error"]


def test_markdown_importer_reimport_imports_new_files_with_same_custody_root():
    embedder, reranker = dev_models()
    old_env = _set_custody_env()
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            memory = root / "memory"
            memory.mkdir()
            (memory / "reference_alpha.md").write_text(
                "Alpha import should persist a custody-backed signer.",
                encoding="utf-8",
            )
            db_path = root / "heartwood.db"

            first = import_markdown_corpus(
                [memory],
                db_path=db_path,
                created_by="agent:markdown-importer",
                embedder=embedder,
                reranker=reranker,
            )
            assert first["imported_count"] == 1
            assert first["skipped_count"] == 0
            assert first["source_lag_count"] == 0
            assert first["memory_row_count_delta"] == 1

            (memory / "reference_beta.md").write_text(
                "Beta import should succeed on a later importer process.",
                encoding="utf-8",
            )
            second = import_markdown_corpus(
                [memory],
                db_path=db_path,
                created_by="agent:markdown-importer",
                embedder=embedder,
                reranker=reranker,
            )
            assert second["imported_count"] == 1
            assert second["skipped_count"] == 1
            assert second["source_coverage_count"] == 2
            assert second["source_lag_count"] == 0
            assert second["memory_row_count_delta"] == 1

            third = import_markdown_corpus(
                [memory],
                db_path=db_path,
                created_by="agent:markdown-importer",
                embedder=embedder,
                reranker=reranker,
            )
            assert third["imported_count"] == 0
            assert third["skipped_count"] == 2
            assert third["source_lag_count"] == 0
            assert third["memory_row_count_delta"] == 0
    finally:
        _restore_env(old_env)


def test_markdown_importer_extends_legacy_public_key_store_after_custody_enabled():
    embedder, reranker = dev_models()
    with tempfile.TemporaryDirectory() as temp_dir:
        old_env = _clear_custody_env()
        try:
            root = Path(temp_dir)
            memory = root / "memory"
            memory.mkdir()
            (memory / "reference_legacy.md").write_text(
                "Legacy import created an orphaned public signing key.",
                encoding="utf-8",
            )
            db_path = root / "heartwood.db"

            first = import_markdown_corpus(
                [memory],
                db_path=db_path,
                created_by="agent:markdown-importer",
                embedder=embedder,
                reranker=reranker,
            )
            assert first["imported_count"] == 1
        finally:
            _restore_env(old_env)

        old_env = _set_custody_env(root_byte=12, key_id="test-root-v2")
        try:
            (memory / "reference_new.md").write_text(
                "New import must sign with the custody key without invalidating legacy signatures.",
                encoding="utf-8",
            )
            second = import_markdown_corpus(
                [memory],
                db_path=db_path,
                created_by="agent:markdown-importer",
                embedder=embedder,
                reranker=reranker,
            )
            assert second["imported_count"] == 1
            assert second["skipped_count"] == 1
            assert second["source_lag_count"] == 0

            db = Heartwood(path=str(db_path), tenant="tenant:ops", embedder=embedder, reranker=reranker)
            try:
                alias_count = db.store.conn.execute(
                    "SELECT COUNT(*) FROM principal_key_aliases "
                    "WHERE tenant=? AND principal_id=?",
                    ("tenant:ops", "agent:markdown-importer"),
                ).fetchone()[0]
                assert alias_count == 1
                out = db.recall(
                    "legacy new import",
                    principal=Principal(id="agent:reader", tenant="tenant:ops"),
                    k=5,
                )
                assert {row["provenance"]["signature_valid"] for row in out["results"]} == {True}
            finally:
                db.store.close()
        finally:
            _restore_env(old_env)


def test_markdown_importer_isolates_bad_files_and_reports_errors():
    embedder, reranker = dev_models()
    old_env = _set_custody_env(root_byte=21, key_id="test-root-errors")
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            memory = root / "memory"
            memory.mkdir()
            (memory / "reference_good.md").write_text(
                "Good row survives a malformed neighbor.",
                encoding="utf-8",
            )
            (memory / "reference_bad.md").write_text(
                "---\nkind: impossible-kind\n---\nBad row should be reported.",
                encoding="utf-8",
            )
            db_path = root / "heartwood.db"

            report = import_markdown_corpus(
                [memory],
                db_path=db_path,
                embedder=embedder,
                reranker=reranker,
            )

            assert report["ok"] is False
            assert report["imported_count"] == 1
            assert report["failed_count"] == 1
            assert report["errors"][0]["path"] == "memory/reference_bad.md"
            assert "impossible-kind" in report["errors"][0]["error"]

            db = Heartwood(path=str(db_path), tenant="tenant:ops", embedder=embedder, reranker=reranker)
            try:
                out = db.recall(
                    "malformed neighbor",
                    principal=Principal(id="agent:reader", tenant="tenant:ops"),
                    k=5,
                )
                assert [row["content"] for row in out["results"]] == [
                    "Good row survives a malformed neighbor."
                ]
            finally:
                db.close()
    finally:
        _restore_env(old_env)


def test_markdown_importer_update_supersedes_source_path_rows():
    embedder, reranker = dev_models()
    old_env = _set_custody_env(root_byte=22, key_id="test-root-update")
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            memory = root / "memory"
            memory.mkdir()
            source = memory / "reference_edit.md"
            source.write_text("Alpha original recall anchor.", encoding="utf-8")
            db_path = root / "heartwood.db"

            first = import_markdown_corpus([memory], db_path=db_path, embedder=embedder, reranker=reranker)
            assert first["imported_count"] == 1

            source.write_text("Beta no-update duplicate anchor.", encoding="utf-8")
            duplicate = import_markdown_corpus([memory], db_path=db_path, embedder=embedder, reranker=reranker)
            assert duplicate["imported_count"] == 1
            assert duplicate["superseded_count"] == 0
            assert duplicate["memory_row_count_after"] == 2

            source.write_text("Gamma update replacement anchor.", encoding="utf-8")
            updated = import_markdown_corpus(
                [memory],
                db_path=db_path,
                embedder=embedder,
                reranker=reranker,
                update=True,
            )
            assert updated["imported_count"] == 1
            assert updated["superseded_count"] == 2
            assert updated["memory_row_count_after"] == 1

            db = Heartwood(path=str(db_path), tenant="tenant:ops", embedder=embedder, reranker=reranker)
            try:
                out = db.recall(
                    "alpha beta gamma replacement",
                    principal=Principal(id="agent:reader", tenant="tenant:ops"),
                    k=5,
                )
                assert [row["content"] for row in out["results"]] == [
                    "Gamma update replacement anchor."
                ]
            finally:
                db.close()
    finally:
        _restore_env(old_env)


def test_markdown_importer_failed_update_does_not_purge_prior_rows():
    embedder, reranker = dev_models()
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = root / "memory"
        memory.mkdir()
        source = memory / "reference_reimport.md"
        source.write_text("Original row must survive failed replacement.", encoding="utf-8")
        db_path = root / "heartwood.db"

        old_env = _set_custody_env(root_byte=33, key_id="test-root-survive")
        try:
            first = import_markdown_corpus(
                [memory],
                db_path=db_path,
                created_by="agent:markdown-importer",
                embedder=embedder,
                reranker=reranker,
            )
            assert first["imported_count"] == 1
            original_id = first["imported"][0]["id"]
        finally:
            _restore_env(old_env)

        source.write_text("Replacement row cannot sign without custody env.", encoding="utf-8")
        old_env = _clear_custody_env()
        try:
            failed = import_markdown_corpus(
                [memory],
                db_path=db_path,
                created_by="agent:markdown-importer",
                embedder=embedder,
                reranker=reranker,
                update=True,
            )
        finally:
            _restore_env(old_env)

        assert failed["ok"] is False
        assert failed["imported_count"] == 0
        assert failed["superseded_count"] == 0
        assert failed["memory_row_count_before"] == 1
        assert failed["memory_row_count_after"] == 1
        assert "matching private key" in failed["errors"][0]["error"]

        old_env = _set_custody_env(root_byte=33, key_id="test-root-survive")
        try:
            db = Heartwood(path=str(db_path), tenant="tenant:ops", embedder=embedder, reranker=reranker)
            try:
                assert db.store.get_meta(original_id) is not None
                out = db.recall(
                    "original survive replacement",
                    principal=Principal(id="agent:reader", tenant="tenant:ops"),
                    k=5,
                )
                assert [row["content"] for row in out["results"]] == [
                    "Original row must survive failed replacement."
                ]
            finally:
                db.close()
        finally:
            _restore_env(old_env)


def test_markdown_importer_update_replaces_pinned_memory_id():
    embedder, reranker = dev_models()
    old_env = _set_custody_env(root_byte=23, key_id="test-root-pinned-update")
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            memory = root / "memory"
            memory.mkdir()
            source = memory / "reference_pinned.md"
            source.write_text(
                "---\nmemory_id: pinned_edit_demo\n---\nPinned original anchor.",
                encoding="utf-8",
            )
            db_path = root / "heartwood.db"

            first = import_markdown_corpus([memory], db_path=db_path, embedder=embedder, reranker=reranker)
            assert first["imported_count"] == 1

            source.write_text(
                "---\nmemory_id: pinned_edit_demo\n---\nPinned updated anchor.",
                encoding="utf-8",
            )
            updated = import_markdown_corpus(
                [memory],
                db_path=db_path,
                embedder=embedder,
                reranker=reranker,
                update=True,
            )
            assert updated["imported_count"] == 1
            assert updated["superseded_count"] == 1
            assert updated["imported"][0]["id"] == "pinned_edit_demo"

            db = Heartwood(path=str(db_path), tenant="tenant:ops", embedder=embedder, reranker=reranker)
            try:
                assert db.read_content("pinned_edit_demo") == "Pinned updated anchor."
            finally:
                db.close()
    finally:
        _restore_env(old_env)


def test_markdown_importer_routes_large_docs_through_contextual_ingest_only_when_configured():
    def fake_generator(**_kwargs):
        return "Alpha retrieval anchors phasebonus"

    embedder, reranker = dev_models()
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = root / "memory"
        memory.mkdir()
        (memory / "reference_contextual_large.md").write_text(
            "# Contextual Large\n\n"
            "Alpha retrieval anchors explain governed memory chunks.\n\n"
            "# Bonus\n\n"
            "Phasebonus retrieval anchors remain in the neighboring section.",
            encoding="utf-8",
        )
        (memory / "reference_small.md").write_text(
            "Small source memory stays whole.",
            encoding="utf-8",
        )
        db_path = root / "heartwood.db"

        report = import_markdown_corpus(
            [memory],
            db_path=db_path,
            embedder=embedder,
            reranker=reranker,
            contextual_threshold_tokens=8,
            contextual_generator=fake_generator,
            contextual_target_tokens=7,
            contextual_overlap=0,
        )

        contextual_rows = [
            row for row in report["imported"]
            if row["path"] == "memory/reference_contextual_large.md"
        ]
        small_rows = [
            row for row in report["imported"]
            if row["path"] == "memory/reference_small.md"
        ]
        assert contextual_rows
        assert all(row["ingest_mode"] == "contextual" for row in contextual_rows)
        assert all(row.get("context_id") for row in contextual_rows)
        assert len(small_rows) == 1
        assert "ingest_mode" not in small_rows[0]

        db = Heartwood(path=str(db_path), tenant="tenant:ops", embedder=embedder, reranker=reranker)
        try:
            context_meta = db.store.get_meta(contextual_rows[0]["context_id"])
            assert context_meta["epistemic"] == "model-generated"
            assert context_meta["policy_scope"] == CONTEXTUAL_AUX_POLICY_SCOPE
            second = import_markdown_corpus(
                [memory],
                db_path=db_path,
                embedder=embedder,
                reranker=reranker,
                contextual_threshold_tokens=8,
                contextual_generator=fake_generator,
                contextual_target_tokens=7,
                contextual_overlap=0,
            )
            assert second["imported_count"] == 0
            assert second["skipped_count"] == 2
        finally:
            db.store.close()


def main():
    test_markdown_importer_infers_tenant_epistemic_and_policy()
    test_markdown_importer_scans_roots_under_hidden_ancestors()
    test_markdown_importer_reports_directory_noop_as_error()
    test_markdown_importer_refuses_embedding_dimension_mismatch()
    test_markdown_importer_reimport_imports_new_files_with_same_custody_root()
    test_markdown_importer_extends_legacy_public_key_store_after_custody_enabled()
    test_markdown_importer_isolates_bad_files_and_reports_errors()
    test_markdown_importer_update_supersedes_source_path_rows()
    test_markdown_importer_failed_update_does_not_purge_prior_rows()
    test_markdown_importer_update_replaces_pinned_memory_id()
    test_markdown_importer_routes_large_docs_through_contextual_ingest_only_when_configured()
    print("MARKDOWN IMPORTER TESTS PASSED")


if __name__ == "__main__":
    main()
