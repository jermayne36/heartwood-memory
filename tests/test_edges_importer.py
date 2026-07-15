"""Provenance/graph edge importer tests."""
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.importers.edges import import_edges  # noqa: E402
from heartwood.importers.markdown import dev_models, import_markdown_corpus  # noqa: E402


TENANT = "tenant:ops"


def test_import_edges_from_markdown_wikilinks_reports_dangling_links():
    embedder, reranker = dev_models()
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = root / "memory"
        memory.mkdir()
        (memory / "alpha.md").write_text(
            "# Alpha\n\nAlpha links to [[beta]] and [[missing target]].",
            encoding="utf-8",
        )
        (memory / "beta.md").write_text(
            "# Beta\n\nBeta is a linked memory.",
            encoding="utf-8",
        )
        db_path = root / "heartwood.db"
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            embedder=embedder,
            reranker=reranker,
        )

        report = import_edges(db_path=db_path, sources=[memory], tenant=TENANT)

        assert report["edge_count_before"] == 0
        assert report["edge_count_after"] == 1
        assert report["wikilinks"]["link_count"] == 2
        assert report["wikilinks"]["inserted_count"] == 1
        assert report["wikilinks"]["dangling_count"] == 1
        assert report["wikilinks"]["dangling_examples"][0]["target"] == "missing target"
        assert report["failed_count"] == 0


def test_import_edges_from_proposal_is_idempotent_and_explainable():
    embedder, reranker = dev_models()
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        db_path = root / "heartwood.db"
        db = Heartwood(path=str(db_path), tenant=TENANT, embedder=embedder, reranker=reranker)
        try:
            alpha_id = db.remember(
                "Alpha invoice policy requires beta review.",
                subject="memory:ops:alpha",
                created_by="agent:test",
                memory_id="mem_alpha",
            )
            beta_id = db.remember(
                "Beta review explains the alpha invoice policy.",
                subject="memory:ops:beta",
                created_by="agent:test",
                memory_id="mem_beta",
            )
        finally:
            db.close()

        proposal = root / "proposal.jsonl"
        proposal.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "src_id": alpha_id,
                            "dst_id": beta_id,
                            "type": "applies_to",
                            "confidence": 0.9,
                        }
                    ),
                    json.dumps(
                        {
                            "src_id": alpha_id,
                            "dst_id": "missing_memory",
                            "type": "derived_from",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        first = import_edges(db_path=db_path, proposal_jsonl=proposal, tenant=TENANT)
        second = import_edges(db_path=db_path, proposal_jsonl=proposal, tenant=TENANT)

        assert first["proposal"]["row_count"] == 2
        assert first["proposal"]["inserted_count"] == 1
        assert first["proposal"]["skipped_missing_count"] == 1
        assert first["edge_count_after"] == 1
        assert second["proposal"]["duplicate_count"] == 1
        assert second["edge_count_after"] == 1

        conn = sqlite3.connect(db_path)
        try:
            assert conn.execute("SELECT COUNT(*) FROM prov_edges").fetchone()[0] == 1
        finally:
            conn.close()

        db = Heartwood(path=str(db_path), tenant=TENANT, embedder=embedder, reranker=reranker)
        try:
            recall = db.recall(
                "alpha beta invoice review policy",
                principal=Principal(id="agent:test", tenant=TENANT),
                filters={"method": "lexical"},
                k=2,
            )
            explain = db.explain_recall(recall["recall_id"])
        finally:
            db.close()

        assert explain["result_ids"] == [alpha_id, beta_id]
        assert explain["graph_paths"] == [
            {
                "from": alpha_id,
                "to": beta_id,
                "child": alpha_id,
                "parent": beta_id,
                "kind": "applies_to",
                "path": [alpha_id, beta_id],
            }
        ]
