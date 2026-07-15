"""Phase 1 B3 tenant/provenance/classification API ergonomics tests."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, normalize_tenant, policy_from, principal_from  # noqa: E402
from heartwood.importers.markdown import dev_models  # noqa: E402


def _records() -> list[dict]:
    return [
        {
            "tenant": "acme-payments",
            "subject": "acme-payments:audit",
            "content": "Acme Payments reviews must preserve audit details, source spans, and provenance.",
            "created_by": "owner:operator",
            "classification": "internal",
            "source_uri": "doc://acme-payments/audit-guidance",
            "entities": ["acme-payments", "audit"],
        },
        {
            "tenant": "northwind-retail",
            "subject": "northwind-retail:auth",
            "content": "Northwind Retail finance incidents require finance review before auth changes ship.",
            "created_by": "agent:reviewer",
            "classification": "confidential",
            "roles": ["finance"],
            "source": {"kind": "fixture", "uri": "doc://northwind-retail/auth-review"},
            "subject_ids": ["northwind-retail", "auth"],
        },
        {
            "tenant": "ops",
            "subject": "ops:dispatch",
            "content": "Security dispatch memory stays restricted to security operators in region us.",
            "created_by": "agent:orchestrator",
            "classification": "restricted",
            "pii": True,
            "roles": "security",
            "attrs": {"region": "us"},
            "source_uri": "doc://ops/security-dispatch",
        },
    ]


def test_bulk_public_api_routes_records_by_tenant_and_preserves_governance():
    embedder, reranker = dev_models()
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "heartwood.db"
        db = Heartwood(path=db_path, tenant="tenant:ops", embedder=embedder, reranker=reranker)
        try:
            assert normalize_tenant("acme-payments") == "tenant:acme-payments"
            assert policy_from({"classification": "confidential", "roles": "finance"}).roles == ("finance",)
            assert principal_from("agent:orchestrator", tenant="ops").tenant == "tenant:ops"

            report = db.remember_many(_records(), default_created_by="agent:bulk")
            assert report["ok"] is True
            assert report["imported_count"] == 3
            assert report["failed_count"] == 0
            assert report["tenant_counts"] == {
                "tenant:acme-payments": 1,
                "tenant:northwind-retail": 1,
                "tenant:ops": 1,
            }
            assert report["provenance_coverage"] == {"with_source_ids": 3, "with_source_spans": 3}

            acme = db.recall_for_tenant(
                "acme-payments",
                "what must Acme Payments reviews preserve?",
                principal_id="agent:orchestrator",
                k=3,
            )
            assert len(acme["results"]) == 1
            assert acme["results"][0]["classification"] == "internal"
            assert acme["results"][0]["source_ids"] == ("doc://acme-payments/audit-guidance",)
            assert acme["results"][0]["provenance"]["signature_valid"] is True
            assert acme["results"][0]["provenance"]["content_hash_match"] is True

            northwind = db.with_tenant("northwind-retail")
            try:
                no_role = northwind.recall(
                    "auth finance review",
                    principal=northwind.principal("agent:ops", clearance="confidential"),
                    k=3,
                )
                assert no_role["results"] == []

                finance = northwind.recall(
                    "auth finance review",
                    principal=northwind.principal("agent:finance", roles="finance", clearance="confidential"),
                    k=3,
                )
                assert len(finance["results"]) == 1
                assert finance["results"][0]["classification"] == "confidential"
                assert finance["results"][0]["provenance"]["signature_valid"] is True
            finally:
                northwind.close()
        finally:
            db.close()


def test_bulk_remember_cli_imports_jsonl_records():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        records_path = root / "records.jsonl"
        records_path.write_text(
            "\n".join(json.dumps(record) for record in _records()),
            encoding="utf-8",
        )
        db_path = root / "heartwood.db"

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "bulk-remember",
                "--input",
                str(records_path),
                "--db",
                str(db_path),
                "--tenant",
                "tenant:ops",
                "--created-by",
                "agent:bulk",
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(proc.stdout)
        assert out["imported_count"] == 3
        assert out["failed_count"] == 0
        assert out["provenance_coverage"]["with_source_spans"] == 3

        embedder, reranker = dev_models()
        northwind = Heartwood(path=db_path, tenant="tenant:northwind-retail", embedder=embedder, reranker=reranker)
        try:
            recalled = northwind.recall(
                "finance review auth changes",
                principal=northwind.principal("agent:finance", roles=("finance",), clearance="confidential"),
                k=3,
            )
            assert len(recalled["results"]) == 1
            assert recalled["results"][0]["provenance"]["signature_valid"] is True
        finally:
            northwind.close()


def main():
    test_bulk_public_api_routes_records_by_tenant_and_preserves_governance()
    test_bulk_remember_cli_imports_jsonl_records()
    print("BULK API TESTS PASSED")


if __name__ == "__main__":
    main()
