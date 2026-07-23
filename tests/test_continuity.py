"""Security and recall-boundary tests for the continuity core."""
from __future__ import annotations

import copy
import json
import os
import re
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.adapters.mcp_server import MCPMemoryAPI  # noqa: E402
from heartwood.continuity import (  # noqa: E402
    CONTRACT_SCHEMA_VERSION,
    CONTINUITY_ADMIN_ROLE,
    RECEIPT_SCHEMA_VERSION,
    BaselineBinding,
    CapabilityContract,
    Continuity,
    ContinuityIntegrityError,
    ContinuityValidationError,
    ContractBinding,
    ErrorCategory,
    EvalSuiteBinding,
    GenesisMarker,
    RotationReceiptDraft,
    SignedRotationReceipt,
    content_hash,
    sanitize_error_category,
)
from heartwood.importers.markdown import dev_models  # noqa: E402


TENANT = "tenant:continuity-test"
ROUTE_A = "route_aaaaaaaaaaaaaaaa"
ROUTE_B = "route_bbbbbbbbbbbbbbbb"
CASE_A = "case_aaaaaaaaaaaaaaaa"
CASE_B = "case_bbbbbbbbbbbbbbbb"
SUITE_ID = "suite_aaaaaaaaaaaaaaaa"
RUN_ID = "run_aaaaaaaaaaaaaaaa"
RECEIPT_ID = "rot_aaaaaaaaaaaaaaaa"
RECEIPT_ID_2 = "rot_cccccccccccccccc"
BASELINE_ID = "rot_bbbbbbbbbbbbbbbb"
BASELINE_HASH = "sha256:" + "b" * 64
EVAL_HASH = "sha256:" + "e" * 64


def _db(path: str | Path = ":memory:") -> Heartwood:
    embedder, reranker = dev_models()
    return Heartwood(
        path=path,
        tenant=TENANT,
        embedder=embedder,
        reranker=reranker,
    )


def _admin() -> Principal:
    return Principal(
        id="agent:continuity-test",
        tenant=TENANT,
        roles=(CONTINUITY_ADMIN_ROLE,),
        clearance="confidential",
    )


def _contract_dict(route_id: str, target_route_id: str) -> dict:
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "route_id": route_id,
        "provider": "provider.catalog",
        "model": "model/catalog-v1",
        "tool_use": True,
        "structured_output": {
            "json_mode": True,
            "json_schema": True,
            "grammar": False,
        },
        "context_window_tokens": 200_000,
        "latency_class": "interactive",
        "price_class": "standard",
        "residency": "us-east",
        "fallback": {
            "on_error": {
                "target_route_id": target_route_id,
                "policy": "degrade",
            },
            "on_degraded": {
                "target_route_id": target_route_id,
                "policy": "retry_then_degrade",
            },
        },
    }


def _contracts() -> tuple[CapabilityContract, CapabilityContract]:
    return (
        CapabilityContract.from_dict(_contract_dict(ROUTE_A, ROUTE_B)),
        CapabilityContract.from_dict(_contract_dict(ROUTE_B, ROUTE_A)),
    )


def _draft_dict(
    from_contract: CapabilityContract,
    to_contract: CapabilityContract,
    *,
    evidence_mode: str = "prototype",
    receipt_id: str = RECEIPT_ID,
    prior_baseline: dict | None = None,
) -> dict:
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "evidence_mode": evidence_mode,
        "from_route": from_contract.route_id,
        "to_route": to_contract.route_id,
        "from_contract": {
            "route_id": from_contract.route_id,
            "schema_version": from_contract.schema_version,
            "contract_hash": from_contract.contract_hash,
        },
        "to_contract": {
            "route_id": to_contract.route_id,
            "schema_version": to_contract.schema_version,
            "contract_hash": to_contract.contract_hash,
        },
        "eval_suite": {
            "eval_suite_id": SUITE_ID,
            "schema_version": "3",
            "eval_suite_hash": EVAL_HASH,
        },
        "run_id": RUN_ID,
        "prior_baseline": prior_baseline or {"is_genesis": True},
        "ts": "2026-07-23T17:00:00Z",
        "cases": [
            {
                "case_id": CASE_A,
                "before": "pass",
                "after": "pass",
                "delta": 0.0,
                "before_error_category": None,
                "after_error_category": None,
                "fallback": {
                    "attempted": False,
                    "fallback_exercised": False,
                },
            },
            {
                "case_id": CASE_B,
                "before": "pass",
                "after": "degraded",
                "delta": -0.12,
                "before_error_category": None,
                "after_error_category": None,
                "fallback": {
                    "attempted": True,
                    "fallback_exercised": True,
                    "trigger": "on_degraded",
                    "target_route_id": from_contract.route_id,
                    "result": "pass",
                    "error_category": None,
                },
            },
        ],
        "summary": {
            "passed": 1,
            "degraded": 1,
            "failed": 0,
        },
    }


def _seed_contracts(
    db: Heartwood,
) -> tuple[Continuity, CapabilityContract, CapabilityContract]:
    continuity = Continuity(db)
    from_contract, to_contract = _contracts()
    stored_from = continuity.store_capability_contract(
        from_contract,
        principal=_admin(),
    )
    stored_to = continuity.store_capability_contract(
        to_contract,
        principal=_admin(),
    )
    return (
        continuity,
        continuity.get_capability_contract(
            stored_from.memory_id,
            principal=_admin(),
        ),
        continuity.get_capability_contract(
            stored_to.memory_id,
            principal=_admin(),
        ),
    )


def _baseline_binding(receipt: SignedRotationReceipt) -> dict:
    return {
        "receipt_id": receipt.draft.receipt_id,
        "receipt_hash": receipt.receipt_hash,
        "audit_seq": receipt.audit_seq,
    }


def test_closed_schema_rejects_unknown_fields():
    contract = _contract_dict(ROUTE_A, ROUTE_B)
    contract["prompt"] = "not allowed"
    with pytest.raises(ContinuityValidationError, match="capability_contract_fields"):
        CapabilityContract.from_dict(contract)

    from_contract, to_contract = _contracts()
    draft = _draft_dict(from_contract, to_contract)
    draft["cases"][0]["evidence"] = "not allowed"
    with pytest.raises(ContinuityValidationError, match="rotation_case_fields"):
        RotationReceiptDraft.from_dict(draft)


def test_bounded_values_are_enforced():
    contract = _contract_dict(ROUTE_A, ROUTE_B)
    contract["context_window_tokens"] = 10_000_001
    with pytest.raises(ContinuityValidationError, match="context_window_tokens"):
        CapabilityContract.from_dict(contract)

    from_contract, to_contract = _contracts()
    draft = _draft_dict(from_contract, to_contract)
    draft["cases"][1]["delta"] = -1.01
    with pytest.raises(ContinuityValidationError, match="delta"):
        RotationReceiptDraft.from_dict(draft)

    mismatch = _draft_dict(from_contract, to_contract)
    mismatch["summary"]["passed"] = 2
    with pytest.raises(ContinuityValidationError, match="summary_mismatch"):
        RotationReceiptDraft.from_dict(mismatch)


def test_unobserved_fallback_is_rejected():
    from_contract, to_contract = _contracts()
    missing_result = _draft_dict(from_contract, to_contract)
    del missing_result["cases"][1]["fallback"]["result"]
    with pytest.raises(ContinuityValidationError, match="fallback_observation_fields"):
        RotationReceiptDraft.from_dict(missing_result)

    false_claim = _draft_dict(from_contract, to_contract)
    false_claim["cases"][0]["fallback"]["fallback_exercised"] = True
    with pytest.raises(ContinuityValidationError, match="unobserved_fallback"):
        RotationReceiptDraft.from_dict(false_claim)

    unattempted_detail = _draft_dict(from_contract, to_contract)
    unattempted_detail["cases"][0]["fallback"]["result"] = "pass"
    with pytest.raises(ContinuityValidationError, match="fallback_observation_fields"):
        RotationReceiptDraft.from_dict(unattempted_detail)


def test_fixed_error_sanitization_discards_raw_message():
    sentinel = "hw_secret_sentinel_error_message"
    category = sanitize_error_category(RuntimeError(sentinel))
    assert category is ErrorCategory.INTERNAL
    assert sentinel not in category.value


def test_negative_secret_sentinel_rejected_before_signing_and_absent_from_audit():
    db = _db()
    continuity = Continuity(db)
    try:
        bad_contract = _contract_dict(ROUTE_A, ROUTE_B)
        bad_contract["provider"] = "hw_secret_sentinel_provider"
        with pytest.raises(ContinuityValidationError) as contract_error:
            continuity.store_capability_contract(bad_contract, principal=_admin())
        assert "hw_secret_sentinel" not in str(contract_error.value)
        assert db.store.memory_count() == 0
        assert list(db.store.iter_audit()) == []

        continuity, from_contract, to_contract = _seed_contracts(db)
        before_rows = list(db.store.iter_audit())
        bad_draft = _draft_dict(from_contract, to_contract)
        sentinel = "hw_secret_sentinel_123456"
        bad_draft["cases"][0]["case_id"] = "case_" + sentinel
        with pytest.raises(ContinuityValidationError) as receipt_error:
            continuity.issue_rotation_receipt(bad_draft, principal=_admin())
        assert sentinel not in str(receipt_error.value)
        after_rows = list(db.store.iter_audit())
        assert after_rows == before_rows
        assert sentinel not in json.dumps(after_rows)
    finally:
        db.close()


def test_contract_recall_exclusion_across_all_ordinary_paths():
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "heartwood.db"
        db = _db(path)
        continuity = Continuity(db)
        contract, _ = _contracts()
        stored = continuity.store_capability_contract(contract, principal=_admin())
        try:
            assert db.store.get_meta(stored.memory_id)["indexed"] is False
            assert db.store.index_lag(TENANT) == 0
            assert stored.memory_id not in db.index._v
            assert stored.memory_id not in db._text_cache

            path_filters = (
                {},
                {"method": "hybrid_untyped"},
                {"method": "lexical"},
                {"method": "typed_router", "typed": True},
            )
            for filters in path_filters:
                out = db.recall(
                    "provider catalog model route",
                    principal=_admin(),
                    filters=filters,
                    k=10,
                    topc=10,
                )
                assert stored.memory_id not in {row["id"] for row in out["results"]}

            assert db.warm_recall_cache(_admin()) == 0
            assert stored.memory_id not in db._text_cache

            mcp = MCPMemoryAPI(db)
            out = mcp.recall(
                "provider catalog model route",
                principal_id=_admin().id,
                roles=[CONTINUITY_ADMIN_ROLE],
                clearance="confidential",
            )
            assert stored.memory_id not in {row["id"] for row in out["results"]}
        finally:
            db.close()

        reopened = _db(path)
        try:
            assert stored.memory_id not in reopened.index._v
            out = reopened.recall(
                "provider catalog model route",
                principal=_admin(),
                k=10,
                topc=10,
            )
            assert stored.memory_id not in {row["id"] for row in out["results"]}
        finally:
            reopened.close()


def test_contract_is_retrievable_only_via_privileged_api():
    db = _db()
    continuity = Continuity(db)
    contract, _ = _contracts()
    stored = continuity.store_capability_contract(contract, principal=_admin())
    try:
        assert db.read_content(stored.memory_id) is None
        with pytest.raises(PermissionError, match="continuity access denied"):
            continuity.get_capability_contract(
                stored.memory_id,
                principal=Principal(
                    id="agent:reader",
                    tenant=TENANT,
                    roles=(),
                    clearance="confidential",
                ),
            )
        loaded = continuity.get_capability_contract(stored.memory_id, principal=_admin())
        assert loaded.provider == contract.provider
        assert loaded.model == contract.model
        assert loaded.route_id == stored.route_id
        assert loaded.route_id != contract.route_id
        with pytest.raises(PermissionError, match="cannot enter ordinary recall"):
            db.set_indexed(
                stored.memory_id,
                True,
                actor=_admin().id,
                reason="negative test",
            )
    finally:
        db.close()


def test_direct_capability_contract_write_cannot_enter_recall():
    db = _db()
    try:
        with pytest.raises(PermissionError, match="indexed=False"):
            db.remember(
                "{}",
                subject="continuity-contract:negative",
                created_by=_admin().id,
                kind="capability-contract",
                policy_scope="continuity-privileged",
                indexed=True,
            )
        assert db.store.memory_count() == 0
    finally:
        db.close()


def test_receipt_binds_contract_eval_run_baseline_fallback_signature_and_audit():
    db = _db()
    continuity, from_contract, to_contract = _seed_contracts(db)
    try:
        draft = RotationReceiptDraft.from_dict(_draft_dict(from_contract, to_contract))
        receipt = continuity.issue_rotation_receipt(draft, principal=_admin())
        rendered = receipt.render()
        parsed = SignedRotationReceipt.from_dict(json.loads(rendered))
        assert parsed == receipt
        assert receipt.draft.from_contract == ContractBinding(
            route_id=from_contract.route_id,
            schema_version=from_contract.schema_version,
            contract_hash=from_contract.contract_hash,
        )
        assert receipt.draft.eval_suite == EvalSuiteBinding(
            eval_suite_id=SUITE_ID,
            schema_version="3",
            eval_suite_hash=EVAL_HASH,
        )
        assert receipt.draft.prior_baseline == GenesisMarker(is_genesis=True)
        assert receipt.draft.run_id != RUN_ID
        assert receipt.draft.cases[1].fallback.exercised is True

        verification = continuity.verify_rotation_receipt(receipt)
        assert verification == {
            "ok": True,
            "signature_valid": True,
            "audit_event_valid": True,
            "audit_chain_valid": True,
            "baseline_valid": True,
            "receipt_id": receipt.draft.receipt_id,
            "receipt_hash": receipt.receipt_hash,
        }

        audit_row = db.store.audit_row(receipt.audit_seq)
        audit_body = json.loads(audit_row["body"])
        assert audit_body["target"] == receipt.draft.receipt_id
        assert audit_body["detail"] == {
            "receipt_hash": receipt.receipt_hash,
            "lineage_hash": content_hash(
                {
                    "from_route": from_contract.route_id,
                    "to_route": to_contract.route_id,
                }
            ),
            "status": "prototype",
        }
        assert set(audit_body["detail"]) == {
            "receipt_hash",
            "lineage_hash",
            "status",
        }
        assert from_contract.route_id not in audit_row["body"]
        assert to_contract.route_id not in audit_row["body"]
        assert CASE_A not in audit_row["body"]

        tampered = copy.deepcopy(receipt.to_dict())
        tampered["cases"][0]["delta"] = 0.5
        assert continuity.verify_rotation_receipt(tampered)["ok"] is False
    finally:
        db.close()


def test_prototype_marker_is_machine_readable_and_visible_in_rendered_output():
    db = _db()
    continuity, from_contract, to_contract = _seed_contracts(db)
    try:
        receipt = continuity.issue_rotation_receipt(
            _draft_dict(from_contract, to_contract, evidence_mode="prototype"),
            principal=_admin(),
        )
        rendered = receipt.render()
        assert receipt.to_dict()["evidence_mode"] == "prototype"
        assert '"evidence_mode":"prototype"' in rendered
    finally:
        db.close()


def test_core_refuses_production_evidence_without_execution_attestation():
    db = _db()
    continuity, from_contract, to_contract = _seed_contracts(db)
    try:
        before_rows = list(db.store.iter_audit())
        with pytest.raises(
            ContinuityIntegrityError,
            match="production evidence requires validated execution attestation",
        ):
            continuity.issue_rotation_receipt(
                _draft_dict(
                    from_contract,
                    to_contract,
                    evidence_mode="production",
                ),
                principal=_admin(),
            )
        assert list(db.store.iter_audit()) == before_rows
    finally:
        db.close()


def test_prototype_evidence_mode_still_allowed_and_labeled():
    db = _db()
    continuity, from_contract, to_contract = _seed_contracts(db)
    try:
        receipt = continuity.issue_rotation_receipt(
            _draft_dict(
                from_contract,
                to_contract,
                evidence_mode="prototype",
            ),
            principal=_admin(),
        )
        assert receipt.draft.evidence_mode.value == "prototype"
        assert '"evidence_mode":"prototype"' in receipt.render()
        assert continuity.verify_rotation_receipt(receipt)["ok"] is True
    finally:
        db.close()


def test_receipt_rejects_unstored_contract_binding():
    db = _db()
    continuity = Continuity(db)
    from_contract, to_contract = _contracts()
    stored = continuity.store_capability_contract(from_contract, principal=_admin())
    from_contract = continuity.get_capability_contract(
        stored.memory_id,
        principal=_admin(),
    )
    try:
        draft = RotationReceiptDraft.from_dict(_draft_dict(from_contract, to_contract))
        with pytest.raises(ContinuityIntegrityError, match="contract binding not found"):
            continuity.issue_rotation_receipt(draft, principal=_admin())
    finally:
        db.close()


def test_receipt_hash_is_over_the_versioned_audit_bound_unsigned_payload():
    db = _db()
    continuity, from_contract, to_contract = _seed_contracts(db)
    try:
        receipt = continuity.issue_rotation_receipt(
            _draft_dict(from_contract, to_contract),
            principal=_admin(),
        )
        assert receipt.receipt_hash == content_hash(receipt.unsigned_payload())
        assert receipt.signing_version.endswith(".v1")
        assert receipt.audit_seq > 0
    finally:
        db.close()


def test_receipt_rejects_unresolvable_prior_baseline():
    db = _db()
    continuity, from_contract, to_contract = _seed_contracts(db)
    try:
        missing = {
            "receipt_id": BASELINE_ID,
            "receipt_hash": BASELINE_HASH,
            "audit_seq": 9_999_999,
        }
        with pytest.raises(
            ContinuityIntegrityError,
            match="prior baseline invalid",
        ):
            continuity.issue_rotation_receipt(
                _draft_dict(
                    from_contract,
                    to_contract,
                    prior_baseline=missing,
                ),
                principal=_admin(),
            )

        genesis = continuity.issue_rotation_receipt(
            _draft_dict(from_contract, to_contract),
            principal=_admin(),
        )
        forged = copy.deepcopy(genesis.to_dict())
        forged["prior_baseline"] = missing
        unsigned = {
            key: value
            for key, value in forged.items()
            if key not in {"receipt_hash", "signature"}
        }
        forged["receipt_hash"] = content_hash(unsigned)
        verification = continuity.verify_rotation_receipt(forged)
        assert verification["ok"] is False
        assert verification["baseline_valid"] is False
    finally:
        db.close()


def test_prior_baseline_verified_against_audit_chain():
    db = _db()
    continuity, from_contract, to_contract = _seed_contracts(db)
    try:
        baseline = continuity.issue_rotation_receipt(
            _draft_dict(from_contract, to_contract),
            principal=_admin(),
        )
        receipt = continuity.issue_rotation_receipt(
            _draft_dict(
                from_contract,
                to_contract,
                receipt_id=RECEIPT_ID_2,
                prior_baseline=_baseline_binding(baseline),
            ),
            principal=_admin(),
        )
        verification = continuity.verify_rotation_receipt(receipt)
        assert verification["ok"] is True
        assert verification["baseline_valid"] is True
        assert receipt.draft.prior_baseline == BaselineBinding(
            receipt_id=baseline.draft.receipt_id,
            receipt_hash=baseline.receipt_hash,
            audit_seq=baseline.audit_seq,
        )
    finally:
        db.close()


def test_explicit_genesis_issues_and_verifies_and_second_genesis_rejected():
    db = _db()
    continuity, from_contract, to_contract = _seed_contracts(db)
    try:
        genesis = continuity.issue_rotation_receipt(
            _draft_dict(from_contract, to_contract),
            principal=_admin(),
        )
        assert genesis.draft.prior_baseline == GenesisMarker(is_genesis=True)
        assert continuity.verify_rotation_receipt(genesis)["ok"] is True

        with pytest.raises(
            ContinuityIntegrityError,
            match="prior baseline invalid",
        ):
            continuity.issue_rotation_receipt(
                _draft_dict(
                    from_contract,
                    to_contract,
                    receipt_id=RECEIPT_ID_2,
                ),
                principal=_admin(),
            )
    finally:
        db.close()


def test_prior_baseline_ordering_enforced():
    db = _db()
    continuity, from_contract, to_contract = _seed_contracts(db)
    try:
        genesis = continuity.issue_rotation_receipt(
            _draft_dict(from_contract, to_contract),
            principal=_admin(),
        )
        forged = copy.deepcopy(genesis.to_dict())
        forged["prior_baseline"] = {
            "receipt_id": genesis.draft.receipt_id,
            "receipt_hash": genesis.receipt_hash,
            "audit_seq": genesis.audit_seq,
        }
        unsigned = {
            key: value
            for key, value in forged.items()
            if key not in {"receipt_hash", "signature"}
        }
        forged["receipt_hash"] = content_hash(unsigned)
        verification = continuity.verify_rotation_receipt(forged)
        assert verification["ok"] is False
        assert verification["baseline_valid"] is False
    finally:
        db.close()


def test_high_entropy_identifier_and_label_not_preserved_in_canonical_output():
    db = _db()
    continuity = Continuity(db)
    secret_route_a = "route_Z9x8C7v6B5n4M3q2P1w0"
    secret_route_b = "route_Q1w2E3r4T5y6U7i8O9p0"
    from_value = _contract_dict(secret_route_a, secret_route_b)
    to_value = _contract_dict(secret_route_b, secret_route_a)
    try:
        stored_from = continuity.store_capability_contract(
            from_value,
            principal=_admin(),
        )
        stored_to = continuity.store_capability_contract(
            to_value,
            principal=_admin(),
        )
        from_contract = continuity.get_capability_contract(
            stored_from.memory_id,
            principal=_admin(),
        )
        to_contract = continuity.get_capability_contract(
            stored_to.memory_id,
            principal=_admin(),
        )
        assert secret_route_a not in from_contract.render()
        assert secret_route_b not in from_contract.render()

        draft = _draft_dict(from_contract, to_contract)
        secret_receipt = "rot_Z9x8C7v6B5n4M3q2P1w0"
        secret_run = "run_Q1w2E3r4T5y6U7i8O9p0"
        secret_case = "case_A1s2D3f4G5h6J7k8L9z0"
        draft["receipt_id"] = secret_receipt
        draft["run_id"] = secret_run
        draft["cases"][0]["case_id"] = secret_case
        receipt = continuity.issue_rotation_receipt(draft, principal=_admin())
        rendered = receipt.render()
        for caller_value in (
            secret_route_a,
            secret_route_b,
            secret_receipt,
            secret_run,
            secret_case,
        ):
            assert caller_value not in rendered

        unapproved = _contract_dict(ROUTE_A, ROUTE_B)
        unapproved["provider"] = "Z9x8C7v6B5n4M3q2P1w0"
        unapproved["model"] = "Q1w2E3r4T5y6U7i8O9p0"
        with pytest.raises(
            ContinuityValidationError,
            match="approved_provider_model",
        ):
            CapabilityContract.from_dict(unapproved)
    finally:
        db.close()


def test_issued_ids_are_boundary_minted():
    db = _db()
    continuity, from_contract, to_contract = _seed_contracts(db)
    try:
        receipt = continuity.issue_rotation_receipt(
            _draft_dict(from_contract, to_contract),
            principal=_admin(),
        )
        minted = (
            receipt.draft.receipt_id,
            receipt.draft.run_id,
            receipt.draft.from_route,
            receipt.draft.to_route,
            *(case.case_id for case in receipt.draft.cases),
        )
        assert receipt.draft.receipt_id != RECEIPT_ID
        assert receipt.draft.run_id != RUN_ID
        assert from_contract.route_id not in {ROUTE_A, ROUTE_B}
        assert to_contract.route_id not in {ROUTE_A, ROUTE_B}
        assert all(
            re.fullmatch(r"(?:rot|run|route|case)_[0-9a-f]{32}", value)
            for value in minted
        )
    finally:
        db.close()
