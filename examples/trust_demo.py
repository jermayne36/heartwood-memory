#!/usr/bin/env python3
"""Run the Heartwood five-receipt trust demo against a fresh local store.

This demo is intentionally scoped to today's source-auditable guarantees:
provenance tampering is surfaced on recall, audit in-place edits are detected,
policy filtering happens before ranking, hard forget produces a key-destruction
proof, and generated memories fail closed on faithfulness/egress gates.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from heartwood import Heartwood, Principal, prove_crypto_erase_path  # noqa: E402
from heartwood.provenance import Signer  # noqa: E402


TENANT = "tenant:trust-demo"
CRYPTO_TENANT = "tenant:trust-demo-crypto"
POLICY_TENANT = "tenant:trust-demo-policy"


def _embed(texts: list[str]) -> np.ndarray:
    vocab = (
        "alpha",
        "budget",
        "overrun",
        "secret",
        "restricted",
        "refund",
        "duplicate",
        "policy",
        "customer",
        "ssn",
        "crypto",
    )
    vecs = np.zeros((len(texts), len(vocab) + 1), dtype=np.float32)
    for row, text in enumerate(texts):
        lowered = text.lower()
        vecs[row, 0] = 1.0
        for col, token in enumerate(vocab, start=1):
            vecs[row, col] = float(token in lowered)
    return vecs


def _rerank(query: str, texts: list[str]) -> np.ndarray:
    query_tokens = set(query.lower().split())
    return np.asarray(
        [len(query_tokens & set(text.lower().split())) for text in texts],
        dtype=np.float32,
    )


def _db(path: Path, *, tenant: str = TENANT) -> Heartwood:
    return Heartwood(
        path=str(path),
        tenant=tenant,
        embedder=(_embed, "trust-demo-embedder"),
        reranker=(_rerank, "trust-demo-reranker"),
    )


def _print_receipt(number: int, title: str, payload: dict[str, Any]) -> None:
    print(f"\nRECEIPT {number}: {title}")
    for key, value in payload.items():
        if isinstance(value, (dict, list, tuple)):
            rendered = json.dumps(value, sort_keys=True)
        else:
            rendered = str(value)
        print(f"  {key}: {rendered}")


def _candidate_count(db: Heartwood) -> int:
    return len(db.store.candidate_meta(db.tenant))


def _egress_request(source_spans: list[dict[str, Any]], expected_decision: str) -> dict[str, Any]:
    return {
        "request_id": f"trust_demo_{expected_decision}",
        "expected_decision": expected_decision,
        "model": {
            "runtime": "external",
            "provider": "openai",
            "region": "us",
            "retention": "zero",
            "training_opt_out": True,
        },
        "policy": {
            "allow_external_models": True,
            "allowed_providers": ["openai"],
            "allowed_regions": ["us"],
            "require_zero_retention": True,
            "allow_redaction": True,
            "redactable_pii_labels": ["email", "phone", "customer_id"],
            "deny_pii_labels": ["ssn", "credit_card"],
            "deny_classifications": ["restricted"],
            "human_review_classifications": ["confidential"],
        },
        "source_spans": source_spans,
    }


def receipt_provenance_surface(db: Heartwood) -> dict[str, Any]:
    mem_id = db.remember(
        "Alpha budget overrun was approved for internal mitigation.",
        subject="project:alpha",
        created_by="agent:producer",
        source={"uri": "doc://alpha/budget"},
    )
    principal = Principal(id="agent:reader", tenant=db.tenant, clearance="internal")
    before = db.recall("alpha budget overrun", principal=principal, k=1)

    meta = db.store.get_meta(mem_id)
    forged = Signer().sign(
        "agent:producer",
        mem_id,
        meta["content_hash"],
        meta["source"].get("uri"),
        "agent:producer",
        meta["epistemic"],
    )
    db.store.conn.execute(
        "UPDATE memories SET producer_sig=?, sig_valid=1 WHERE id=?",
        (forged, mem_id),
    )
    db.store.conn.commit()

    after = db.recall("alpha budget overrun", principal=principal, k=1)
    result = after["results"][0]
    ok = (
        before["results"][0]["provenance"]["signature_valid"] is True
        and result["id"] == mem_id
        and result["provenance"]["signature_valid"] is False
        and result["provenance"]["content_hash_match"] is True
    )
    assert ok
    return {
        "scope": "read-time signature/content verification is recomputed and surfaced; tampered reads are not blocked today",
        "tamper": "producer signature replaced by a different signer; cached sig_valid bit left true",
        "returned_after_tamper": result["id"] == mem_id,
        "signature_valid": result["provenance"]["signature_valid"],
        "content_hash_match": result["provenance"]["content_hash_match"],
        "does_not_prove": "read-time enforcement/drop/quarantine",
        "status": "PASS",
    }


def receipt_audit_tamper(db: Heartwood) -> dict[str, Any]:
    before = db.verify_audit()
    row = db.store.conn.execute(
        "SELECT seq, action, target FROM audit_log ORDER BY seq LIMIT 1"
    ).fetchone()
    db.store.conn.execute(
        "UPDATE audit_log SET body = body || ? WHERE seq = ?",
        ("|trust-demo-in-place-tamper", row["seq"]),
    )
    db.store.conn.commit()
    after = db.verify_audit()
    assert before is True and after is False
    return {
        "scope": "hash chain detects in-place audit-row edits/deletions of retained rows; tail truncation needs an external anchor",
        "tampered_seq": row["seq"],
        "tampered_action": row["action"],
        "verify_chain_before": before,
        "verify_chain_after": after,
        "does_not_prove": "tail-truncation or rollback protection without an external anchor",
        "status": "PASS",
    }


def receipt_policy_before_ranking(db: Heartwood) -> dict[str, Any]:
    policy_db = db.with_tenant(POLICY_TENANT)
    try:
        restricted_id = policy_db.remember(
            "Secret restricted customer Alpha escalation detail.",
            subject="customer:restricted",
            created_by="agent:caseworker",
            source={"uri": "case://restricted-alpha"},
            policy=policy_db.policy(classification="restricted"),
        )
        authorized = policy_db.recall(
            "secret restricted customer alpha",
            principal=Principal(id="agent:authorized", tenant=policy_db.tenant, clearance="restricted"),
            k=3,
        )
        unauthorized = policy_db.recall(
            "secret restricted customer alpha",
            principal=Principal(id="agent:unauthorized", tenant=policy_db.tenant, clearance="internal"),
            k=3,
        )
        explanation = policy_db.explain_recall(unauthorized["recall_id"])
        ok = (
            any(row["id"] == restricted_id for row in authorized["results"])
            and unauthorized["results"] == []
            and explanation["candidates_considered"] == 0
        )
        assert ok
        return {
            "scope": "policy filters visible_ids before ANN/BM25/rerank; caller response stays constant-shape",
            "authorized_can_recall_restricted": any(
                row["id"] == restricted_id for row in authorized["results"]
            ),
            "unauthorized_result_ids": [row["id"] for row in unauthorized["results"]],
            "unauthorized_candidates_considered": explanation["candidates_considered"],
            "caller_response_keys": sorted(unauthorized.keys()),
            "does_not_prove": "large-scale multi-tenant isolation or timing-side-channel bounds",
            "status": "PASS",
        }
    finally:
        policy_db.close()


def receipt_crypto_shred(path: Path) -> dict[str, Any]:
    db = _db(path, tenant=CRYPTO_TENANT)
    try:
        mem_id = db.remember(
            "Crypto receipt subject data should become unrecoverable after hard forget.",
            subject="customer:42",
            created_by="agent:privacy",
            source={"uri": "case://customer-42"},
        )
        forget_receipt = db.forget(
            "customer:42",
            mode="hard",
            actor="agent:privacy",
            reason="trust demo",
        )
        proof = prove_crypto_erase_path(path, tenant=CRYPTO_TENANT, root_present=False).to_dict()
        ok = (
            forget_receipt["key_shredded"] is True
            and forget_receipt["purged"] >= 1
            and proof["content_unrecoverable"] is True
            and proof["shredded_key_count"] >= 1
        )
        assert ok
        return {
            "scope": "per-subject key was shredded and proof object shows no raw active DEKs for this demo tenant with root_present=false",
            "forgotten_memory_id": mem_id,
            "forget_receipt": forget_receipt,
            "proof_subset": {
                "content_unrecoverable": proof["content_unrecoverable"],
                "proved": proof["proved"],
                "active_key_count": proof["active_key_count"],
                "raw_active_key_count": proof["raw_active_key_count"],
                "shredded_key_count": proof["shredded_key_count"],
                "reason": proof["reason"],
            },
            "does_not_prove": "content-byte erasure, snapshot purge, legal Article 17 completion, or tenant-wide root destruction in production",
            "status": "PASS",
        }
    finally:
        db.close()


def receipt_faithfulness_and_egress(db: Heartwood) -> dict[str, Any]:
    before = _candidate_count(db)
    bad_span = {
        "span_id": "case#42",
        "source_id": "case://42",
        "classification": "internal",
        "pii_labels": [],
        "text": "Customer 42 was denied a one-time refund.",
    }
    bad_claim = {
        "claim_id": "bad_claim",
        "text": "Customer 42 is approved for a lifetime refund.",
        "source_span_ids": ["case#42"],
        "material": True,
    }
    try:
        db.remember_generated(
            "Customer 42 is approved for a lifetime refund.",
            subject="customer:42-generated",
            created_by="agent:summarizer",
            source_spans=[bad_span],
            claims=[bad_claim],
        )
        raise AssertionError("unfaithful generated memory was persisted")
    except PermissionError as exc:
        faithfulness_error = str(exc)

    after_faithfulness = _candidate_count(db)
    restricted_span = {
        "span_id": "restricted#1",
        "source_id": "case://restricted",
        "classification": "restricted",
        "pii_labels": ["ssn"],
        "text": "Customer SSN is 123-45-6789.",
    }
    denied = db.evaluate_egress(_egress_request([restricted_span], "denied"))
    try:
        db.remember_generated(
            "Customer SSN is available.",
            subject="customer:ssn-generated",
            created_by="agent:summarizer",
            source_spans=[restricted_span],
            claims=[
                {
                    "claim_id": "pii_claim",
                    "text": "Customer SSN is available.",
                    "source_span_ids": ["restricted#1"],
                    "material": True,
                }
            ],
            egress_request=_egress_request([restricted_span], "denied"),
        )
        raise AssertionError("generated memory persisted after denied egress")
    except PermissionError as exc:
        egress_error = str(exc)

    after_egress = _candidate_count(db)
    ok = (
        "faithfulness" in faithfulness_error
        and denied["decision"] == "denied"
        and "egress" in egress_error
        and after_faithfulness == before
        and after_egress == after_faithfulness
    )
    assert ok
    return {
        "scope": "generated memory is not persisted by default when faithfulness rejects or egress is denied",
        "faithfulness_error": faithfulness_error,
        "egress_decision": denied["decision"],
        "egress_error": egress_error,
        "candidate_count_before": before,
        "candidate_count_after": after_egress,
        "does_not_prove": "learned entailment quality or human-review workflow completeness",
        "status": "PASS",
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="heartwood-trust-demo-") as temp_dir:
        path = Path(temp_dir) / "heartwood.db"
        db = _db(path)
        try:
            print("Heartwood reproducible trust demo")
            print(f"fresh_local_store: {path}")
            print("command: python examples/trust_demo.py")
            _print_receipt(1, "Provenance tamper is surfaced on read", receipt_provenance_surface(db))
            _print_receipt(2, "Audit in-place tamper breaks verify_chain()", receipt_audit_tamper(db))
            _print_receipt(3, "Policy-before-ranking returns no unauthorized score/leak", receipt_policy_before_ranking(db))
            _print_receipt(4, "Hard forget emits key-destruction proof", receipt_crypto_shred(path))
            _print_receipt(5, "Faithfulness and egress gates reject generated memory", receipt_faithfulness_and_egress(db))
            print("\nTRUST_DEMO_RESULT: PASS")
            return 0
        finally:
            db.close()


if __name__ == "__main__":
    raise SystemExit(main())
