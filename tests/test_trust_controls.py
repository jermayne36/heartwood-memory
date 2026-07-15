"""Product-level egress and faithfulness controls."""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal  # noqa: E402


def _embed(texts):
    vecs = np.zeros((len(texts), 4), dtype=np.float32)
    for i, text in enumerate(texts):
        lowered = text.lower()
        vecs[i, 0] = 1.0
        vecs[i, 1] = float("refund" in lowered)
        vecs[i, 2] = float("duplicate" in lowered)
        vecs[i, 3] = float("policy" in lowered)
    return vecs


def _rerank(query, texts):
    q = set(query.lower().split())
    return np.asarray([len(q & set(text.lower().split())) for text in texts], dtype=np.float32)


def _db():
    return Heartwood(
        path=":memory:",
        tenant="tenant:trust",
        embedder=(_embed, "test-embedder"),
        reranker=(_rerank, "test-reranker"),
    )


def _egress_request(source_spans, expected_decision="external_model_allowed"):
    return {
        "request_id": "trust_controls_external",
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


def main():
    db = _db()
    span = {
        "span_id": "policy#1",
        "source_id": "kb://refund-policy",
        "classification": "internal",
        "pii_labels": [],
        "text": "Refund policy allows expedited review when duplicate charges are documented.",
    }
    claims = [
        {
            "claim_id": "claim_1",
            "text": "Refund policy allows expedited review for duplicate charge.",
            "source_span_ids": ["policy#1"],
            "material": True,
        }
    ]

    egress = db.evaluate_egress(_egress_request([span]))
    assert egress["decision"] == "external_model_allowed"

    stored = db.remember_generated(
        "Refund policy allows expedited review for duplicate charge.",
        subject="policy:refunds",
        created_by="agent:summarizer",
        source_spans=[span],
        claims=claims,
        egress_request=_egress_request([span]),
        model_version="trust-controls-test",
    )
    assert stored["truth_status"] == "generated_supported"
    assert stored["faithfulness"]["decision"] == "accepted"
    assert stored["egress"]["decision"] == "external_model_allowed"

    principal = Principal(id="agent:reader", tenant="tenant:trust", clearance="internal")
    recalled = db.recall(
        "duplicate refund policy",
        principal=principal,
        filters={"include_review_states": ["proposed"]},
        k=3,
    )
    result = next(item for item in recalled["results"] if item["id"] == stored["id"])
    assert result["truth_status"] == "generated_supported"
    assert result["provenance"]["signature_valid"] is True

    bad_span = {
        "span_id": "case#1",
        "source_id": "case://42",
        "classification": "internal",
        "pii_labels": [],
        "text": "Customer 42 was denied a one-time refund.",
    }
    bad_claims = [
        {
            "claim_id": "bad_claim",
            "text": "Customer 42 is approved for a lifetime refund.",
            "source_span_ids": ["case#1"],
            "material": True,
        }
    ]
    try:
        db.remember_generated(
            "Customer 42 is approved for a lifetime refund.",
            subject="customer:42",
            created_by="agent:summarizer",
            source_spans=[bad_span],
            claims=bad_claims,
        )
        assert False, "unsupported generated memory must not persist by default"
    except PermissionError as exc:
        assert "faithfulness" in str(exc)

    restricted_span = {
        "span_id": "restricted#1",
        "source_id": "case://restricted",
        "classification": "restricted",
        "pii_labels": ["ssn"],
        "text": "Customer SSN is 123-45-6789.",
    }
    denied = db.evaluate_egress(_egress_request([restricted_span], expected_decision="denied"))
    assert denied["decision"] == "denied"
    try:
        db.remember_generated(
            "Customer SSN is available.",
            subject="customer:restricted",
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
            egress_request=_egress_request([restricted_span], expected_decision="denied"),
        )
        assert False, "denied egress must block generated memory"
    except PermissionError as exc:
        assert "egress" in str(exc)

    assert db.verify_audit() is True
    print("TRUST CONTROL TESTS PASSED")


if __name__ == "__main__":
    main()
