"""External-model egress policy for Heartwood.

The product API uses this module before source spans are sent to model runtimes.
The experiment gates import the same logic so the shipped package, not only the
proof harness, owns the egress decision rules.
"""
from __future__ import annotations

import re
from typing import Any

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CUSTOMER_ID_RE = re.compile(r"\bcustomer\s+[_-]?\s*\d+\b", re.IGNORECASE)
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

EXTERNAL_ALLOWED = "external_model_allowed"
EXTERNAL_REDACTED = "external_model_allowed_with_redaction"
LOCAL_ONLY = "local_model_only"
HUMAN_REVIEW = "human_approval_required"
DENIED = "denied"

GENERATION_ALLOWED_DECISIONS = {EXTERNAL_ALLOWED, EXTERNAL_REDACTED, LOCAL_ONLY}


def provider_policy_matches_model(provider: dict[str, Any], model: dict[str, Any]) -> bool:
    checked_fields = ("provider", "runtime", "region", "retention", "training_opt_out")
    for field in checked_fields:
        if field in model and provider.get(field) != model.get(field):
            return False
    if "endpoint" in model and provider.get("endpoint") != model.get("endpoint"):
        return False
    return True


def resolve_provider_policy(
    model: dict[str, Any],
    registry: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not registry:
        return None
    providers = registry.get("providers", [])
    requested_policy_id = model.get("provider_policy_id")
    if requested_policy_id:
        for provider in providers:
            if (
                provider.get("provider_policy_id") == requested_policy_id
                and provider_policy_matches_model(provider, model)
            ):
                return provider
        return None

    for provider in providers:
        if provider_policy_matches_model(provider, model):
            return provider
    return None


def redact_text(text: str, labels: set[str]) -> str:
    redacted = text
    if "email" in labels:
        redacted = EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)
    if "phone" in labels:
        redacted = PHONE_RE.sub("[REDACTED_PHONE]", redacted)
    if "ssn" in labels:
        redacted = SSN_RE.sub("[REDACTED_SSN]", redacted)
    if "customer_id" in labels:
        redacted = CUSTOMER_ID_RE.sub("[REDACTED_CUSTOMER_ID]", redacted)
    if "credit_card" in labels:
        redacted = CREDIT_CARD_RE.sub("[REDACTED_CREDIT_CARD]", redacted)
    return redacted


def raw_pii_patterns(text: str) -> list[str]:
    found: list[str] = []
    if EMAIL_RE.search(text):
        found.append("email")
    if PHONE_RE.search(text):
        found.append("phone")
    if SSN_RE.search(text):
        found.append("ssn")
    if CREDIT_CARD_RE.search(text):
        found.append("credit_card")
    return sorted(set(found))


def request_pii_labels(request: dict[str, Any]) -> set[str]:
    labels: set[str] = set()
    for span in request.get("source_spans", []):
        labels.update(span.get("pii_labels", []))
    return labels


def request_classifications(request: dict[str, Any]) -> set[str]:
    return {
        span.get("classification", "internal")
        for span in request.get("source_spans", [])
    }


def build_payload(request: dict[str, Any], labels_to_redact: set[str]) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for span in request.get("source_spans", []):
        labels = set(span.get("pii_labels", []))
        payload.append(
            {
                "span_id": span["span_id"],
                "classification": span.get("classification", "internal"),
                "pii_labels": sorted(labels),
                "text": redact_text(span.get("text", ""), labels & labels_to_redact),
            }
        )
    return payload


def raw_pii_in_payload(payload: list[dict[str, Any]]) -> dict[str, list[str]]:
    leaks: dict[str, list[str]] = {}
    for span in payload:
        patterns = raw_pii_patterns(span.get("text", ""))
        if patterns:
            leaks[span["span_id"]] = patterns
    return leaks


def evaluate_request(
    request: dict[str, Any],
    provider_registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    model = request["model"]
    policy = request["policy"]
    provider_policy = resolve_provider_policy(model, provider_registry)
    pii_labels = request_pii_labels(request)
    classifications = request_classifications(request)
    reasons: list[str] = []
    labels_to_redact: set[str] = set()

    if provider_policy:
        reasons.append(
            "provider registry matched "
            f"{provider_policy.get('provider_policy_id')} "
            f"from {provider_registry.get('registry_version') if provider_registry else 'inline'}"
        )

    if model.get("runtime") == "local":
        decision = LOCAL_ONLY
        reasons.append("model runtime is local")
        payload: list[dict[str, Any]] = []
    elif not policy.get("allow_external_models", False):
        decision = LOCAL_ONLY
        reasons.append("tenant policy disables external models")
        payload = []
    elif provider_registry and provider_policy is None:
        decision = DENIED
        reasons.append("model endpoint has no matching provider registry entry")
        payload = []
    elif provider_policy and provider_policy.get("status") != "approved":
        decision = DENIED
        reasons.append("provider registry entry is not approved")
        payload = []
    elif model.get("provider") not in set(policy.get("allowed_providers", [])):
        decision = DENIED
        reasons.append("model provider is not allowed")
        payload = []
    elif model.get("region") not in set(policy.get("allowed_regions", [])):
        decision = DENIED
        reasons.append("model region is not allowed")
        payload = []
    elif policy.get("require_zero_retention", False) and model.get("retention") != "zero":
        decision = DENIED
        reasons.append("model endpoint does not satisfy zero-retention policy")
        payload = []
    elif not model.get("training_opt_out", False):
        decision = DENIED
        reasons.append("model endpoint does not opt out of training")
        payload = []
    elif provider_policy and classifications - set(provider_policy.get("allowed_classifications", [])):
        decision = DENIED
        reasons.append("provider registry disallows one or more source classifications")
        payload = []
    elif provider_policy and pii_labels & set(provider_policy.get("denied_pii_labels", [])):
        decision = DENIED
        reasons.append("provider registry denies one or more PII labels")
        payload = []
    elif classifications & set(policy.get("deny_classifications", [])):
        decision = DENIED
        reasons.append("source classification is denied for external egress")
        payload = []
    elif pii_labels & set(policy.get("deny_pii_labels", [])):
        decision = DENIED
        reasons.append("source contains PII labels denied for external egress")
        payload = []
    elif classifications & set(policy.get("human_review_classifications", [])):
        decision = HUMAN_REVIEW
        reasons.append("source classification requires human approval")
        payload = []
    else:
        redactable = set(policy.get("redactable_pii_labels", []))
        if pii_labels:
            if policy.get("allow_redaction", False) and pii_labels <= redactable:
                decision = EXTERNAL_REDACTED
                labels_to_redact = pii_labels
                reasons.append("source contains redactable PII; redaction required before egress")
                payload = build_payload(request, labels_to_redact)
            else:
                decision = HUMAN_REVIEW
                reasons.append("source contains PII that is not automatically redactable")
                payload = []
        else:
            decision = EXTERNAL_ALLOWED
            reasons.append("external egress allowed by tenant and model policy")
            payload = build_payload(request, labels_to_redact)

    raw_pii_leaks = raw_pii_in_payload(payload)
    if decision == EXTERNAL_REDACTED and raw_pii_leaks:
        decision = DENIED
        reasons.append("redacted payload still contains raw PII patterns")
        payload = []

    unsafe_external = decision == EXTERNAL_ALLOWED and (
        bool(pii_labels)
        or bool(classifications & set(policy.get("deny_classifications", [])))
        or bool(classifications & set(policy.get("human_review_classifications", [])))
    )
    expected_decision = request.get("expected_decision")
    expectation_mismatches = []
    if expected_decision and decision != expected_decision:
        expectation_mismatches.append(f"decision expected {expected_decision} got {decision}")

    provider_registry_version = provider_registry.get("registry_version") if provider_registry else None
    return {
        "request_id": request.get("request_id", "egress_request"),
        "decision": decision,
        "expected_decision": expected_decision,
        "reasons": reasons,
        "provider_registry_version": provider_registry_version,
        "provider_policy_id": provider_policy.get("provider_policy_id") if provider_policy else None,
        "pii_labels": sorted(pii_labels),
        "classifications": sorted(classifications),
        "payload_span_count": len(payload),
        "raw_pii_leaks": raw_pii_leaks,
        "unsafe_external": unsafe_external,
        "expectation_mismatches": expectation_mismatches,
        "payload": payload,
    }


def generation_allowed(decision: dict[str, Any], *, allow_human_review: bool = False) -> bool:
    if decision["decision"] in GENERATION_ALLOWED_DECISIONS:
        return True
    return allow_human_review and decision["decision"] == HUMAN_REVIEW


def summarize(evaluated: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        EXTERNAL_ALLOWED: 0,
        EXTERNAL_REDACTED: 0,
        LOCAL_ONLY: 0,
        HUMAN_REVIEW: 0,
        DENIED: 0,
    }
    for result in evaluated:
        counts[result["decision"]] += 1
    return counts
