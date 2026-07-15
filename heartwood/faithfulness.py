"""Generated-memory faithfulness checks for Heartwood.

This deterministic gate is intentionally conservative. It is not a replacement
for a human reviewer or a learned entailment model; it is a release-safe default
that prevents unsupported generated claims from becoming durable memory.
"""
from __future__ import annotations

import re
from typing import Any

TOKEN_RE = re.compile(r"[a-z0-9]+")
ENTITY_RE = re.compile(r"\b(?:customer|case|order)\s*[_-]?\s*[a-z0-9]+\b")
PERCENT_RE = re.compile(r"\b\d+(?:\.\d+)?\s*(?:percent|%)\b")
MONEY_RE = re.compile(r"\$\s*\d+(?:\.\d+)?")

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "because",
    "by",
    "for",
    "has",
    "is",
    "of",
    "on",
    "the",
    "to",
    "was",
    "with",
}

ANCHOR_PHRASES = {
    "approved",
    "denied",
    "duplicate charge",
    "eligible",
    "expedited review",
    "lifetime",
    "not eligible",
    "one time",
    "one-time",
    "pending authorization",
    "refund exception",
    "unpublished",
    "vip escalation",
}

UNCERTAIN_SUPPORT_TERMS = {
    "might",
    "may",
    "possible",
    "suspected",
    "not confirmed",
    "unconfirmed",
    "had not confirmed",
}

UNCERTAIN_CLAIM_TERMS = {
    "might",
    "may",
    "possible",
    "possibly",
    "suspected",
}

POSITIVE_TERMS = {
    "approved",
    "eligible",
    "offered",
    "promised",
    "received",
}

NEGATIVE_TERMS = {
    "denied",
    "declined",
    "not eligible",
    "no refund",
    "rejected",
}


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().replace("_", " ")).strip()


def tokens(text: str) -> set[str]:
    return {
        token
        for token in TOKEN_RE.findall(normalize(text))
        if token not in STOPWORDS and len(token) > 2
    }


def support_score(claim_text: str, support_text: str) -> float:
    claim_tokens = tokens(claim_text)
    if not claim_tokens:
        return 0.0
    support_tokens = tokens(support_text)
    return len(claim_tokens & support_tokens) / len(claim_tokens)


def phrase_present(text: str, phrase: str) -> bool:
    return phrase in normalize(text).replace("-", " ")


def anchors(text: str) -> set[str]:
    lowered = normalize(text).replace("-", " ")
    found = set(ENTITY_RE.findall(lowered))
    found.update(PERCENT_RE.findall(lowered))
    found.update(MONEY_RE.findall(lowered))
    for phrase in ANCHOR_PHRASES:
        if phrase_present(lowered, phrase):
            found.add(phrase.replace("-", " "))
    return found


def missing_claim_anchors(claim_text: str, support_text: str) -> list[str]:
    support = normalize(support_text).replace("-", " ")
    missing: list[str] = []
    for anchor in sorted(anchors(claim_text)):
        if anchor not in support:
            missing.append(anchor)
    return missing


def has_any(text: str, terms: set[str]) -> bool:
    lowered = normalize(text).replace("-", " ")
    return any(term in lowered for term in terms)


def detects_contradiction(claim_text: str, support_text: str) -> bool:
    claim = normalize(claim_text).replace("-", " ")
    support = normalize(support_text).replace("-", " ")

    if has_any(claim, POSITIVE_TERMS) and has_any(support, NEGATIVE_TERMS):
        return True
    if "lifetime" in claim and ("one time" in support or "one-time" in support):
        return True
    if "eligible" in claim and "not eligible" in support:
        return True
    if "approved" in claim and ("denied" in support or "declined" in support or "rejected" in support):
        return True
    return False


def uncertainty_mismatch(claim_text: str, support_text: str) -> bool:
    support_uncertain = has_any(support_text, UNCERTAIN_SUPPORT_TERMS)
    claim_uncertain = has_any(claim_text, UNCERTAIN_CLAIM_TERMS)
    return support_uncertain and not claim_uncertain


def source_text_for_claim(
    claim: dict[str, Any],
    spans: dict[str, str],
) -> str:
    return " ".join(
        spans[span_id]
        for span_id in claim.get("source_span_ids", [])
        if span_id in spans
    )


def evaluate_claim(
    claim: dict[str, Any],
    spans: dict[str, str],
    support_threshold: float = 0.72,
    review_threshold: float = 0.45,
) -> dict[str, Any]:
    support_text = source_text_for_claim(claim, spans)
    score = support_score(claim["text"], support_text)

    if not claim.get("source_span_ids") or not support_text:
        label = "not_checkable"
        missing = []
    elif detects_contradiction(claim["text"], support_text):
        label = "contradicted"
        missing = []
    else:
        missing = missing_claim_anchors(claim["text"], support_text)
        if missing:
            label = "unsupported"
        elif uncertainty_mismatch(claim["text"], support_text):
            label = "partially_supported"
        elif score >= support_threshold:
            label = "supported"
        elif score >= review_threshold:
            label = "partially_supported"
        else:
            label = "unsupported"

    return {
        "claim_id": claim.get("claim_id", "claim"),
        "text": claim["text"],
        "material": bool(claim.get("material", True)),
        "source_span_ids": claim.get("source_span_ids", []),
        "support_score": score,
        "missing_anchors": missing,
        "label": label,
        "expected_label": claim.get("expected_label"),
    }


def decide(evaluated_claims: list[dict[str, Any]]) -> str:
    material_claims = [claim for claim in evaluated_claims if claim["material"]]
    labels = {claim["label"] for claim in material_claims}
    if labels & {"contradicted", "unsupported"}:
        return "rejected"
    if labels & {"partially_supported", "not_checkable"}:
        return "needs_human_review"
    return "accepted"


def evaluate_candidate(
    candidate: dict[str, Any],
    support_threshold: float = 0.72,
    review_threshold: float = 0.45,
) -> dict[str, Any]:
    spans = {span["span_id"]: span["text"] for span in candidate.get("source_spans", [])}
    evaluated_claims = [
        evaluate_claim(claim, spans, support_threshold, review_threshold)
        for claim in candidate.get("claims", [])
    ]
    decision = decide(evaluated_claims)
    expected_decision = candidate.get("expected_decision")
    mismatches: list[str] = []
    if expected_decision and decision != expected_decision:
        mismatches.append(f"decision expected {expected_decision} got {decision}")
    for claim in evaluated_claims:
        if claim["expected_label"] and claim["label"] != claim["expected_label"]:
            mismatches.append(
                f"{claim['claim_id']} expected {claim['expected_label']} got {claim['label']}"
            )

    return {
        "candidate_id": candidate.get("candidate_id", "generated_memory"),
        "decision": decision,
        "expected_decision": expected_decision,
        "claim_count": len(evaluated_claims),
        "claims": evaluated_claims,
        "expectation_mismatches": mismatches,
    }


def summarize(evaluated: list[dict[str, Any]]) -> dict[str, int]:
    decision_counts: dict[str, int] = {
        "accepted": 0,
        "needs_human_review": 0,
        "rejected": 0,
    }
    claim_label_counts: dict[str, int] = {
        "supported": 0,
        "partially_supported": 0,
        "unsupported": 0,
        "contradicted": 0,
        "not_checkable": 0,
    }
    for candidate in evaluated:
        decision_counts[candidate["decision"]] += 1
        for claim in candidate["claims"]:
            claim_label_counts[claim["label"]] += 1
    return {
        **decision_counts,
        **{f"claims_{label}": count for label, count in claim_label_counts.items()},
    }
