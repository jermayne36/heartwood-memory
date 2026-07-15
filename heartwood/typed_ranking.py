"""Typed-memory ranking signals for product recall.

These weights came from the Phase 0 typed-memory proof harness, but this module
is imported by the shipped Heartwood package so product benchmarks exercise the
same scoring path customers install.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .envelope import TruthStatus, default_truth_status

DEFAULT_TYPE_WEIGHTS: dict[str, dict[str, float]] = {
    "default": {
        "source": 1.05,
        "episodic": 1.00,
        "semantic": 1.10,
        "procedural": 1.00,
        "profile": 0.95,
        "generated": 0.85,
        "working": 1.00,
    },
    "customer_support": {
        "source": 1.10,
        "episodic": 1.05,
        "semantic": 1.22,
        "procedural": 1.08,
        "profile": 1.00,
        "generated": 0.85,
        "working": 1.00,
    },
    "procedure": {
        "source": 1.00,
        "episodic": 0.92,
        "semantic": 1.05,
        "procedural": 1.38,
        "profile": 0.80,
        "generated": 0.82,
        "working": 0.95,
    },
    "profile": {
        "source": 0.92,
        "episodic": 0.88,
        "semantic": 0.95,
        "procedural": 0.80,
        "profile": 1.45,
        "generated": 0.75,
        "working": 0.95,
    },
    "temporal_state": {
        "source": 1.00,
        "episodic": 1.35,
        "semantic": 1.12,
        "procedural": 0.85,
        "profile": 0.85,
        "generated": 0.80,
        "working": 1.10,
    },
    "policy": {
        "source": 1.20,
        "episodic": 0.88,
        "semantic": 1.08,
        "procedural": 1.15,
        "profile": 0.75,
        "generated": 0.78,
        "working": 0.95,
    },
}

TRUTH_WEIGHTS = {
    TruthStatus.SOURCE_OBSERVED.value: 1.00,
    TruthStatus.HUMAN_APPROVED.value: 1.00,
    TruthStatus.GENERATED_SUPPORTED.value: 0.92,
    TruthStatus.GENERATED_NEEDS_REVIEW.value: 0.40,
    TruthStatus.INFERRED.value: 0.52,
}


def type_weight_for(intent: str, memory_type: str) -> float:
    weights = DEFAULT_TYPE_WEIGHTS.get(intent, DEFAULT_TYPE_WEIGHTS["default"])
    return weights.get(memory_type, 1.0)


def truth_status_for(row: dict[str, Any]) -> str:
    status = row.get("truth_status")
    if status in TRUTH_WEIGHTS:
        return status
    return default_truth_status(row.get("epistemic", "user-stated"))


def truth_weight_for(row: dict[str, Any]) -> float:
    return TRUTH_WEIGHTS[truth_status_for(row)]


def parse_dt(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    normalized = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def valid_at(row: dict[str, Any], effective_at: Any) -> bool:
    effective = parse_dt(effective_at)
    if effective is None:
        return True
    valid_from = parse_dt(row.get("valid_from"))
    valid_until = parse_dt(row.get("valid_until"))
    if valid_from and effective < valid_from:
        return False
    if valid_until and effective >= valid_until:
        return False
    return True


def recency_signal(row: dict[str, Any], effective_at: Any) -> float:
    effective = parse_dt(effective_at) or datetime.now(timezone.utc)
    created = parse_dt(row.get("created_at"))
    if not created:
        return 0.0
    age_days = max((effective - created).total_seconds() / 86400.0, 0.0)
    return 1.0 / (1.0 + age_days / 30.0)


def entity_overlap_score(query_entities: list[str] | tuple[str, ...], row: dict[str, Any]) -> float:
    query_set = set(query_entities or ())
    memory_set = set(row.get("entities") or ())
    if not query_set or not memory_set:
        return 0.0
    overlap = query_set & memory_set
    if not overlap:
        return 0.0
    return 0.06 * (len(overlap) / len(query_set))


def typed_adjusted_score(
    base_score: float,
    row: dict[str, Any],
    *,
    intent: str = "default",
    query_entities: list[str] | tuple[str, ...] = (),
    effective_at: Any = None,
) -> tuple[float, dict[str, float]]:
    type_weight = type_weight_for(intent, row.get("kind", "semantic"))
    truth_weight = truth_weight_for(row)
    confidence = float(row.get("confidence") or 1.0)
    entity_overlap = entity_overlap_score(query_entities, row)
    source_bonus = 0.035 if row.get("source_ids") and row.get("source_spans") else 0.0
    recency_bonus = recency_signal(row, effective_at) * 0.035 if effective_at else 0.0
    score = (base_score * type_weight * truth_weight * confidence) + entity_overlap + source_bonus + recency_bonus
    return score, {
        "base": round(float(base_score), 4),
        "type_weight": round(float(type_weight), 4),
        "truth_weight": round(float(truth_weight), 4),
        "confidence": round(float(confidence), 4),
        "entity_overlap": round(float(entity_overlap), 4),
        "source_bonus": round(float(source_bonus), 4),
        "recency_bonus": round(float(recency_bonus), 4),
        "typed_score": round(float(score), 4),
    }
