"""Validation for mutable typed-memory metadata.

These fields affect recall and ranking after a memory has been signed and
stored.  Normalize them before the compare-and-swap so malformed timestamps
cannot fail open and future ``valid_from`` values cannot silently hide a row.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .envelope import TruthStatus
from .typed_ranking import parse_dt


def normalize_metadata_instant(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a parseable instant, got {value!r}")
    parsed = parse_dt(value)
    if parsed is None:
        raise ValueError(f"{field} must be a parseable instant, got {value!r}")
    return parsed.astimezone(timezone.utc).isoformat()


def normalize_substrate_metadata(
    *,
    valid_from: Any,
    valid_until: Any,
    entities: Any,
    truth_status: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    normalized_from = normalize_metadata_instant(valid_from, field="valid_from")
    normalized_until = normalize_metadata_instant(valid_until, field="valid_until")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if normalized_from is not None and datetime.fromisoformat(normalized_from) > current:
        raise ValueError(
            "valid_from cannot be in the future because it would hide the memory "
            "from default recall"
        )
    if (
        normalized_from is not None
        and normalized_until is not None
        and datetime.fromisoformat(normalized_until) < datetime.fromisoformat(normalized_from)
    ):
        raise ValueError("valid_until cannot be earlier than valid_from")
    if not isinstance(entities, (list, tuple)):
        raise TypeError("entities must be a list or tuple of non-empty strings")
    normalized_entities = []
    for entity in entities:
        if not isinstance(entity, str) or not entity.strip():
            raise ValueError("entities must contain only non-empty strings")
        normalized = entity.strip()
        if normalized not in normalized_entities:
            normalized_entities.append(normalized)
    try:
        normalized_truth = TruthStatus(truth_status).value
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(status.value for status in TruthStatus)
        raise ValueError(f"truth_status must be one of: {allowed}") from exc
    return {
        "valid_from": normalized_from,
        "valid_until": normalized_until,
        "entities": tuple(normalized_entities),
        "truth_status": normalized_truth,
    }
