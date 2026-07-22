"""Human review-state workflow for generated memories."""
from __future__ import annotations

from enum import Enum


class ReviewState(str, Enum):
    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    DISPUTED = "disputed"


LEGAL_TRANSITIONS = {
    ReviewState.PROPOSED: {
        ReviewState.ACCEPTED,
        ReviewState.REJECTED,
        ReviewState.DISPUTED,
        ReviewState.SUPERSEDED,
    },
    ReviewState.ACCEPTED: {ReviewState.SUPERSEDED, ReviewState.DISPUTED},
    ReviewState.REJECTED: {ReviewState.DISPUTED},
    ReviewState.DISPUTED: {
        ReviewState.ACCEPTED,
        ReviewState.REJECTED,
        ReviewState.SUPERSEDED,
    },
    ReviewState.SUPERSEDED: set(),
}

REVIEW_ROLES = {"reviewer", "approver"}
# Default recall returns current truth. These states all mean "not current":
# rejected (untrusted), disputed (contested), and superseded (replaced by a newer
# record — a terminal state that `approve` also refuses). Callers that need the
# retired record, e.g. audit and lineage tooling, opt back in explicitly with
# filters={"include_review_states": [...]}, and the choice is reported in
# explain_recall(...)["hidden_review_states"].
DEFAULT_HIDDEN_REVIEW_STATES = {
    ReviewState.REJECTED.value,
    ReviewState.DISPUTED.value,
    ReviewState.SUPERSEDED.value,
}


def normalize_review_state(state: str | ReviewState | None) -> str | None:
    if state is None or state == "":
        return None
    if isinstance(state, ReviewState):
        return state.value
    return ReviewState(str(state)).value


def validate_transition(frm: str | ReviewState | None,
                        to: str | ReviewState | None,
                        principal) -> str:
    """Validate a review-state transition and return the normalized target."""
    from_state_value = normalize_review_state(frm)
    to_state_value = normalize_review_state(to)
    if to_state_value is None:
        raise ValueError("review transition target is required")

    roles = set(getattr(principal, "roles", ()) or ())
    if not (roles & REVIEW_ROLES):
        raise PermissionError("review transition requires the 'reviewer' or 'approver' role")

    if from_state_value is None:
        raise ValueError("memory is not in the review workflow")

    from_state = ReviewState(from_state_value)
    to_state = ReviewState(to_state_value)
    if to_state not in LEGAL_TRANSITIONS[from_state]:
        raise ValueError(f"illegal review transition: {from_state.value} -> {to_state.value}")
    return to_state.value
