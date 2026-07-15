"""The memory envelope: Heartwood's core immutable record.

A Memory is simultaneously a relational row, an embedding, and (later) a graph
vertex. Records are immutable (frozen dataclass) — updates produce new copies via
`dataclasses.replace`, never in-place mutation (project rule: immutability).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum

_ULID_T = re.compile(r"[^a-z0-9]")


class Kind(str, Enum):
    SOURCE = "source"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"
    PROFILE = "profile"
    GENERATED = "generated"
    WORKING = "working"


class Epistemic(str, Enum):
    OBSERVED_FACT = "observed-fact"
    IMPORTED_SOURCE = "imported-source"
    USER_STATED = "user-stated"
    MODEL_GENERATED = "model-generated"
    INFERRED_BELIEF = "inferred-belief"
    HYPOTHESIS = "hypothesis"
    SIMULATED = "simulated"
    APPROVED_CANONICAL = "approved-canonical"


class TruthStatus(str, Enum):
    SOURCE_OBSERVED = "source_observed"
    GENERATED_SUPPORTED = "generated_supported"
    GENERATED_NEEDS_REVIEW = "generated_needs_review"
    HUMAN_APPROVED = "human_approved"
    INFERRED = "inferred"


# Trust ladder: a producer at trust level T may assert epistemic classes whose
# rank <= T. APPROVED_CANONICAL is never auto-assertable; it requires approve().
_TRUST_RANK = {
    Epistemic.HYPOTHESIS: 0, Epistemic.SIMULATED: 0,
    Epistemic.INFERRED_BELIEF: 1, Epistemic.MODEL_GENERATED: 1,
    Epistemic.USER_STATED: 2, Epistemic.IMPORTED_SOURCE: 2,
    Epistemic.OBSERVED_FACT: 3,
    Epistemic.APPROVED_CANONICAL: 99,
}


def epistemic_rank(e: str) -> int:
    return _TRUST_RANK[Epistemic(e)]


def default_truth_status(epistemic: str) -> str:
    """Map Heartwood's trust ladder onto typed-memory truth-status weights."""
    value = Epistemic(epistemic)
    if value == Epistemic.APPROVED_CANONICAL:
        return TruthStatus.HUMAN_APPROVED.value
    if value in (Epistemic.MODEL_GENERATED,):
        return TruthStatus.GENERATED_SUPPORTED.value
    if value in (Epistemic.INFERRED_BELIEF, Epistemic.HYPOTHESIS, Epistemic.SIMULATED):
        return TruthStatus.INFERRED.value
    return TruthStatus.SOURCE_OBSERVED.value


CLASSIFICATION_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


@dataclass(frozen=True)
class Policy:
    visibility: str = "tenant"          # private | tenant | shared
    classification: str = "internal"    # public | internal | confidential | restricted
    pii: bool = False
    roles: tuple = ()                    # primary role gate: need ANY of these (empty => any)
    attrs: tuple = ()                    # required ((key, value), ...) attribute matches
    retention: str = "decayable"        # pinned | decayable | ttl:<seconds>
    # Additional conjunctive role gates. The effective requirement is the
    # conjunction (AND) of [roles] + role_groups, where each group is a
    # disjunction (need ANY within it). A memory derived from a clinical-gated
    # source AND a billing-gated source requires BOTH clinical and billing.
    role_groups: tuple = ()

    def requirement_groups(self) -> list:
        groups = []
        if self.roles:
            groups.append(tuple(self.roles))
        for g in self.role_groups:
            if g:
                groups.append(tuple(g))
        return groups

    def validate(self):
        if self.classification not in CLASSIFICATION_RANK:
            raise ValueError(f"bad classification: {self.classification}")
        if self.visibility not in ("private", "tenant", "shared"):
            raise ValueError(f"bad visibility: {self.visibility}")


@dataclass(frozen=True)
class Memory:
    id: str
    tenant: str
    kind: str
    epistemic: str
    content: str                 # plaintext in memory; persisted ENCRYPTED (crypto-shred)
    content_hash: str
    subject: str
    confidence: float
    salience: float
    created_by: str
    created_at: float
    source: dict = field(default_factory=dict)
    derived_from: tuple = ()
    model_version: str | None = None
    policy: Policy = field(default_factory=Policy)
    producer_sig: str | None = None
    embedding: object = None     # np.ndarray (L2-normalized) or None until indexed
    truth_status: str | None = None
    policy_scope: str = "default"
    valid_from: str | None = None
    valid_until: str | None = None
    entities: tuple = ()
    source_ids: tuple = ()
    source_spans: tuple = ()

    def validate(self):
        if not self.tenant or not self.subject:
            raise ValueError("tenant and subject are required")
        Kind(self.kind)
        Epistemic(self.epistemic)
        TruthStatus(self.truth_status or default_truth_status(self.epistemic))
        self.policy.validate()
        for name in ("confidence", "salience"):
            v = getattr(self, name)
            if not (0.0 <= float(v) <= 1.0):
                raise ValueError(f"{name} must be in [0,1], got {v}")
        if self.content_hash != hash_content(self.content):
            raise ValueError("content_hash does not match content (integrity)")


def hash_content(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()
