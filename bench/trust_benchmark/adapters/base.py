"""Substrate-neutral adapter interface for the trust-receipts benchmark."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class AdapterNotAvailable(RuntimeError):
    """Raised by a stub adapter that has no live implementation in this run."""


@dataclass
class RecallView:
    """Normalized, caller-facing view of one recall call.

    ``hits`` is the ordered list of returned records, each a dict with at least
    ``id`` and ``content`` and, where the substrate provides them, the surfaced
    ``signature_valid`` / ``content_hash_match`` provenance flags. ``raised`` is
    the exception type name if recall failed closed (e.g. strict enforcement),
    else ``None``. ``denied`` is the audited count of policy-denied candidates
    where the substrate exposes it.
    """
    hits: list[dict] = field(default_factory=list)
    raised: str | None = None
    denied: int | None = None
    strict_dropped_ids: list[str] = field(default_factory=list)
    recall_id: str | None = None
    audit_detail: dict | None = None
    explain: dict | None = None

    @property
    def ids(self) -> list[str]:
        return [h["id"] for h in self.hits]

    def contains_text(self, needle: str) -> bool:
        return any(needle in str(h.get("content") or "") for h in self.hits)

    def hit(self, memory_id: str) -> dict | None:
        for h in self.hits:
            if h["id"] == memory_id:
                return h
        return None


class Session(ABC):
    """One open store. Governance + adversary operations over a single tenant.

    Adversary methods simulate an at-rest / database-write ("T2") attacker
    against the substrate. They are attack simulation for measurement, never a
    product API.
    """

    # --- governance ----------------------------------------------------- #
    @abstractmethod
    def remember(self, *, memory_id: str, subject: str, content: str,
                 created_by: str = "agent:bench", classification: str = "internal",
                 role_gate: tuple = (), indexed: bool = True,
                 review_state: str | None = None) -> str: ...

    @abstractmethod
    def recall(self, cue: str, *, reader: dict, filters: dict | None = None) -> RecallView: ...

    @abstractmethod
    def verify_audit(self) -> bool: ...

    @abstractmethod
    def set_indexed(self, memory_id: str, indexed: bool, *, actor: str = "agent:bench",
                    reason: str = "") -> None: ...

    @abstractmethod
    def expire(self, memory_id: str, at, *, actor: str = "agent:bench",
               reason: str = "") -> None: ...

    @abstractmethod
    def supersede(self, memory_id: str, *, reviewer: dict, reason: str = "") -> None: ...

    @abstractmethod
    def forget(self, subject: str, *, actor: str = "agent:bench", reason: str = "") -> dict: ...

    @abstractmethod
    def erase_proof(self, *, root_present: bool) -> dict: ...

    @abstractmethod
    def audit_action_present(self, target: str, action: str) -> bool: ...

    # --- external anchoring (optional capability) ----------------------- #
    def anchor(self) -> dict:
        raise AdapterNotAvailable("external anchoring not supported by this adapter")

    def verify_against_anchors(self) -> dict:
        raise AdapterNotAvailable("external anchoring not supported by this adapter")

    # --- adversary simulation (at-rest / DB-write attacker) ------------- #
    @abstractmethod
    def adv_flip_content_hash(self, memory_id: str) -> None: ...

    @abstractmethod
    def adv_forge_signature(self, memory_id: str) -> None: ...

    @abstractmethod
    def adv_flip_unsigned_field(self, memory_id: str, field: str, value) -> None: ...

    @abstractmethod
    def adv_edit_audit_body_inplace(self) -> None: ...

    @abstractmethod
    def adv_drop_interior_audit_row(self) -> None: ...

    @abstractmethod
    def adv_truncate_audit_tail(self, n: int = 1) -> None: ...

    @abstractmethod
    def adv_raw_unindex(self, memory_id: str) -> None: ...

    # --- lifecycle ------------------------------------------------------ #
    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class MemoryAdapter(ABC):
    """A benchmarkable memory system. ``session()`` opens an isolated store."""

    name: str = "abstract"

    @abstractmethod
    def capabilities(self) -> dict: ...

    def requirements(self) -> dict:
        """What a real (non-stub) run of this adapter would need. Empty when live."""
        return {}

    @abstractmethod
    def session(self, **config) -> Session: ...

    def cleanup(self) -> None:
        """Release any adapter-owned resources (temp dirs, connections)."""
