"""Competitor adapter stubs.

These are intentionally non-live. This benchmark run makes ZERO third-party
network calls and requires ZERO new competitor signups or credentials, so no
comparative claim about a competitor is produced.

A stub publishes only two things: the *name* of a substrate no adapter has been
written for, and the fact that nothing about it was measured here. It
deliberately does NOT publish that product's API surface, pricing/free-tier
posture, signup or credential requirements, or which governance primitives it
does or does not offer. Those are competitor-specific assertions, and this run
has no evidence for any of them — a reader would reasonably take them as a
comparison. They may be published only after a real, owner-approved run against
a live adapter, with a cited source per statement and legal review.

Capability rows below are uniformly ``None`` = "not measured in this run".
"""
from __future__ import annotations

from .base import AdapterNotAvailable, MemoryAdapter, Session

# Every governance primitive the benchmark can probe, declared unmeasured for
# every stub. Uniformly None: this run distinguishes no competitor from another.
_UNMEASURED_CAPABILITIES: dict = {
    "signed_provenance": None,
    "strict_enforcement": None,
    "hash_chained_audit": None,
    "external_anchor": None,
    "policy_before_ranking": None,
    "auditable_retirement": None,
    "key_destruction_receipt": None,
    "crypto_erase_proof": None,
}


class _CompetitorStub(MemoryAdapter):
    _capabilities: dict = _UNMEASURED_CAPABILITIES
    _requirements: dict = {
        "adapter": "not implemented in benchmark v1",
        "measured_in_this_run": "nothing",
        "needs": "a live adapter and an owner-approved, funded run before any "
                 "capability, requirement, or comparison for this substrate is "
                 "published",
    }

    def capabilities(self) -> dict:
        return dict(self._capabilities)

    def requirements(self) -> dict:
        return dict(self._requirements)

    def session(self, **config) -> Session:
        raise AdapterNotAvailable(
            f"{self.name} adapter is a stub in benchmark v1: "
            f"{self._requirements.get('needs', 'a real integration is required')}"
        )


class Mem0Stub(_CompetitorStub):
    name = "mem0"


class ZepStub(_CompetitorStub):
    name = "zep"


class SupermemoryStub(_CompetitorStub):
    name = "supermemory"


def competitor_stub_adapters() -> list[MemoryAdapter]:
    return [Mem0Stub(), ZepStub(), SupermemoryStub()]


STUB_ADAPTERS = ["mem0", "zep", "supermemory"]
