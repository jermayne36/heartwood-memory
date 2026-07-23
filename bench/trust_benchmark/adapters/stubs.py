"""Competitor adapter stubs.

These are intentionally non-live. This benchmark run makes ZERO third-party
network calls and requires ZERO new competitor signups or credentials, so no
comparative claim about a competitor is produced. Each stub declares (a) which
governance primitives the product is understood to offer vs not, and (b)
exactly what a real, funded run would require. The stubs make it structurally
impossible to publish a competitor comparison until a real run replaces them.

Capability rows below are declared as ``None`` = "not independently verified in
this run". They are hypotheses to be confirmed by a real adapter, never claims.
"""
from __future__ import annotations

from .base import AdapterNotAvailable, MemoryAdapter, Session


class _CompetitorStub(MemoryAdapter):
    _requirements: dict = {}
    _capabilities: dict = {}
    _applicability: str = ""

    def capabilities(self) -> dict:
        return dict(self._capabilities)

    def requirements(self) -> dict:
        return {**self._requirements, "probe_applicability": self._applicability}

    def session(self, **config) -> Session:
        raise AdapterNotAvailable(
            f"{self.name} adapter is a stub in benchmark v1: "
            f"{self._requirements.get('needs', 'a real integration is required')}"
        )


class Mem0Stub(_CompetitorStub):
    name = "mem0"
    _capabilities = {
        # None = not independently verified in this run (hypothesis, not a claim).
        "signed_provenance": None,
        "strict_enforcement": None,
        "hash_chained_audit": None,
        "external_anchor": None,
        "policy_before_ranking": None,
        "auditable_retirement": None,
        "key_destruction_receipt": None,
        "crypto_erase_proof": None,
    }
    _requirements = {
        "needs": "mem0 account + OpenAI (or configured LLM) API key",
        "api_surface": "mem0 client add()/search()/get_all()/delete()",
        "free_tier": "hosted free tier exists; self-host OSS avoids signup",
        "signup": "yes (hosted) — OUT of scope for a $0 no-signup run",
        "network": "third-party calls to mem0 + an embedding/LLM provider",
    }
    _applicability = (
        "Forgery/tamper/erasure probes measure whether a signed-provenance / "
        "hash-chained-audit / key-destruction primitive EXISTS to test; a real "
        "run reports primitive-absent where mem0 offers no equivalent receipt."
    )


class ZepStub(_CompetitorStub):
    name = "zep"
    _capabilities = {
        "signed_provenance": None,
        "strict_enforcement": None,
        "hash_chained_audit": None,
        "external_anchor": None,
        "policy_before_ranking": None,
        "auditable_retirement": None,
        "key_destruction_receipt": None,
        "crypto_erase_proof": None,
    }
    _requirements = {
        "needs": "Zep Cloud API key or self-hosted Zep + Graphiti stack",
        "api_surface": "Zep memory add/search/delete; graph episodes",
        "free_tier": "cloud free tier exists; self-host avoids signup",
        "signup": "yes (cloud) — OUT of scope for a $0 no-signup run",
        "network": "third-party calls to Zep + an embedding/LLM provider",
    }
    _applicability = (
        "Policy-leak and retirement probes map to Zep's access model and "
        "episode invalidation; a real run measures whether recall exclusion and "
        "audited retirement are enforced, not merely available."
    )


class SupermemoryStub(_CompetitorStub):
    name = "supermemory"
    _capabilities = {
        "signed_provenance": None,
        "strict_enforcement": None,
        "hash_chained_audit": None,
        "external_anchor": None,
        "policy_before_ranking": None,
        "auditable_retirement": None,
        "key_destruction_receipt": None,
        "crypto_erase_proof": None,
    }
    _requirements = {
        "needs": "Supermemory API key",
        "api_surface": "Supermemory add/search/delete endpoints",
        "free_tier": "free tier exists; requires account + API key",
        "signup": "yes — OUT of scope for a $0 no-signup run",
        "network": "third-party calls to the Supermemory API",
    }
    _applicability = (
        "All five probe classes require the corresponding governance receipt to "
        "exist; a real run reports primitive-absent for any receipt Supermemory "
        "does not provide, rather than a pass/fail comparison."
    )


def competitor_stub_adapters() -> list[MemoryAdapter]:
    return [Mem0Stub(), ZepStub(), SupermemoryStub()]


STUB_ADAPTERS = ["mem0", "zep", "supermemory"]
