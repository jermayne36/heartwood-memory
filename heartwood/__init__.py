"""Heartwood — provenance-first, embedded agent-memory library (Phase 0).

The differentiation is governance — tamper-evident provenance + policy-enforced
recall + crypto-shred erasure — over benchmark-validated hybrid retrieval. NOT a
novel retrieval mechanism (spreading activation was CUT).

    from heartwood import Heartwood, Principal, Policy
    db = Heartwood(path="mem.db", tenant="tenant:acme")
    mid = db.remember("User prefers concise answers.", subject="user:1",
                      created_by="agent:asst", kind="semantic", epistemic="user-stated")
    out = db.recall("how should I talk to this user?",
                    principal=Principal(id="agent:asst", tenant="tenant:acme"))
"""
from .client import Heartwood
from .egress import DENIED, EXTERNAL_ALLOWED, EXTERNAL_REDACTED, HUMAN_REVIEW, LOCAL_ONLY
from .envelope import Epistemic, Kind, Memory, Policy, TruthStatus
from .ergonomics import normalize_tenant, policy_from, principal_from, tenant_slug
from .key_custody import LocalKmsCustodian, RawKeyCustodian
from .key_lifecycle import (
    CryptoEraseProof,
    ProvenanceAliasReport,
    RewrapReport,
    RotationReport,
    TenantRootMaterial,
    provision_tenant_root,
    prove_crypto_erase_path,
    register_rotation_provenance_aliases,
    rewrap_tenant_keys,
    rotate_tenant_root,
)
from .policy import Principal

__all__ = [
    "Heartwood",
    "Principal",
    "Policy",
    "Memory",
    "Kind",
    "Epistemic",
    "TruthStatus",
    "normalize_tenant",
    "tenant_slug",
    "policy_from",
    "principal_from",
    "LocalKmsCustodian",
    "RawKeyCustodian",
    "TenantRootMaterial",
    "RewrapReport",
    "ProvenanceAliasReport",
    "RotationReport",
    "CryptoEraseProof",
    "provision_tenant_root",
    "rewrap_tenant_keys",
    "rotate_tenant_root",
    "register_rotation_provenance_aliases",
    "prove_crypto_erase_path",
    "EXTERNAL_ALLOWED",
    "EXTERNAL_REDACTED",
    "LOCAL_ONLY",
    "HUMAN_REVIEW",
    "DENIED",
]
__version__ = "0.2.3"
