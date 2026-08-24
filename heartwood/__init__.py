"""Heartwood — provenance-first, embedded agent-memory library.

Public exports are lazy so the offline receipt verifier can run from the wheel
without importing retrieval/model dependencies. Accessing an embedded-memory
API imports its owning module on demand.
"""
from __future__ import annotations

from importlib import import_module

_EXPORTS = {
    "Heartwood": (".client", "Heartwood"),
    "AnchorSink": (".anchors", "AnchorSink"),
    "LocalFileAnchorSink": (".anchors", "LocalFileAnchorSink"),
    "AnchorError": (".anchors", "AnchorError"),
    "AnchorConfigurationError": (".anchors", "AnchorConfigurationError"),
    "AnchorSinkError": (".anchors", "AnchorSinkError"),
    "AnchorWriteError": (".anchors", "AnchorWriteError"),
    "anchor_root_fingerprint": (".anchors", "anchor_root_fingerprint"),
    "verify_chain_against_anchors": (".anchors", "verify_chain_against_anchors"),
    "Principal": (".policy", "Principal"),
    "Policy": (".envelope", "Policy"),
    "Memory": (".envelope", "Memory"),
    "Kind": (".envelope", "Kind"),
    "Epistemic": (".envelope", "Epistemic"),
    "TruthStatus": (".envelope", "TruthStatus"),
    "normalize_tenant": (".ergonomics", "normalize_tenant"),
    "tenant_slug": (".ergonomics", "tenant_slug"),
    "policy_from": (".ergonomics", "policy_from"),
    "principal_from": (".ergonomics", "principal_from"),
    "LocalKmsCustodian": (".key_custody", "LocalKmsCustodian"),
    "RawKeyCustodian": (".key_custody", "RawKeyCustodian"),
    "KeyCustodian": (".key_custody", "KeyCustodian"),
    "SigningKeyCustodian": (".key_custody", "SigningKeyCustodian"),
    "Ed25519Signer": (".key_custody", "Ed25519Signer"),
    "TenantRootMaterial": (".key_lifecycle", "TenantRootMaterial"),
    "RewrapReport": (".key_lifecycle", "RewrapReport"),
    "ProvenanceAliasReport": (".key_lifecycle", "ProvenanceAliasReport"),
    "RotationReport": (".key_lifecycle", "RotationReport"),
    "CryptoEraseProof": (".key_lifecycle", "CryptoEraseProof"),
    "provision_tenant_root": (".key_lifecycle", "provision_tenant_root"),
    "rewrap_tenant_keys": (".key_lifecycle", "rewrap_tenant_keys"),
    "rotate_tenant_root": (".key_lifecycle", "rotate_tenant_root"),
    "register_rotation_provenance_aliases": (
        ".key_lifecycle", "register_rotation_provenance_aliases",
    ),
    "prove_crypto_erase_path": (".key_lifecycle", "prove_crypto_erase_path"),
    "EXTERNAL_ALLOWED": (".egress", "EXTERNAL_ALLOWED"),
    "EXTERNAL_REDACTED": (".egress", "EXTERNAL_REDACTED"),
    "LOCAL_ONLY": (".egress", "LOCAL_ONLY"),
    "HUMAN_REVIEW": (".egress", "HUMAN_REVIEW"),
    "DENIED": (".egress", "DENIED"),
    "StrictMode": (".strict", "StrictMode"),
    "StrictConfigurationError": (".strict", "StrictConfigurationError"),
    "StrictSignatureError": (".strict", "StrictSignatureError"),
    "verify_recall_receipt": (".receipts", "verify_recall_receipt"),
    "verify_erasure_receipt": (".receipts", "verify_erasure_receipt"),
    "verify_erasure_against_store": (".receipts", "verify_erasure_against_store"),
}

__all__ = list(_EXPORTS)
__version__ = "0.2.7"


def __getattr__(name: str):
    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_EXPORTS})
