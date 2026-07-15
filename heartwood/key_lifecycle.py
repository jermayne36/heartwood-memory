"""Per-tenant key lifecycle helpers for Heartwood custody roots.

These helpers operate on the existing KeyCustodian seam. They do not rotate
live infrastructure secrets; callers provide throwaway or owner-approved root
material explicitly.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

from .key_custody import (
    KeyCustodian,
    LocalKmsCustodian,
    RawKeyCustodian,
    envelope_key_id,
    is_wrapped_key,
    root_from_b64,
    root_to_b64,
)
from .provenance import Signer
from .store import Store


@dataclass(frozen=True)
class TenantRootMaterial:
    tenant: str
    key_id: str
    root_b64: str

    def custodian(self) -> LocalKmsCustodian:
        return LocalKmsCustodian(root_from_b64(self.root_b64), key_id=self.key_id)

    def env(self) -> dict[str, str]:
        return {
            "HEARTWOOD_KEY_CUSTODY_ROOT_B64": self.root_b64,
            "HEARTWOOD_KEY_CUSTODY_KEY_ID": self.key_id,
        }


@dataclass(frozen=True)
class RewrapReport:
    tenant: str
    old_mode: str
    new_mode: str
    new_key_id: str
    scanned: int
    migrated: int
    raw_migrated: int
    rewrapped: int
    already_current: int
    skipped_shredded: int
    skipped_missing: int
    remaining: int
    limit_reached: bool

    @property
    def complete(self) -> bool:
        return self.remaining == 0 and not self.limit_reached

    def to_dict(self) -> dict:
        data = asdict(self)
        data["complete"] = self.complete
        return data


@dataclass(frozen=True)
class ProvenanceAliasReport:
    tenant: str
    old_key_id: str
    new_key_id: str
    principals_scanned: int
    legacy_aliases_registered: int
    new_aliases_registered: int
    skipped_non_ed25519: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class RotationReport:
    tenant: str
    provenance: ProvenanceAliasReport
    keys: RewrapReport

    @property
    def complete(self) -> bool:
        return self.keys.complete

    def to_dict(self) -> dict:
        return {
            "tenant": self.tenant,
            "complete": self.complete,
            "provenance": self.provenance.to_dict(),
            "keys": self.keys.to_dict(),
        }


@dataclass(frozen=True)
class CryptoEraseProof:
    tenant: str
    db_path: str
    root_present: bool
    data_store_present: bool
    data_files_present: tuple[str, ...]
    active_key_count: int
    wrapped_active_key_count: int
    raw_active_key_count: int
    shredded_key_count: int
    content_unrecoverable: bool
    proved: bool
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


def provision_tenant_root(
    tenant: str,
    *,
    version: int = 1,
    key_id: str | None = None,
    root_key: bytes | None = None,
) -> TenantRootMaterial:
    root = root_key or os.urandom(32)
    if len(root) < 32:
        raise ValueError("tenant custody root must be at least 32 bytes")
    return TenantRootMaterial(
        tenant=tenant,
        key_id=key_id or f"{tenant}-root-v{version}",
        root_b64=root_to_b64(root[:32]),
    )


def rewrap_tenant_keys(
    store,
    *,
    tenant: str,
    old_custodian: KeyCustodian | None,
    new_custodian: LocalKmsCustodian,
    max_updates: int | None = None,
) -> RewrapReport:
    old = old_custodian or RawKeyCustodian()
    scanned = migrated = raw_migrated = rewrapped = already = skipped_shredded = skipped_missing = 0
    limit_reached = False
    updates = 0

    for row in store.iter_keys(tenant):
        if max_updates is not None and updates >= max_updates:
            limit_reached = True
            break
        scanned += 1
        subject = row["subject"]
        envelope = row["dek"]
        state = row["state"]
        if state == "shredded":
            skipped_shredded += 1
            continue
        if envelope is None:
            skipped_missing += 1
            continue
        if is_wrapped_key(envelope) and envelope_key_id(envelope) == new_custodian.key_id:
            new_custodian.unwrap(tenant=tenant, subject=subject, envelope=envelope)
            already += 1
            continue

        was_wrapped = is_wrapped_key(envelope)
        dek = old.unwrap(tenant=tenant, subject=subject, envelope=envelope)
        new_envelope = new_custodian.wrap(tenant=tenant, subject=subject, dek=dek)
        store.put_key(tenant, subject, new_envelope)
        updates += 1
        migrated += 1
        if was_wrapped:
            rewrapped += 1
        else:
            raw_migrated += 1

    remaining = _remaining_rewrap_count(store, tenant=tenant, new_custodian=new_custodian)
    return RewrapReport(
        tenant=tenant,
        old_mode=old.name,
        new_mode=new_custodian.name,
        new_key_id=new_custodian.key_id,
        scanned=scanned,
        migrated=migrated,
        raw_migrated=raw_migrated,
        rewrapped=rewrapped,
        already_current=already,
        skipped_shredded=skipped_shredded,
        skipped_missing=skipped_missing,
        remaining=remaining,
        limit_reached=limit_reached,
    )


def register_rotation_provenance_aliases(
    store,
    *,
    tenant: str,
    old_custodian: LocalKmsCustodian,
    new_custodian: LocalKmsCustodian,
) -> ProvenanceAliasReport:
    principals = store.iter_principal_keys(tenant)
    signer = Signer(store, tenant, key_custodian=new_custodian)
    scanned = legacy_aliases = new_aliases = skipped_non_ed25519 = 0

    for row in principals:
        scanned += 1
        if row["algorithm"] != "ed25519":
            skipped_non_ed25519 += 1
            continue
        principal_id = row["principal_id"]
        before = store.principal_key_alias_count(tenant, principal_id)
        store.register_principal_key_alias(
            tenant,
            principal_id,
            "ed25519",
            row["public_key"],
            old_custodian.key_id,
        )
        after_legacy = store.principal_key_alias_count(tenant, principal_id)
        if after_legacy > before:
            legacy_aliases += 1

        signer.register(principal_id)
        after_new = store.principal_key_alias_count(tenant, principal_id)
        if after_new > after_legacy:
            new_aliases += 1

    return ProvenanceAliasReport(
        tenant=tenant,
        old_key_id=old_custodian.key_id,
        new_key_id=new_custodian.key_id,
        principals_scanned=scanned,
        legacy_aliases_registered=legacy_aliases,
        new_aliases_registered=new_aliases,
        skipped_non_ed25519=skipped_non_ed25519,
    )


def rotate_tenant_root(
    store,
    *,
    tenant: str,
    old_custodian: LocalKmsCustodian,
    new_custodian: LocalKmsCustodian,
    max_updates: int | None = None,
) -> RotationReport:
    provenance = register_rotation_provenance_aliases(
        store,
        tenant=tenant,
        old_custodian=old_custodian,
        new_custodian=new_custodian,
    )
    keys = rewrap_tenant_keys(
        store,
        tenant=tenant,
        old_custodian=old_custodian,
        new_custodian=new_custodian,
        max_updates=max_updates,
    )
    return RotationReport(tenant=tenant, provenance=provenance, keys=keys)


def prove_crypto_erase_path(
    db_path: str | Path,
    *,
    tenant: str,
    root_present: bool,
) -> CryptoEraseProof:
    path = Path(db_path)
    present_paths = tuple(str(candidate) for candidate in _sqlite_data_paths(path) if candidate.exists())
    if not present_paths:
        proved = not root_present
        return CryptoEraseProof(
            tenant=tenant,
            db_path=str(path),
            root_present=root_present,
            data_store_present=False,
            data_files_present=present_paths,
            active_key_count=0,
            wrapped_active_key_count=0,
            raw_active_key_count=0,
            shredded_key_count=0,
            content_unrecoverable=proved,
            proved=proved,
            reason="root absent and SQLite data files absent" if proved else "root still present",
        )

    store = Store(str(path))
    try:
        return prove_crypto_erase_store(store, tenant=tenant, root_present=root_present, db_path=str(path))
    finally:
        store.close()


def prove_crypto_erase_store(
    store,
    *,
    tenant: str,
    root_present: bool,
    db_path: str = ":memory:",
) -> CryptoEraseProof:
    active = wrapped = raw = shredded = 0
    for row in store.iter_keys(tenant):
        if row["state"] == "shredded":
            shredded += 1
            continue
        if row["dek"] is None:
            continue
        active += 1
        if is_wrapped_key(row["dek"]):
            wrapped += 1
        else:
            raw += 1

    content_unrecoverable = not root_present and raw == 0
    proved = content_unrecoverable
    if root_present:
        reason = "root still present"
    elif raw:
        reason = "raw active DEKs remain in the database"
    else:
        reason = "root absent and no raw active DEKs remain"
    return CryptoEraseProof(
        tenant=tenant,
        db_path=db_path,
        root_present=root_present,
        data_store_present=True,
        data_files_present=(db_path,),
        active_key_count=active,
        wrapped_active_key_count=wrapped,
        raw_active_key_count=raw,
        shredded_key_count=shredded,
        content_unrecoverable=content_unrecoverable,
        proved=proved,
        reason=reason,
    )


def _remaining_rewrap_count(store, *, tenant: str, new_custodian: LocalKmsCustodian) -> int:
    remaining = 0
    for row in store.iter_keys(tenant):
        if row["state"] == "shredded" or row["dek"] is None:
            continue
        if not is_wrapped_key(row["dek"]) or envelope_key_id(row["dek"]) != new_custodian.key_id:
            remaining += 1
    return remaining


def _sqlite_data_paths(path: Path) -> tuple[Path, ...]:
    return (
        path,
        path.with_name(f"{path.name}-wal"),
        path.with_name(f"{path.name}-shm"),
    )
