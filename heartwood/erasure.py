"""Erasure: crypto-shredding (per-subject keys) + deletion-lineage purge.

Validated by EDPB Guidelines 02/2025: for immutable/derived data, encrypt PII
with per-subject keys and destroy the keys on erasure. Crypto-shredding alone is
not sufficient (an embedding is a recoverable encoding of its source), so
forget(hard) ALSO physically purges derived artifacts (embeddings, postings) via
the deletion lineage. The erasure *event* is retained in the audit log.

Cipher: AES via cryptography.Fernet. Heartwood fails closed if the cryptography
package is unavailable instead of falling back to a dev-grade cipher. Production
stores keys in an external KMS/HSM, not beside the data.
"""
from __future__ import annotations

import base64
import os

from .key_custody import KeyCustodian, RawKeyCustodian, custodian_from_env, is_wrapped_key
from .store import Store, erased_subject_error

try:
    from cryptography.fernet import Fernet
    _HAVE_FERNET = True
except Exception as exc:  # pragma: no cover - exercised only without dependency
    _FERNET_IMPORT_ERROR = exc
    _HAVE_FERNET = False


def new_key() -> bytes:
    return os.urandom(32)


class Cipher:
    name = "fernet-aes128"

    def __init__(self):
        if not _HAVE_FERNET:
            raise RuntimeError(
                "Heartwood requires the 'cryptography' package for encrypted memory. "
                "Install heartwood-memory with its default dependencies or add "
                "cryptography>=42."
            ) from _FERNET_IMPORT_ERROR

    def encrypt(self, plaintext: str, key: bytes) -> bytes:
        pt = plaintext.encode("utf-8")
        return Fernet(base64.urlsafe_b64encode(key[:32])).encrypt(pt)

    def decrypt(self, ciphertext: bytes, key: bytes) -> str:
        return Fernet(base64.urlsafe_b64encode(key[:32])).decrypt(ciphertext).decode("utf-8")


class KeyStore:
    """Per-subject data-encryption keys. Production: external KMS. Here: the
    `keys` table (so the demo is self-contained), with shred = key destruction."""

    def __init__(self, store: Store, custodian: KeyCustodian | None = None):
        self.store = store
        self.custodian = custodian or custodian_from_env()

    def get_or_create(self, tenant: str, subject: str) -> bytes:
        envelope, state = self.store.get_key(tenant, subject)
        if envelope is None and state != "shredded":
            key = new_key()
            wrapped = self.custodian.wrap(tenant=tenant, subject=subject, dek=key)
            # The store keeps whichever row exists first: an erasure's tombstone
            # or another writer's key, which this writer then uses instead.
            envelope, state = self.store.create_key(tenant, subject, wrapped)
            if state != "shredded" and envelope == wrapped:
                return key
        if state == "shredded":
            raise erased_subject_error(subject)
        if envelope is None:
            raise RuntimeError(f"subject {subject} has a key row without key material")
        resolved_key, state = self._resolve_key(tenant, subject, envelope, state)
        if resolved_key is None:
            if state == "shredded":
                raise erased_subject_error(subject)
            raise RuntimeError("subject key changed during custody migration")
        return resolved_key

    def get(self, tenant: str, subject: str) -> bytes | None:
        envelope, state = self.store.get_key(tenant, subject)
        key, _ = self._resolve_key(tenant, subject, envelope, state)
        return key

    def _resolve_key(
        self, tenant: str, subject: str, envelope: bytes | None, state: str | None,
    ) -> tuple[bytes | None, str | None]:
        if state == "shredded" or envelope is None:
            return None, state
        if is_wrapped_key(envelope):
            return self.custodian.unwrap(tenant=tenant, subject=subject, envelope=envelope), state
        if isinstance(self.custodian, RawKeyCustodian):
            return envelope, state
        # Migrate old raw-local stores lazily when custody is enabled.
        wrapped = self.custodian.wrap(tenant=tenant, subject=subject, dek=envelope)
        if self.store.rewrap_raw_key(
            tenant, subject, expected_dek=envelope, wrapped_dek=wrapped,
        ):
            return envelope, state
        # A concurrent migration can supply a usable envelope. Never use the stale DEK.
        current, state = self.store.get_key(tenant, subject)
        if state == "active" and current is not None and is_wrapped_key(current):
            return self.custodian.unwrap(tenant=tenant, subject=subject, envelope=current), state
        return None, state

    def custody_info(self, tenant: str, subject: str) -> dict:
        envelope, state = self.store.get_key(tenant, subject)
        info = self.custodian.info(envelope)
        info["state"] = state or "missing"
        return info

    def shred(self, tenant: str, subject: str):
        self.store.shred_key(tenant, subject)
