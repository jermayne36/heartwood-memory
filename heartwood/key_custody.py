"""Key-custody adapters for Heartwood data-encryption keys.

The production pattern is an envelope-encryption chain:

    deployment root secret -> HKDF tenant/subject KEK -> AES-KW wrapped DEK

The local raw custodian remains available for older stores and tiny in-memory
tests. Production deployments can inject a provider adapter through the public
custody and durable-signing protocols without exposing provider implementation
code in the core.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

ENVELOPE_PREFIX = b"hwkw1:"


def _validate_retention_floor_seconds(value: int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("retention_floor_seconds must be a non-negative integer")
    return value


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def root_to_b64(root_key: bytes) -> str:
    """Encode root material for vault/env transport."""

    return _b64e(root_key)


def root_from_b64(root: str) -> bytes:
    """Decode and validate root material from vault/env transport."""

    root_key = _b64d(root)
    if len(root_key) < 32:
        raise ValueError("root material must decode to at least 32 bytes")
    return root_key[:32]


def is_wrapped_key(blob: bytes | None) -> bool:
    return bool(blob and bytes(blob).startswith(ENVELOPE_PREFIX))


def envelope_key_id(blob: bytes | None) -> str | None:
    if not is_wrapped_key(blob):
        return None
    data = json.loads(bytes(blob)[len(ENVELOPE_PREFIX):].decode("utf-8"))
    return data.get("key_id")


@runtime_checkable
class Ed25519Signer(Protocol):
    """Opaque Ed25519 signing handle returned by a custody backend."""

    key_id: str

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte Ed25519 verification key."""

    def sign(self, payload: bytes) -> bytes:
        """Sign bytes without exposing the custody backend's root material."""


@runtime_checkable
class SigningKeyCustodian(Protocol):
    """Capability seam for custody backends that can provide durable signing."""

    key_id: str

    def ed25519_signer(self, *, salt: bytes, info: bytes) -> Ed25519Signer:
        """Return a deterministic domain-scoped Ed25519 signing handle."""


@dataclass(frozen=True)
class _LocalEd25519Signer:
    key_id: str
    private_key: ed25519.Ed25519PrivateKey

    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, payload: bytes) -> bytes:
        return self.private_key.sign(payload)


class KeyCustodian:
    """Custody contract with a declared provider-side retention floor.

    The floor is echoed in erasure receipts as configuration, not measured as
    an erasure-duration or purge-completion guarantee. ``None`` means that a
    backend has not declared a floor; proof-oriented callers declare one.
    """

    name = "raw-local"
    retention_floor_seconds = 0

    def __init__(self, *, retention_floor_seconds: int = 0):
        self.retention_floor_seconds = _validate_retention_floor_seconds(
            retention_floor_seconds
        )

    def wrap(self, *, tenant: str, subject: str, dek: bytes) -> bytes:
        return dek

    def unwrap(self, *, tenant: str, subject: str, envelope: bytes) -> bytes:
        return envelope

    def info(self, envelope: bytes | None = None) -> dict:
        return {
            "mode": self.name,
            "wrapped": is_wrapped_key(envelope),
            "retention_floor_seconds": self.retention_floor_seconds,
        }


class RawKeyCustodian(KeyCustodian):
    """Compatibility custodian: stores raw DEKs exactly like early Phase 0."""

    name = "raw-local"


@dataclass(frozen=True)
class LocalKmsCustodian(KeyCustodian):
    """Local KMS-compatible custodian using HKDF and AES key wrap.

    ``root_key`` stands in for a KMS/HSM-protected secret. In production this
    should be loaded from the deployment vault, not committed to the database or
    source tree.
    """

    root_key: bytes
    key_id: str = "local-root"
    retention_floor_seconds: int | None = None

    def __post_init__(self) -> None:
        _validate_retention_floor_seconds(self.retention_floor_seconds)

    @property
    def name(self) -> str:  # type: ignore[override]
        return "hkdf-aeskw-local"

    def wrap(self, *, tenant: str, subject: str, dek: bytes) -> bytes:
        envelope = {
            "v": 1,
            "alg": "HKDF-SHA256+A256KW",
            "key_id": self.key_id,
            "wrapped_dek": _b64e(aes_key_wrap(self._kek(tenant, subject), dek)),
        }
        return ENVELOPE_PREFIX + json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def unwrap(self, *, tenant: str, subject: str, envelope: bytes) -> bytes:
        if not is_wrapped_key(envelope):
            return envelope
        data = json.loads(bytes(envelope)[len(ENVELOPE_PREFIX):].decode("utf-8"))
        if data.get("alg") != "HKDF-SHA256+A256KW":
            raise ValueError(f"unsupported DEK envelope algorithm: {data.get('alg')}")
        if data.get("key_id") != self.key_id:
            raise ValueError(f"DEK envelope key_id {data.get('key_id')!r} does not match {self.key_id!r}")
        return aes_key_unwrap(self._kek(tenant, subject), _b64d(data["wrapped_dek"]))

    def info(self, envelope: bytes | None = None) -> dict:
        info = {
            "mode": self.name,
            "key_id": self.key_id,
            "wrapped": is_wrapped_key(envelope),
            "retention_floor_seconds": self.retention_floor_seconds,
        }
        if is_wrapped_key(envelope):
            data = json.loads(bytes(envelope)[len(ENVELOPE_PREFIX):].decode("utf-8"))
            info["algorithm"] = data.get("alg")
            info["envelope_key_id"] = data.get("key_id")
        return info

    def ed25519_signer(self, *, salt: bytes, info: bytes) -> Ed25519Signer:
        if not isinstance(salt, bytes) or not salt:
            raise ValueError("Ed25519 derivation salt must be non-empty bytes")
        if not isinstance(info, bytes) or not info:
            raise ValueError("Ed25519 derivation info must be non-empty bytes")
        seed = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        ).derive(self.root_key)
        return _LocalEd25519Signer(
            key_id=self.key_id,
            private_key=ed25519.Ed25519PrivateKey.from_private_bytes(seed),
        )

    def _kek(self, tenant: str, subject: str) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=f"heartwood:kek:{tenant}".encode("utf-8"),
            info=f"subject:{subject}:dek-wrap".encode("utf-8"),
        ).derive(self.root_key)


def custodian_from_env() -> KeyCustodian:
    """Build a custodian from environment variables.

    Set ``HEARTWOOD_KEY_CUSTODY_ROOT_B64`` to a 32-byte base64url root secret to
    enable HKDF/AES-KW wrapping. Without it, Heartwood keeps legacy raw-local
    behavior for compatibility and tests.
    """

    root = os.environ.get("HEARTWOOD_KEY_CUSTODY_ROOT_B64")
    if not root:
        return RawKeyCustodian()
    root_key = root_from_b64(root)
    return LocalKmsCustodian(
        root_key=root_key,
        key_id=os.environ.get("HEARTWOOD_KEY_CUSTODY_KEY_ID", "env-root"),
    )
