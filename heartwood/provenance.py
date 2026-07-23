"""Tamper-evident provenance.

Every memory carries a producer signature binding (id, content_hash, source,
created_by, epistemic) to the producing principal's key. A memory therefore
cannot claim a trust level (epistemic class) its producer did not actually sign
for — defending against memory-poisoning.

Uses Ed25519 when `cryptography` is available. Verification is fail-closed: the
trusted public key must already be registered for the principal, either in the
durable store or in this signer process. The stdlib fallback uses random
per-principal HMAC keys for local/dev mode; it never derives a signing secret
from a public principal id.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    _HAVE_ED25519 = True
except Exception:
    _HAVE_ED25519 = False

from .key_custody import LocalKmsCustodian


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _payload(mem_id, content_hash, source_uri, created_by, epistemic) -> bytes:
    return "|".join([mem_id, content_hash, str(source_uri), created_by, epistemic]).encode("utf-8")


class Signer:
    """Per-principal signing keys. In production, back this with KMS/HSM keys.

    The local scaffold keeps private keys in process memory and persists only
    the trust root: a write-once principal -> public-key registry. After a
    restart, old signatures remain verifiable, but signing as an existing
    principal requires loading that principal's private key from a future KMS
    adapter rather than silently minting a new identity.
    """

    def __init__(self, store: Any = None, tenant: str = "tenant:default", key_custodian: Any = None):
        self.store = store
        self.tenant = tenant
        self.key_custodian = key_custodian
        self._hmac_keys: dict[str, bytes] = {}
        self._ed25519_private = {}
        self._ed25519_public: dict[str, bytes] = {}

    def _get_registered_key(self, principal_id: str) -> tuple[str, bytes] | None:
        if self.store is not None:
            row = self.store.get_principal_key(self.tenant, principal_id)
            if row:
                return row["algorithm"], row["public_key"]
        public_key = self._ed25519_public.get(principal_id)
        if public_key is not None:
            return "ed25519", public_key
        if principal_id in self._hmac_keys:
            return "hmac-sha256", hashlib.sha256(self._hmac_keys[principal_id]).digest()
        return None

    def _get_registered_keys(self, principal_id: str) -> list[tuple[str, bytes]]:
        if self.store is not None and hasattr(self.store, "get_principal_keys"):
            return [
                (row["algorithm"], row["public_key"])
                for row in self.store.get_principal_keys(self.tenant, principal_id)
            ]
        registered = self._get_registered_key(principal_id)
        return [registered] if registered is not None else []

    def _custody_private_key(self, principal_id: str):
        if not (_HAVE_ED25519 and isinstance(self.key_custodian, LocalKmsCustodian)):
            return None
        seed = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=f"heartwood:signing:{self.tenant}".encode("utf-8"),
            info=f"principal:{principal_id}:ed25519:{self.key_custodian.key_id}".encode("utf-8"),
        ).derive(self.key_custodian.root_key)
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed)

    def _public_bytes(self, private_key) -> bytes:
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def _register_key(self, principal_id: str, algorithm: str, public_key: bytes) -> bytes:
        if self.store is not None:
            return self.store.register_principal_key(
                self.tenant,
                principal_id,
                algorithm,
                public_key,
            )
        if algorithm == "ed25519":
            existing = self._ed25519_public.get(principal_id)
            if existing is not None and existing != public_key:
                raise ValueError(f"principal key already registered for {principal_id}")
            self._ed25519_public[principal_id] = public_key
        return public_key

    def register(self, principal_id: str, secret: bytes | None = None) -> bytes:
        if _HAVE_ED25519 and secret is None:
            custody_private = self._custody_private_key(principal_id)
            if custody_private is not None:
                public_key = self._public_bytes(custody_private)
                registered = self._get_registered_keys(principal_id)
                non_ed25519 = [algorithm for algorithm, _key in registered if algorithm != "ed25519"]
                if non_ed25519:
                    raise ValueError(f"principal {principal_id} is registered for {non_ed25519[0]}")
                if not registered:
                    public_key = self._register_key(principal_id, "ed25519", public_key)
                elif not any(public_key == key for _algorithm, key in registered):
                    if self.store is None or not hasattr(self.store, "register_principal_key_alias"):
                        raise RuntimeError(
                            f"principal {principal_id} already has a public key, but this process "
                            "does not have the matching private key. Set "
                            "HEARTWOOD_KEY_CUSTODY_ROOT_B64 for durable multi-agent identity "
                            "or run `heartwood init-identity --help`; see "
                            "docs/security/multi-agent-identity.md."
                        )
                    public_key = self.store.register_principal_key_alias(
                        self.tenant,
                        principal_id,
                        "ed25519",
                        public_key,
                        self.key_custodian.key_id,
                    )
                self._ed25519_private[principal_id] = custody_private
                self._ed25519_public[principal_id] = public_key
                return public_key
            registered = self._get_registered_key(principal_id)
            if registered is not None and principal_id not in self._ed25519_private:
                algorithm, _public_key = registered
                if algorithm != "ed25519":
                    raise ValueError(f"principal {principal_id} is registered for {algorithm}")
                raise RuntimeError(
                    f"principal {principal_id} already has a public key, but this process "
                    "does not have the matching private key. Set "
                    "HEARTWOOD_KEY_CUSTODY_ROOT_B64 for durable multi-agent identity "
                    "or run `heartwood init-identity --help`; see "
                    "docs/security/multi-agent-identity.md."
                )
            if principal_id not in self._ed25519_private:
                private_key = ed25519.Ed25519PrivateKey.generate()
                public_key = self._public_bytes(private_key)
                self._ed25519_private[principal_id] = private_key
                self._ed25519_public[principal_id] = self._register_key(
                    principal_id,
                    "ed25519",
                    public_key,
                )
            return self._ed25519_public[principal_id]
        if principal_id not in self._hmac_keys:
            self._hmac_keys[principal_id] = secret or os.urandom(32)
            self._register_key(
                principal_id,
                "hmac-sha256",
                hashlib.sha256(self._hmac_keys[principal_id]).digest(),
            )
        return self._hmac_keys[principal_id]

    def sign(self, principal_id, mem_id, content_hash, source_uri, created_by, epistemic) -> str:
        payload = _payload(mem_id, content_hash, source_uri, created_by, epistemic)
        if _HAVE_ED25519:
            self.register(principal_id)
            private_key = self._ed25519_private[principal_id]
            public_key = self._ed25519_public[principal_id]
            sig = private_key.sign(payload)
            return f"ed25519:{_b64e(public_key)}:{_b64e(sig)}"
        key = self.register(principal_id)
        mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return "hmac-sha256:" + mac

    def verify(self, sig, principal_id, mem_id, content_hash, source_uri, created_by, epistemic) -> bool:
        if not sig:
            return False
        payload = _payload(mem_id, content_hash, source_uri, created_by, epistemic)
        if sig.startswith("ed25519:") and _HAVE_ED25519:
            try:
                _, public_text, sig_text = sig.split(":", 2)
                public_bytes = _b64d(public_text)
                signature = _b64d(sig_text)
                registered = self._get_registered_keys(principal_id)
                if not registered:
                    return False
                if not any(
                    algorithm == "ed25519" and registered_public == public_bytes
                    for algorithm, registered_public in registered
                ):
                    return False
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
                public_key.verify(signature, payload)
                return True
            except Exception:
                return False
        if sig.startswith("hmac-sha256:"):
            key = self._hmac_keys.get(principal_id)
            if key is None:
                return False
            mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(sig, "hmac-sha256:" + mac)
        return False

    def sign_detached(self, principal_id: str, payload: bytes, *, domain: bytes) -> str:
        """Sign canonical artifact bytes under an explicit domain separator."""
        signed_payload = _domain_payload(payload, domain)
        if _HAVE_ED25519:
            self.register(principal_id)
            private_key = self._ed25519_private[principal_id]
            public_key = self._ed25519_public[principal_id]
            sig = private_key.sign(signed_payload)
            return f"ed25519:{_b64e(public_key)}:{_b64e(sig)}"
        key = self.register(principal_id)
        mac = hmac.new(key, signed_payload, hashlib.sha256).hexdigest()
        return "hmac-sha256:" + mac

    def verify_detached(
        self,
        sig: str,
        principal_id: str,
        payload: bytes,
        *,
        domain: bytes,
    ) -> bool:
        """Verify canonical artifact bytes against the registered trust root."""
        if not sig:
            return False
        signed_payload = _domain_payload(payload, domain)
        if sig.startswith("ed25519:") and _HAVE_ED25519:
            try:
                _, public_text, sig_text = sig.split(":", 2)
                public_bytes = _b64d(public_text)
                signature = _b64d(sig_text)
                registered = self._get_registered_keys(principal_id)
                if not any(
                    algorithm == "ed25519" and registered_public == public_bytes
                    for algorithm, registered_public in registered
                ):
                    return False
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
                public_key.verify(signature, signed_payload)
                return True
            except Exception:
                return False
        if sig.startswith("hmac-sha256:"):
            key = self._hmac_keys.get(principal_id)
            if key is None:
                return False
            mac = hmac.new(key, signed_payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(sig, "hmac-sha256:" + mac)
        return False


def _domain_payload(payload: bytes, domain: bytes) -> bytes:
    if not isinstance(payload, bytes) or not isinstance(domain, bytes) or not domain:
        raise TypeError("detached signing requires non-empty bytes payload and domain")
    return domain + payload


def verify_meta(signer: Signer, row: dict, content: str | None = None) -> bool:
    content_hash = row.get("content_hash")
    if not content_hash:
        return False
    if content is not None:
        from .envelope import hash_content

        if hash_content(content) != content_hash:
            return False
    return signer.verify(
        row.get("producer_sig"),
        row.get("created_by"),
        row.get("id"),
        content_hash,
        row.get("source", {}).get("uri"),
        row.get("created_by"),
        row.get("epistemic"),
    )


def chain(store, mem_id: str, signer: Signer | None = None, _depth=0, _seen=None) -> dict:
    """Walk the derivation DAG to originating sources. Returns a provenance tree."""
    _seen = _seen if _seen is not None else set()
    if mem_id in _seen or _depth > 16:
        return {"id": mem_id, "cycle_or_depth_cut": True}
    _seen.add(mem_id)
    row = store.get_meta(mem_id)
    if not row:
        return {"id": mem_id, "missing": True}
    parents = store.parents(mem_id)
    signature_valid = verify_meta(signer, row) if signer is not None else False
    return {
        "id": mem_id,
        "epistemic": row["epistemic"],
        "source": row.get("source"),
        "model_version": row.get("model_version"),
        "signature_valid": signature_valid,
        "derived_from": [chain(store, p, signer, _depth + 1, _seen) for p in parents],
    }
