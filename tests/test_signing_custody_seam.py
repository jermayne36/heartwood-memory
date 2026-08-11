"""Contract tests for durable signing through the public custody seam."""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pytest

from heartwood import (
    AnchorConfigurationError,
    KeyCustodian,
    LocalFileAnchorSink,
    LocalKmsCustodian,
    RawKeyCustodian,
    StrictConfigurationError,
    StrictMode,
    anchor_root_fingerprint,
)
from heartwood.anchors import AnchorWriter
from heartwood.audit import AuditLog
from heartwood.provenance import Signer
from heartwood.store import Store
from heartwood.strict import (
    require_durable_strict_custody,
    sign_strict_cutover_manifest,
    verify_strict_cutover_manifest_signature,
)


ROOT = bytes([61]) * 32
KEY_ID = "signing-seam-root-v1"
CHAIN_ID = "chain_" + "1" * 32


class SeamCustodian(KeyCustodian):
    """Non-local custodian proving consumers dispatch through the capability."""

    name = "synthetic-external"

    def __init__(self):
        super().__init__()
        self.key_id = KEY_ID
        self.delegate = LocalKmsCustodian(ROOT, key_id=self.key_id)

    def wrap(self, *, tenant: str, subject: str, dek: bytes) -> bytes:
        return self.delegate.wrap(tenant=tenant, subject=subject, dek=dek)

    def unwrap(self, *, tenant: str, subject: str, envelope: bytes) -> bytes:
        return self.delegate.unwrap(
            tenant=tenant,
            subject=subject,
            envelope=envelope,
        )

    def ed25519_signer(self, *, salt: bytes, info: bytes):
        return self.delegate.ed25519_signer(salt=salt, info=info)


def _unsigned_manifest() -> dict:
    return {
        "domain": "heartwood.strict-cutover.v1",
        "schema_version": 1,
        "manifest_id": "sct_" + "2" * 24,
        "chain_id": CHAIN_ID,
        "producer": "agent:seam-test",
    }


def test_local_signing_derivation_remains_byte_compatible():
    custodian = LocalKmsCustodian(ROOT, key_id=KEY_ID)
    salt = b"heartwood:audit-anchor:v1"
    info = f"chain:{CHAIN_ID}:sink:test-sink:key:{KEY_ID}".encode("utf-8")
    signer = custodian.ed25519_signer(salt=salt, info=info)

    legacy_seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(ROOT)
    legacy_key = ed25519.Ed25519PrivateKey.from_private_bytes(legacy_seed)
    payload = b"local-behavior-regression"

    assert signer.public_key_bytes() == legacy_key.public_key().public_bytes_raw()
    assert signer.sign(payload) == legacy_key.sign(payload)


def test_non_local_custodian_drives_provenance_strict_and_anchor_signing(tmp_path):
    custodian = SeamCustodian()
    assert not isinstance(custodian, LocalKmsCustodian)

    provenance_store = Store(tmp_path / "provenance.db")
    try:
        signer = Signer(
            provenance_store,
            "tenant:seam",
            key_custodian=custodian,
        )
        signature = signer.sign(
            "agent:seam",
            "mem-seam",
            "sha256:" + "3" * 64,
            "doc://seam",
            "agent:seam",
            "observed-fact",
        )
        assert signature.startswith("ed25519:")
        assert signer.verify(
            signature,
            "agent:seam",
            "mem-seam",
            "sha256:" + "3" * 64,
            "doc://seam",
            "agent:seam",
            "observed-fact",
        )
    finally:
        provenance_store.close()

    require_durable_strict_custody(StrictMode.ENFORCE, custodian)
    manifest = sign_strict_cutover_manifest(_unsigned_manifest(), custodian)
    assert verify_strict_cutover_manifest_signature(manifest)

    anchor_store = Store(tmp_path / "anchors.db")
    sink = LocalFileAnchorSink(tmp_path / "anchors.jsonl", sink_id="seam-sink")
    try:
        fingerprint = anchor_root_fingerprint(
            custodian,
            chain_id=anchor_store.chain_id(),
            sink_id=sink.sink_id,
        )
        writer = AnchorWriter(
            store=anchor_store,
            sink=sink,
            custodian=custodian,
            trusted_root_fingerprints=fingerprint,
        )
        AuditLog(anchor_store).append(
            "store-global",
            "agent:seam-test",
            "seam_test",
            "target:seam",
            "{}",
        )
        assert writer.anchor()["ok"] is True
    finally:
        anchor_store.close()


# @positive-control(custodian-signing-capability): every public fail-closed gate
# must reject a custodian that supports DEK storage but not durable signing.
def test_non_signing_custodian_fires_every_public_custody_guard(tmp_path):
    custodian = RawKeyCustodian()
    with pytest.raises(StrictConfigurationError, match="durable Ed25519"):
        require_durable_strict_custody(StrictMode.ENFORCE, custodian)
    with pytest.raises(StrictConfigurationError, match="durable Ed25519"):
        sign_strict_cutover_manifest(_unsigned_manifest(), custodian)
    with pytest.raises(AnchorConfigurationError, match="durable Ed25519"):
        anchor_root_fingerprint(
            custodian,
            chain_id=CHAIN_ID,
            sink_id="guard-sink",
        )

    store = Store(tmp_path / "guard.db")
    sink = LocalFileAnchorSink(tmp_path / "guard.jsonl", sink_id="guard-sink")
    try:
        with pytest.raises(AnchorConfigurationError, match="durable Ed25519"):
            AnchorWriter(
                store=store,
                sink=sink,
                custodian=custodian,
                trusted_root_fingerprints="sha256:" + "0" * 64,
            )
    finally:
        store.close()
