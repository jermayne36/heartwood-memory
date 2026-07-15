"""Provenance signer regression tests.

The important release-gate property: signing secrets cannot be derived from a
public principal id, and a signature must be bound to the exact payload.
"""
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.cli import cmd_init_identity  # noqa: E402
from heartwood.provenance import Signer, _HAVE_ED25519  # noqa: E402


def _embed(texts):
    vecs = np.zeros((len(texts), 4), dtype=np.float32)
    for i, text in enumerate(texts):
        tokens = set(text.lower().split())
        vecs[i, 0] = 1.0
        vecs[i, 1] = float("budget" in tokens)
        vecs[i, 2] = float("overrun" in tokens)
        vecs[i, 3] = float("alpha" in tokens)
    return vecs


def _rerank(query, texts):
    q = set(query.lower().split())
    return np.asarray([len(q & set(text.lower().split())) for text in texts], dtype=np.float32)


def _heartwood(path: Path, tenant: str) -> Heartwood:
    return Heartwood(
        path=str(path),
        tenant=tenant,
        embedder=(_embed, "test-embedder"),
        reranker=(_rerank, "test-reranker"),
    )


def main():
    signer = Signer()
    sig = signer.sign(
        "agent:asst",
        "mem_1",
        "sha256:abc",
        "doc://source",
        "agent:asst",
        "user-stated",
    )

    assert signer.verify(
        sig,
        "agent:asst",
        "mem_1",
        "sha256:abc",
        "doc://source",
        "agent:asst",
        "user-stated",
    )
    assert not signer.verify(
        sig,
        "agent:asst",
        "mem_2",
        "sha256:abc",
        "doc://source",
        "agent:asst",
        "user-stated",
    ), "signature must be bound to memory id"

    attacker = Signer()
    forged = attacker.sign(
        "agent:asst",
        "mem_1",
        "sha256:abc",
        "doc://source",
        "agent:asst",
        "user-stated",
    )
    assert not signer.verify(
        forged,
        "agent:asst",
        "mem_1",
        "sha256:abc",
        "doc://source",
        "agent:asst",
        "user-stated",
    ), "a second signer must not recreate the same principal secret"

    empty_verifier = Signer()
    assert not empty_verifier.verify(
        sig,
        "agent:asst",
        "mem_1",
        "sha256:abc",
        "doc://source",
        "agent:asst",
        "user-stated",
    ), "unregistered principals must fail closed instead of trusting embedded pubkeys"

    if _HAVE_ED25519:
        with tempfile.TemporaryDirectory() as temp_dir:
            _assert_cross_process_forgery_rejected(Path(temp_dir) / "heartwood.db")
            _assert_registered_principal_error_is_actionable(Path(temp_dir) / "identity-error.db")
            _assert_init_identity_registers_public_principals(Path(temp_dir) / "identity-init.db")

    print("PROVENANCE SIGNER TESTS PASSED")


def _assert_cross_process_forgery_rejected(path: Path):
    tenant = "tenant:acme"
    principal = Principal(
        id="agent:reader",
        tenant=tenant,
        roles=("support",),
        clearance="internal",
    )

    db = _heartwood(path, tenant)
    mem_id = db.remember(
        "Alpha project risk is budget overrun.",
        subject="project:alpha",
        created_by="agent:asst",
        source={"uri": "doc://alpha/risk"},
    )
    out = db.recall("budget overrun", principal=principal, filters={"subject": "project:alpha"}, k=1)
    assert out["results"][0]["provenance"]["signature_valid"] is True
    db.store.close()

    db2 = _heartwood(path, tenant)
    out2 = db2.recall("budget overrun", principal=principal, filters={"subject": "project:alpha"}, k=1)
    assert out2["results"][0]["provenance"]["signature_valid"] is True, (
        "persisted public-key registry must verify signatures after restart"
    )

    meta = db2.store.get_meta(mem_id)
    forged = Signer().sign(
        "agent:asst",
        mem_id,
        meta["content_hash"],
        meta["source"].get("uri"),
        "agent:asst",
        meta["epistemic"],
    )
    db2.store.conn.execute(
        "UPDATE memories SET producer_sig=?, sig_valid=1 WHERE id=?",
        (forged, mem_id),
    )
    db2.store.conn.commit()
    db2.store.close()

    db3 = _heartwood(path, tenant)
    out3 = db3.recall("budget overrun", principal=principal, filters={"subject": "project:alpha"}, k=1)
    assert out3["results"][0]["provenance"]["signature_valid"] is False, (
        "forged signatures must be rejected even when the cached sig_valid bit claims true"
    )
    db3.store.close()


def _without_custody_env():
    old = {
        "HEARTWOOD_KEY_CUSTODY_ROOT_B64": os.environ.get("HEARTWOOD_KEY_CUSTODY_ROOT_B64"),
        "HEARTWOOD_KEY_CUSTODY_KEY_ID": os.environ.get("HEARTWOOD_KEY_CUSTODY_KEY_ID"),
    }
    os.environ.pop("HEARTWOOD_KEY_CUSTODY_ROOT_B64", None)
    os.environ.pop("HEARTWOOD_KEY_CUSTODY_KEY_ID", None)
    return old


def _restore_env(old):
    for key, value in old.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _assert_registered_principal_error_is_actionable(path: Path):
    old = _without_custody_env()
    try:
        db = _heartwood(path, "tenant:acme")
        db.remember(
            "First write registers the public key.",
            subject="subject:identity",
            created_by="agent:writer",
        )
        db.store.close()

        db2 = _heartwood(path, "tenant:acme")
        try:
            try:
                db2.remember(
                    "Second process lacks the original private key.",
                    subject="subject:identity",
                    created_by="agent:writer",
                )
                raise AssertionError("expected missing-private-key RuntimeError")
            except RuntimeError as exc:
                text = str(exc)
                assert "HEARTWOOD_KEY_CUSTODY_ROOT_B64" in text
                assert "heartwood init-identity --help" in text
                assert "docs/security/multi-agent-identity.md" in text
        finally:
            db2.store.close()
    finally:
        _restore_env(old)


def _assert_init_identity_registers_public_principals(path: Path):
    args = type(
        "Args",
        (),
        {
            "db": path,
            "tenant": "tenant:acme",
            "principal": ["agent:researcher", "agent:reviewer"],
            "key_id": "test-env-root-v1",
        },
    )()
    out = cmd_init_identity(args)
    assert out["ok"] is True
    assert out["root_export"].startswith("export HEARTWOOD_KEY_CUSTODY_ROOT_B64=")
    assert "Store this root in YOUR vault" in out["vault_notice"]
    assert [row["principal"] for row in out["registered_principals"]] == [
        "agent:researcher",
        "agent:reviewer",
    ]
    assert any("agent:researcher" in line for line in out["multi_agent_example"])

    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            "SELECT principal_id, algorithm FROM principal_keys ORDER BY principal_id"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [("agent:researcher", "ed25519"), ("agent:reviewer", "ed25519")]


if __name__ == "__main__":
    main()
