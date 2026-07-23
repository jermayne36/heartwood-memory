"""Strict signature mode and snapshot-sealed cutover regressions."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from heartwood import (
    Heartwood,
    LocalKmsCustodian,
    Principal,
    RawKeyCustodian,
    StrictConfigurationError,
    StrictMode,
    StrictSignatureError,
)
from heartwood.cli import main as cli_main
from heartwood.envelope import hash_content
from heartwood.importers.markdown import dev_models
from heartwood.key_custody import is_wrapped_key, root_to_b64
from heartwood.strict import parse_strict_cutover_manifest
import heartwood.provenance as provenance

TENANT = "tenant:strict"
ROOT = bytes([73]) * 32


def _custodian() -> LocalKmsCustodian:
    return LocalKmsCustodian(ROOT, key_id="strict-test-root-v1")


def _db(
    path: Path,
    *,
    tenant: str = TENANT,
    custodian=None,
    mode: StrictMode | str = StrictMode.OFF,
    legacy_exemption: str = "off",
    manifest: Path | None = None,
    digest: str | None = None,
) -> Heartwood:
    embedder, reranker = dev_models()
    return Heartwood(
        path=path,
        tenant=tenant,
        embedder=embedder,
        reranker=reranker,
        key_custodian=custodian,
        strict_signatures=mode,
        strict_legacy_exemption=legacy_exemption,
        strict_cutover_path=str(manifest) if manifest else None,
        strict_cutover_digest=digest,
    )


def _principal(tenant: str = TENANT) -> Principal:
    return Principal(id="agent:reader", tenant=tenant, clearance="internal")


def _remember_hmac_legacy(
    path: Path,
    monkeypatch,
    *,
    tenant: str = TENANT,
    created_by: str = "agent:legacy",
    source_uri: str = "doc://legacy/source",
) -> str:
    with monkeypatch.context() as local:
        local.setattr(provenance, "_HAVE_ED25519", False)
        db = _db(path, tenant=tenant, custodian=RawKeyCustodian())
        try:
            return db.remember(
                "Legacy HMAC migration record with strict cutover evidence.",
                subject="subject:legacy",
                created_by=created_by,
                epistemic="imported-source",
                source={"uri": source_uri},
            )
        finally:
            db.close()


def _prepare_cutover(path: Path, manifest: Path, monkeypatch) -> tuple[str, str, dict, dict]:
    mem_id = _remember_hmac_legacy(path, monkeypatch)
    db = _db(path, custodian=_custodian())
    try:
        report = db.strict_preflight()
        assert report["buckets"]["unverifiable_hmac"] == 1
        assert report["buckets"]["valid_ed25519"] == 0
        assert report["tamper_or_error_count"] == 0
        legacy_key, _state = db.store.get_key(TENANT, "subject:legacy")
        assert not is_wrapped_key(legacy_key), "preflight must remain a read-only migration walk"
        sealed = db.seal_strict_cutover(
            approved_report_digest=report["report_digest"],
            manifest_path=str(manifest),
            operator="operator:strict-test",
            reason="test HMAC-era migration",
        )
        activated = db.activate_strict_cutover(
            manifest_path=str(manifest),
            manifest_digest=sealed["manifest_digest"],
            operator="operator:strict-test",
        )
        return mem_id, sealed["manifest_digest"], sealed, activated
    finally:
        db.close()


def test_strict_filter_and_enforce_use_live_verification_not_cached_sig_valid(tmp_path):
    path = tmp_path / "strict.db"
    db = _db(path, custodian=_custodian())
    try:
        mem_id = db.remember(
            "Strict verification rejects a forged provenance signature.",
            subject="subject:strict",
            created_by="agent:writer",
            source={"uri": "doc://strict/source"},
        )
        signature = db.store.get_meta(mem_id)["producer_sig"]
        algorithm, public_key, signature_bytes = signature.split(":", 2)
        forged_signature_bytes = (
            ("A" if signature_bytes[0] != "A" else "B") + signature_bytes[1:]
        )
        forged = f"{algorithm}:{public_key}:{forged_signature_bytes}"
        db.store.conn.execute(
            "UPDATE memories SET producer_sig=?, sig_valid=1 WHERE id=?",
            (forged, mem_id),
        )
        db.store.conn.commit()
    finally:
        db.close()

    off = _db(path, custodian=_custodian(), mode=StrictMode.OFF)
    try:
        out = off.recall("forged provenance", principal=_principal(), k=3)
        assert out["results"][0]["provenance"]["signature_valid"] is False
    finally:
        off.close()

    filtered = _db(path, custodian=_custodian(), mode=StrictMode.FILTER)
    try:
        out = filtered.recall("forged provenance", principal=_principal(), k=3)
        assert out["results"] == []
        explanation = filtered.explain_recall(out["recall_id"])
        assert explanation["strict_dropped"] == {
            "count": 1,
            "reason_buckets": {"signature_invalid": 1},
            "ids": [mem_id],
            "backfill": False,
        }
    finally:
        filtered.close()

    enforced = _db(path, custodian=_custodian(), mode=StrictMode.ENFORCE)
    try:
        with pytest.raises(StrictSignatureError) as exc:
            enforced.recall(
                "forged provenance",
                principal=_principal(),
                filters={"strict_signatures": "off"},
                k=3,
            )
        assert exc.value.ids == (mem_id,)
        assert exc.value.reason_buckets == {"signature_invalid": 1}
        assert enforced._explain == {}
    finally:
        enforced.close()


def test_manifest_seal_activation_roundtrip_and_bucket_separation(tmp_path, monkeypatch):
    path = tmp_path / "cutover.db"
    manifest = tmp_path / "strict-cutover.json"
    mem_id, digest, sealed, activated = _prepare_cutover(path, manifest, monkeypatch)

    parsed = parse_strict_cutover_manifest(manifest.read_bytes())
    assert parsed["manifest_id"] == sealed["manifest_id"]
    assert parsed["exempt_count"] == 1
    assert sealed["seal_transition"]["seq"] == (
        parsed["snapshot"]["audit_head_seq"] + 1
    )
    assert sealed["seal_transition"]["prev_hash"] == (
        parsed["snapshot"]["audit_head_hash"]
    )
    assert activated["activation_transition"]["seq"] == (
        sealed["seal_transition"]["seq"] + 1
    )
    assert activated["activation_transition"]["prev_hash"] == (
        sealed["seal_transition"]["row_hash"]
    )

    strict = _db(
        path,
        custodian=_custodian(),
        mode=StrictMode.ENFORCE,
        legacy_exemption="manifest",
        manifest=manifest,
        digest=digest,
    )
    try:
        out = strict.recall("legacy HMAC migration", principal=_principal(), k=3)
        result = out["results"][0]
        assert result["id"] == mem_id
        assert result["provenance"]["signature_valid"] is False
        assert result["strict_exempt"] == "pre_cutover"
        assert result["strict_exempt_manifest_id"] == parsed["manifest_id"]

        new_id = strict.remember(
            "Post-activation Ed25519 record remains valid after restart.",
            subject="subject:new",
            created_by="agent:new-writer",
            source={"uri": "doc://strict/new"},
        )
    finally:
        strict.close()

    restarted = _db(
        path,
        custodian=_custodian(),
        mode=StrictMode.ENFORCE,
        legacy_exemption="manifest",
        manifest=manifest,
        digest=digest,
    )
    try:
        out = restarted.recall(
            "Post-activation Ed25519",
            principal=_principal(),
            filters={"subject": "subject:new"},
            k=3,
        )
        assert [result["id"] for result in out["results"]] == [new_id]
        assert "strict_exempt" not in out["results"][0]
        assert "strict_exempt_manifest_id" not in out["results"][0]

        key = restarted.keys.get(TENANT, "subject:legacy")
        tampered = "Tampered pre-cutover content must not be grandfathered."
        restarted.store.conn.execute(
            "UPDATE memories SET content_enc=?, content_hash=?, sig_valid=1 WHERE id=?",
            (
                restarted.cipher.encrypt(tampered, key),
                hash_content(tampered),
                mem_id,
            ),
        )
        restarted.store.conn.commit()
        restarted._text_cache.clear()
        restarted._token_cache.clear()
        restarted._bm25_corpus_cache.clear()
        with pytest.raises(StrictSignatureError) as exc:
            restarted.recall(
                "Tampered pre-cutover",
                principal=_principal(),
                filters={"subject": "subject:legacy"},
                k=3,
            )
        assert exc.value.ids == (mem_id,)
    finally:
        restarted.close()


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("source_json", json.dumps({"uri": "doc://changed/source"})),
        ("created_by", "agent:changed"),
        ("epistemic", "observed-fact"),
        ("producer_sig", "hmac-sha256:" + ("0" * 64)),
        ("id", "mem_changed_after_cutover"),
    ],
)
def test_manifest_binds_every_mutable_signed_payload_field(
    tmp_path,
    monkeypatch,
    column,
    value,
):
    path = tmp_path / f"{column}.db"
    manifest = tmp_path / f"{column}.json"
    _mem_id, digest, _sealed, _activated = _prepare_cutover(path, manifest, monkeypatch)

    conn_db = _db(path, custodian=_custodian())
    try:
        conn_db.store.conn.execute(
            f"UPDATE memories SET {column}=?",
            (value,),
        )
        conn_db.store.conn.commit()
    finally:
        conn_db.close()

    strict = _db(
        path,
        custodian=_custodian(),
        mode=StrictMode.ENFORCE,
        legacy_exemption="manifest",
        manifest=manifest,
        digest=digest,
    )
    try:
        with pytest.raises(StrictSignatureError):
            strict.recall("legacy HMAC migration", principal=_principal(), k=3)
    finally:
        strict.close()


def test_manifest_payload_identity_is_not_vulnerable_to_pipe_boundary_shift(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "pipe-boundary.db"
    manifest = tmp_path / "pipe-boundary.json"
    _remember_hmac_legacy(
        path,
        monkeypatch,
        created_by="agent|legacy",
        source_uri="doc://legacy",
    )
    db = _db(path, custodian=_custodian())
    try:
        report = db.strict_preflight()
        sealed = db.seal_strict_cutover(
            approved_report_digest=report["report_digest"],
            manifest_path=str(manifest),
            operator="operator:strict-test",
        )
        db.activate_strict_cutover(
            manifest_path=str(manifest),
            manifest_digest=sealed["manifest_digest"],
            operator="operator:strict-test",
        )
        db.store.conn.execute(
            "UPDATE memories SET source_json=?, created_by=?",
            (json.dumps({"uri": "doc://legacy|agent"}), "legacy"),
        )
        db.store.conn.commit()
    finally:
        db.close()

    strict = _db(
        path,
        custodian=_custodian(),
        mode=StrictMode.ENFORCE,
        legacy_exemption="manifest",
        manifest=manifest,
        digest=sealed["manifest_digest"],
    )
    try:
        with pytest.raises(StrictSignatureError):
            strict.recall("legacy HMAC migration", principal=_principal(), k=3)
    finally:
        strict.close()


def test_preflight_refuses_algorithm_downgrade_even_when_cached_bit_is_true(tmp_path):
    path = tmp_path / "downgrade.db"
    manifest = tmp_path / "downgrade.json"
    db = _db(path, custodian=_custodian())
    try:
        db.remember(
            "Downgraded signatures are not trust-import candidates.",
            subject="subject:downgrade",
            created_by="agent:writer",
        )
        db.store.conn.execute(
            "UPDATE memories SET producer_sig=?, sig_valid=1",
            ("hmac-sha256:" + ("a" * 64),),
        )
        db.store.conn.commit()
        report = db.strict_preflight()
        assert report["buckets"]["algorithm_downgrade"] == 1
        assert report["trust_import_candidates"] == []
        assert report["tamper_or_error_count"] == 1
        with pytest.raises(StrictConfigurationError, match="tamper/integrity/error"):
            db.seal_strict_cutover(
                approved_report_digest=report["report_digest"],
                manifest_path=str(manifest),
                operator="operator:test",
            )
    finally:
        db.close()


def test_seal_reconciles_the_approved_report_under_write_lock(tmp_path, monkeypatch):
    path = tmp_path / "race.db"
    manifest = tmp_path / "race.json"
    _remember_hmac_legacy(path, monkeypatch)
    db = _db(path, custodian=_custodian())
    try:
        report = db.strict_preflight()
        db.remember(
            "Intervening record invalidates the approved snapshot.",
            subject="subject:race",
            created_by="agent:new-writer",
        )
        with pytest.raises(StrictConfigurationError, match="changed after approval"):
            db.seal_strict_cutover(
                approved_report_digest=report["report_digest"],
                manifest_path=str(manifest),
                operator="operator:test",
            )
    finally:
        db.close()
    assert not manifest.exists()


def test_activation_refuses_an_intervening_write_after_seal(tmp_path, monkeypatch):
    path = tmp_path / "activation-race.db"
    manifest = tmp_path / "activation-race.json"
    _remember_hmac_legacy(path, monkeypatch)
    db = _db(path, custodian=_custodian())
    try:
        report = db.strict_preflight()
        sealed = db.seal_strict_cutover(
            approved_report_digest=report["report_digest"],
            manifest_path=str(manifest),
            operator="operator:test",
        )
        db.remember(
            "A write after sealing invalidates activation of that snapshot.",
            subject="subject:activation-race",
            created_by="agent:new-writer",
        )
        with pytest.raises(
            StrictConfigurationError,
            match="audit head advanced after sealing",
        ):
            db.activate_strict_cutover(
                manifest_path=str(manifest),
                manifest_digest=sealed["manifest_digest"],
                operator="operator:test",
            )
    finally:
        db.close()

    with pytest.raises(StrictConfigurationError, match="not activated"):
        _db(
            path,
            custodian=_custodian(),
            mode=StrictMode.ENFORCE,
            legacy_exemption="manifest",
            manifest=manifest,
            digest=sealed["manifest_digest"],
        )


def test_manifest_mode_fails_closed_on_missing_invalid_or_changed_artifact(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "fail-closed.db"
    manifest = tmp_path / "fail-closed.json"
    _mem_id, digest, _sealed, _activated = _prepare_cutover(path, manifest, monkeypatch)

    with pytest.raises(StrictConfigurationError, match="digest"):
        _db(
            path,
            custodian=_custodian(),
            mode=StrictMode.ENFORCE,
            legacy_exemption="manifest",
            manifest=manifest,
            digest="sha256:" + ("0" * 64),
        )
    with pytest.raises(StrictConfigurationError, match="unavailable"):
        _db(
            path,
            custodian=_custodian(),
            mode=StrictMode.ENFORCE,
            legacy_exemption="manifest",
            manifest=tmp_path / "missing.json",
            digest=digest,
        )

    strict = _db(
        path,
        custodian=_custodian(),
        mode=StrictMode.FILTER,
        legacy_exemption="manifest",
        manifest=manifest,
        digest=digest,
    )
    try:
        manifest.write_bytes(manifest.read_bytes() + b"\n")
        with pytest.raises(StrictConfigurationError, match="digest"):
            strict.recall("legacy HMAC migration", principal=_principal(), k=3)
    finally:
        strict.close()


def test_manifest_parser_rejects_duplicate_keys_and_duplicate_ids(tmp_path, monkeypatch):
    with pytest.raises(StrictConfigurationError, match="malformed"):
        parse_strict_cutover_manifest(b'{"domain":"a","domain":"b"}\n')

    path = tmp_path / "schema.db"
    manifest_path = tmp_path / "schema.json"
    _mem_id, _digest, _sealed, _activated = _prepare_cutover(
        path,
        manifest_path,
        monkeypatch,
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["exempt"].append(dict(manifest["exempt"][0]))
    manifest["exempt_count"] = 2
    canonical = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8") + b"\n"
    with pytest.raises(StrictConfigurationError, match="duplicate ids"):
        parse_strict_cutover_manifest(canonical)


def test_strict_preflight_cli_emits_terminal_bucket_report(
    tmp_path,
    monkeypatch,
    capsys,
):
    path = tmp_path / "cli.db"
    _remember_hmac_legacy(path, monkeypatch)
    monkeypatch.setenv("HEARTWOOD_KEY_CUSTODY_ROOT_B64", root_to_b64(ROOT))
    monkeypatch.setenv("HEARTWOOD_KEY_CUSTODY_KEY_ID", "strict-test-root-v1")
    cli_main(
        [
            "strict-preflight",
            "--db",
            str(path),
            "--tenant",
            TENANT,
            "--dev-models",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert output["domain"] == "heartwood.strict-preflight-report.v1"
    assert output["buckets"]["unverifiable_hmac"] == 1
    assert output["snapshot"]["row_count_total"] == sum(output["buckets"].values())
    assert output["report_digest"].startswith("sha256:")
    assert "unverifiable operator trust-import candidates" in output["candidate_taxonomy"]


def test_strict_configuration_propagates_to_tenant_reopens(tmp_path):
    path = tmp_path / "tenant-propagation.db"
    db = _db(path, custodian=_custodian(), mode=StrictMode.ENFORCE)
    tenant_client = db.with_tenant("tenant:other")
    try:
        assert tenant_client._strict_mode is StrictMode.ENFORCE
        assert tenant_client._strict_legacy_exemption == "off"
    finally:
        tenant_client.close()
        db.close()


def test_strict_mode_requires_durable_custody(tmp_path):
    with pytest.raises(StrictConfigurationError, match="durable Ed25519"):
        _db(
            tmp_path / "no-custody.db",
            custodian=RawKeyCustodian(),
            mode=StrictMode.ENFORCE,
        )


def test_strict_mode_env_resolves_once_and_constructor_remains_authoritative(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("HEARTWOOD_STRICT_SIGNATURES", "filter")
    embedder, reranker = dev_models()
    from_env = Heartwood(
        path=tmp_path / "from-env.db",
        tenant=TENANT,
        embedder=embedder,
        reranker=reranker,
        key_custodian=_custodian(),
    )
    explicit = Heartwood(
        path=tmp_path / "explicit.db",
        tenant=TENANT,
        embedder=embedder,
        reranker=reranker,
        key_custodian=_custodian(),
        strict_signatures=StrictMode.OFF,
    )
    try:
        assert from_env._strict_mode is StrictMode.FILTER
        assert explicit._strict_mode is StrictMode.OFF
    finally:
        from_env.close()
        explicit.close()
