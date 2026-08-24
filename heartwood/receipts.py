"""Canonical signed recall and erasure receipts, plus offline verification.

Receipt v1 deliberately preserves the legacy producer-signature payload bytes:
``id|content_hash|str(source_uri)|created_by|epistemic``.  A typed canonical
producer payload is reserved for v2 because JSON null and the literal string
``"None"`` collide in the v1 encoding.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

RECALL_SCHEMA = "heartwood.recall-receipt.v1"
ERASURE_SCHEMA = "heartwood.erasure-receipt.v1"
RECALL_DOMAIN = b"heartwood.recall-receipt.v1\x00"
ERASURE_DOMAIN = b"heartwood.erasure-receipt.v1\x00"
MAX_RECEIPT_BYTES = 1024 * 1024

RECALL_FIELDS = {
    "schema", "receipt_id", "recall_id", "tenant", "principal_id",
    "issued_at_utc", "query_hash", "chain_id", "audit_seq",
    "audit_row_hash", "policy", "results", "principal_keys", "signing",
    "receipt_hash", "signature",
}
ERASURE_FIELDS = {
    "schema", "receipt_id", "tenant", "subject_id", "actor",
    "issued_at_utc", "erasure_initiated_at", "key_shred_requested",
    "purge_requested", "custody_backend", "custody_retention_floor_seconds",
    "payload", "key", "purge", "chain_id", "audit_seq", "audit_row_hash",
    "boundary", "signing", "receipt_hash", "signature",
}
SIGNING_FIELDS = {
    "signing_key_id", "signing_key_epoch", "sink_id", "signing_public_key",
    "verification_root_fingerprint",
}
RECALL_RESULT_FIELDS = {
    "id", "content_hash", "epistemic", "created_by", "source_uri",
    "source_ids", "producer_sig", "producer_key_fingerprint",
    "signature_valid_at_serve", "content_hash_match_at_serve",
}
PRINCIPAL_KEY_FIELDS = {
    "principal_id", "algorithm", "public_key_b64",
}

EXACT_ERASURE_BOUNDARY = (
    "This receipt and store check prove absence only for the exact tenant, "
    "`subject_id`, receipt-named memory IDs, provenance edges, and subject aliases "
    "actually represented by that identifier in the inspected SQLite copy at "
    "verification time. They do not prove semantic identification or deletion of "
    "the same person/data re-ingested under a different subject ID, an unknown alias, "
    "no subject tag, another database, a backup/snapshot, a cache, an export, a "
    "downstream system, or any later point in time."
)

EXPLAIN_BLOCKS = {
    "recall": {
        "proves": [
            "The deployment key matching the buyer's external pin signed this exact receipt.",
            "Each returned record's registered producer key signed its id, content hash, source-locator value, producer identity, and epistemic class.",
            "The caller-supplied content matches the signed content hash.",
            "The recall event and policy counts appear at the named row in the complete chain through the buyer's externally pinned anchor checkpoint.",
        ],
        "does_not_prove": [
            "That ranking or policy evaluation was correct, fair, optimal, or complete.",
            "That another record should not have been returned, or that all relevant records were returned.",
            "That a non-null source exists, is reachable, or is factually true; a null source locator is an explicitly signed null.",
            "Authorization-metadata integrity, algorithm reproducibility, tenant-wide isolation, or anything after the pinned anchor.",
            "That a compromised deployment signer or producer key behaved honestly.",
        ],
    },
    "erasure": {
        "proves": [
            "The deployment key matching the buyer's external pin signed the erasure event, and that event appears in the anchored audit chain.",
            "In the exact SQLite copy inspected, the subject's key row is tombstoned with no DEK, every receipt-named memory and provenance edge is absent, and no current primary/secondary subject or deletion-lineage row names the subject.",
            "If `root_present=false` is supplied, the current store has no raw active DEK under the existing tenant-wide predicate, conditional on the caller's assertion that the external root is absent.",
        ],
        "does_not_prove": [
            EXACT_ERASURE_BOUNDARY,
            "Byte-level overwrite of SQLite pages, WAL files, filesystem blocks, ciphertext, or plaintext residue.",
            "Legal or regulatory completion, including Article 17 compliance.",
        ],
    },
}


class ReceiptError(ValueError):
    """A structural or cryptographic receipt failure with a stable reason."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise ReceiptError("base64url_value_invalid")
    try:
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except Exception as exc:
        raise ReceiptError("base64url_value_invalid") from exc


def public_key_fingerprint(public_key: bytes) -> str:
    return sha256_prefixed(public_key)


def receipt_commitment(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in receipt.items()
        if key not in {"audit_row_hash", "receipt_hash", "signature"}
    }


def expected_receipt_hash(receipt: dict[str, Any]) -> str:
    return sha256_prefixed(canonical_bytes(receipt_commitment(receipt)))


def receipt_signable(receipt: dict[str, Any]) -> bytes:
    return canonical_bytes({key: value for key, value in receipt.items() if key != "signature"})


def load_json_strict(path: str | Path) -> dict[str, Any]:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ReceiptError("receipt_too_large")

    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ReceiptError("duplicate_json_key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=no_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ReceiptError("non_finite_json_number")
            ),
        )
    except ReceiptError:
        raise
    except Exception as exc:
        raise ReceiptError("receipt_json_invalid") from exc
    if not isinstance(value, dict):
        raise ReceiptError("receipt_must_be_object")
    return value


def signing_block(anchor_writer) -> dict[str, Any]:
    return {
        "signing_key_id": anchor_writer.custodian.key_id,
        "signing_key_epoch": anchor_writer.signing_key_epoch,
        "sink_id": anchor_writer.sink.sink_id,
        "signing_public_key": b64e(anchor_writer.signing_public_key),
        "verification_root_fingerprint": anchor_writer.root_fingerprint,
    }


def finalize_receipt(
    commitment: dict[str, Any], *, audit_row_hash: str, anchor_writer, kind: str,
) -> dict[str, Any]:
    receipt = {
        **commitment,
        "audit_row_hash": audit_row_hash,
        "receipt_hash": sha256_prefixed(canonical_bytes(commitment)),
    }
    if kind == "recall":
        signature = anchor_writer.sign_recall_receipt(receipt_signable(receipt))
    elif kind == "erasure":
        signature = anchor_writer.sign_erasure_receipt(receipt_signable(receipt))
    else:
        raise ValueError("unknown receipt kind")
    return {**receipt, "signature": signature}


def principal_key_entries(store, tenant: str, principal_ids: Iterable[str]) -> list[dict]:
    entries = []
    seen = set()
    for principal_id in sorted(set(principal_ids)):
        for row in store.get_principal_keys(tenant, principal_id):
            if row["algorithm"] != "ed25519":
                continue
            public_key = bytes(row["public_key"])
            identity = (principal_id, public_key)
            if identity in seen:
                continue
            seen.add(identity)
            entries.append({
                "principal_id": principal_id,
                "algorithm": "ed25519",
                "public_key_b64": b64e(public_key),
            })
    entries.sort(key=lambda row: (row["principal_id"], row["public_key_b64"]))
    return entries


def producer_signature_parts(signature: str) -> tuple[bytes, bytes]:
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ReceiptError("producer_signature_format_invalid")
    try:
        _algorithm, public_text, signature_text = signature.split(":", 2)
    except ValueError as exc:
        raise ReceiptError("producer_signature_format_invalid") from exc
    public_key, signature_bytes = b64d(public_text), b64d(signature_text)
    if len(public_key) != 32 or len(signature_bytes) != 64:
        raise ReceiptError("producer_signature_length_invalid")
    return public_key, signature_bytes


def producer_payload_v1(result: dict[str, Any]) -> bytes:
    # These bytes are a compatibility contract; typed canonical bytes are v2.
    return "|".join([
        result["id"], result["content_hash"], str(result["source_uri"]),
        result["created_by"], result["epistemic"],
    ]).encode("utf-8")


def _closed(value: Any, fields: set[str], reason: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReceiptError(reason)


def _validate_common(receipt: dict[str, Any], *, kind: str) -> tuple[bytes, bytes]:
    expected_fields = RECALL_FIELDS if kind == "recall" else ERASURE_FIELDS
    expected_schema = RECALL_SCHEMA if kind == "recall" else ERASURE_SCHEMA
    _closed(receipt, expected_fields, "receipt_fields_invalid")
    if receipt["schema"] != expected_schema:
        raise ReceiptError("receipt_schema_invalid")
    _closed(receipt["signing"], SIGNING_FIELDS, "signing_fields_invalid")
    signing = receipt["signing"]
    epoch = signing["signing_key_epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= 0:
        raise ReceiptError("signing_key_epoch_invalid")
    if not isinstance(signing["sink_id"], str) or not signing["sink_id"]:
        raise ReceiptError("sink_id_invalid")
    public_key, signature = b64d(signing["signing_public_key"]), b64d(receipt["signature"])
    if len(public_key) != 32 or len(signature) != 64:
        raise ReceiptError("receipt_signing_material_length_invalid")
    if public_key_fingerprint(public_key) != signing["verification_root_fingerprint"]:
        raise ReceiptError("verification_root_fingerprint_mismatch")
    if receipt["receipt_hash"] != expected_receipt_hash(receipt):
        # @fail-closed(receipt-hash)
        raise ReceiptError("receipt_hash_mismatch")
    domain = RECALL_DOMAIN if kind == "recall" else ERASURE_DOMAIN
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, domain + receipt_signable(receipt),
        )
    except InvalidSignature as exc:
        # @fail-closed(receipt-signature)
        raise ReceiptError("receipt_signature") from exc
    return public_key, signature


def _base_result(kind: str, receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    checked = {
        "root_pinned": False,
        "receipt_hash": False,
        "receipt_signature": False,
        "audit_bound": False,
        "freshness_pinned": False,
    }
    if kind == "recall":
        checked.update({"producer_signatures": False, "content_bound": False})
        checked = {
            key: checked[key] for key in (
                "root_pinned", "receipt_hash", "receipt_signature",
                "producer_signatures", "content_bound", "audit_bound",
                "freshness_pinned",
            )
        }
    return {
        "status": "FAIL", "ok": False, "first_failure": None,
        "receipt_id": receipt.get("receipt_id") if isinstance(receipt, dict) else None,
        "checked": checked,
    }


def _fail(result: dict[str, Any], reason: str, status: str = "FAIL") -> dict[str, Any]:
    return {**result, "status": status, "ok": False, "first_failure": reason}


def _check_root(result, receipt, trusted_root_fingerprints) -> dict[str, Any] | None:
    roots = {
        item.strip() for item in (trusted_root_fingerprints or ()) if item.strip()
    }
    fingerprint = receipt["signing"]["verification_root_fingerprint"]
    if not roots:
        # @fail-closed(receipt-external-root)
        return _fail(result, "external_trust_root_required", "UNTRUSTED_SELF_CONSISTENT")
    if fingerprint not in roots:
        return _fail(result, "verification_root_not_pinned")
    result["checked"]["root_pinned"] = True
    return None


def _audit_binding(
    result: dict[str, Any], receipt: dict[str, Any], *, audit_bundle: str | None,
    trusted_root_fingerprints, expected_latest_anchor_id: str | None,
    expected_detail: dict[str, Any],
) -> dict[str, Any] | None:
    if audit_bundle is None:
        return _fail(result, "audit_bundle_required", "AUDIT_UNBOUND")
    from .audit_bundle import _verify_audit_bundle_with_rows

    bundle_result, rows = _verify_audit_bundle_with_rows(
        audit_bundle,
        trusted_root_fingerprints=trusted_root_fingerprints,
        expected_latest_anchor_id=expected_latest_anchor_id,
    )
    if bundle_result.get("ok") is not True:
        status = bundle_result.get("status", "FAIL")
        mapped = "FRESHNESS_UNVERIFIED" if status == "FRESHNESS_UNVERIFIED" else status
        return _fail(result, str(bundle_result.get("first_failure")), mapped)
    row = next((item for item in rows if item.get("seq") == receipt["audit_seq"]), None)
    if row is None or row.get("row_hash") != receipt["audit_row_hash"]:
        # @fail-closed(receipt-audit-row)
        return _fail(result, "audit_binding_mismatch")
    try:
        body = json.loads(row["body"])
    except Exception:
        return _fail(result, "receipt_audit_body_invalid")
    if body.get("detail") != expected_detail:
        return _fail(result, "audit_binding_mismatch")
    result["checked"]["audit_bound"] = True
    result["checked"]["freshness_pinned"] = True
    return None


def verify_recall_receipt(
    receipt: dict[str, Any], *, trusted_root_fingerprints: Iterable[str] = (),
    results: list[dict[str, Any]] | None = None, audit_bundle: str | None = None,
    expected_latest_anchor_id: str | None = None,
) -> dict[str, Any]:
    result = _base_result("recall", receipt)
    try:
        _validate_common(receipt, kind="recall")
        result["checked"]["receipt_hash"] = True
        result["checked"]["receipt_signature"] = True
        _closed(receipt["policy"], {"strict_mode", "visible", "denied_count", "returned"}, "policy_fields_invalid")
        if not isinstance(receipt["results"], list) or not isinstance(receipt["principal_keys"], list):
            raise ReceiptError("recall_arrays_invalid")
        for item in receipt["results"]:
            _closed(item, RECALL_RESULT_FIELDS, "recall_result_fields_invalid")
        for item in receipt["principal_keys"]:
            _closed(item, PRINCIPAL_KEY_FIELDS, "principal_key_fields_invalid")
            public_key = b64d(item["public_key_b64"])
            if item["algorithm"] != "ed25519" or len(public_key) != 32:
                raise ReceiptError("principal_key_invalid")
        principal_identities = [
            (item["principal_id"], item["public_key_b64"])
            for item in receipt["principal_keys"]
        ]
        if principal_identities != sorted(set(principal_identities)):
            raise ReceiptError("principal_keys_not_sorted_unique")
        result_ids = [item["id"] for item in receipt["results"]]
        if len(result_ids) != len(set(result_ids)):
            raise ReceiptError("recall_result_ids_not_unique")
    except ReceiptError as exc:
        return _fail(result, str(exc))

    root_failure = _check_root(result, receipt, trusted_root_fingerprints)
    if root_failure:
        return root_failure

    registered = {
        (item["principal_id"], public_key_fingerprint(b64d(item["public_key_b64"]))): item
        for item in receipt["principal_keys"]
    }
    for item in receipt["results"]:
        try:
            public_key, signature = producer_signature_parts(item["producer_sig"])
            fingerprint = public_key_fingerprint(public_key)
            if fingerprint != item["producer_key_fingerprint"]:
                raise ReceiptError("producer_key_fingerprint_mismatch")
            key = registered.get((item["created_by"], fingerprint))
            if key is None or key["public_key_b64"] != b64e(public_key) or key["algorithm"] != "ed25519":
                # @fail-closed(producer-key-registration)
                raise ReceiptError("producer_key_not_registered")
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, producer_payload_v1(item),
            )
            if item["signature_valid_at_serve"] is not True:
                raise ReceiptError("serve_integrity_false")
        except InvalidSignature:
            return _fail(result, "producer_signature")
        except ReceiptError as exc:
            return _fail(result, str(exc))
    result["checked"]["producer_signatures"] = True

    if results is None:
        return _fail(result, "result_content_required", "CONTENT_UNBOUND")
    if not isinstance(results, list) or len(results) != len(receipt["results"]):
        return _fail(result, "result_set_mismatch")
    for expected, actual in zip(receipt["results"], results, strict=True):
        if not isinstance(actual, dict) or actual.get("id") != expected["id"]:
            return _fail(result, "result_order_or_id_mismatch")
        content = actual.get("content")
        if not isinstance(content, str) or sha256_prefixed(content.encode("utf-8")) != expected["content_hash"]:
            # @fail-closed(recall-content-binding)
            return _fail(result, "content_hash_mismatch")
        if expected["content_hash_match_at_serve"] is not True:
            return _fail(result, "serve_integrity_false")
    result["checked"]["content_bound"] = True

    detail = {
        "receipt_hash": receipt["receipt_hash"],
        "result_count": len(receipt["results"]),
        "strict_mode": receipt["policy"]["strict_mode"],
        "visible": receipt["policy"]["visible"],
        "denied": receipt["policy"]["denied_count"],
        "returned": receipt["policy"]["returned"],
    }
    failure = _audit_binding(
        result, receipt, audit_bundle=audit_bundle,
        trusted_root_fingerprints=trusted_root_fingerprints,
        expected_latest_anchor_id=expected_latest_anchor_id,
        expected_detail=detail,
    )
    if failure:
        return failure
    return {**result, "status": "PASS", "ok": True, "first_failure": None}


def verify_erasure_receipt(
    receipt: dict[str, Any], *, trusted_root_fingerprints: Iterable[str] = (),
    audit_bundle: str | None = None, expected_latest_anchor_id: str | None = None,
) -> dict[str, Any]:
    result = _base_result("erasure", receipt)
    try:
        _validate_common(receipt, kind="erasure")
        result["checked"]["receipt_hash"] = True
        result["checked"]["receipt_signature"] = True
        _closed(receipt["payload"], {
            "subject", "mode", "purged", "cascade", "key_shredded", "reason",
            "legal_basis", "erasure_initiated_at", "key_shred_requested",
            "purge_requested", "custody_backend", "custody_retention_floor_seconds",
        }, "erasure_payload_fields_invalid")
        _closed(receipt["key"], {"state_after", "dek_present_after", "wrapped_before"}, "erasure_key_fields_invalid")
        _closed(receipt["purge"], {"purged_memory_ids", "purged_count", "cascade_count", "index_removed"}, "erasure_purge_fields_invalid")
        if receipt["key"]["state_after"] != "shredded" or receipt["key"]["dek_present_after"] is not False:
            raise ReceiptError("erasure_key_claim_invalid")
        purged_ids = receipt["purge"]["purged_memory_ids"]
        if purged_ids != sorted(set(purged_ids)) or receipt["purge"]["purged_count"] != len(purged_ids):
            raise ReceiptError("erasure_purge_claim_invalid")
        if receipt["boundary"] != {
            "content_bytes_erased": False,
            "backups_and_snapshots": "outside receipt scope",
            "root_present_at_issue": True,
        }:
            raise ReceiptError("erasure_boundary")
        payload = receipt["payload"]
        expected_equal = {
            "subject": receipt["subject_id"], "mode": "hard",
            "purged": receipt["purge"]["purged_count"],
            "cascade": receipt["purge"]["cascade_count"], "key_shredded": True,
            "erasure_initiated_at": receipt["erasure_initiated_at"],
            "key_shred_requested": receipt["key_shred_requested"],
            "purge_requested": receipt["purge_requested"],
            "custody_backend": receipt["custody_backend"],
            "custody_retention_floor_seconds": receipt["custody_retention_floor_seconds"],
        }
        if any(payload.get(key) != value for key, value in expected_equal.items()):
            raise ReceiptError("erasure_payload_mismatch")
        if (
            receipt["key_shred_requested"] is not True
            or receipt["purge_requested"] is not True
            or receipt["purge"]["index_removed"] is not True
            or receipt["purge"]["cascade_count"] > receipt["purge"]["purged_count"]
        ):
            raise ReceiptError("erasure_claim_invalid")
    except ReceiptError as exc:
        return _fail(result, str(exc))

    root_failure = _check_root(result, receipt, trusted_root_fingerprints)
    if root_failure:
        return root_failure
    detail = {
        "receipt_hash": receipt["receipt_hash"],
        "purged_count": receipt["purge"]["purged_count"],
        "cascade_count": receipt["purge"]["cascade_count"],
        "key_state_after": receipt["key"]["state_after"],
        "dek_present_after": receipt["key"]["dek_present_after"],
    }
    failure = _audit_binding(
        result, receipt, audit_bundle=audit_bundle,
        trusted_root_fingerprints=trusted_root_fingerprints,
        expected_latest_anchor_id=expected_latest_anchor_id,
        expected_detail=detail,
    )
    if failure:
        return failure
    return {**result, "status": "PASS", "ok": True, "first_failure": None}


def verify_erasure_store(
    receipt: dict[str, Any], *, db_path: str | Path, root_present: bool | None = None,
) -> dict[str, Any]:
    checked = {
        "receipt_verified": True, "key_shredded": False,
        "purged_ids_absent": False, "provenance_edges_absent": False,
        "subject_rows_absent": False, "lineage_rows_absent": False,
        "root_absence_asserted": None, "tenant_no_raw_deks": None,
    }
    result = {
        "status": "FAIL", "ok": False, "first_failure": None,
        "receipt_id": receipt.get("receipt_id"), "checked": checked,
    }
    path = Path(db_path).resolve()
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        required = {"keys", "memories", "prov_edges", "deletion_lineage"}
        if not required.issubset(tables):
            return _fail(result, "required_store_tables_missing")
        expected_columns = {
            "keys": {"tenant", "subject", "dek", "state"},
            "memories": {"id", "tenant", "subject", "subject_ids_json"},
            "prov_edges": {"child", "parent"},
            "deletion_lineage": {"artifact_id", "tenant", "subject"},
        }
        for table, columns in expected_columns.items():
            actual = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            if not columns.issubset(actual):
                return _fail(result, "required_store_columns_missing")
        tenant, subject = receipt["tenant"], receipt["subject_id"]
        key_rows = connection.execute(
            "SELECT dek,state FROM keys WHERE tenant=? AND subject=?", (tenant, subject),
        ).fetchall()
        if len(key_rows) != 1 or key_rows[0]["state"] != "shredded" or key_rows[0]["dek"] is not None:
            # @fail-closed(erasure-key-tombstone)
            return _fail(result, "key_not_shredded")
        checked["key_shredded"] = True
        purged_ids = receipt["purge"]["purged_memory_ids"]
        if purged_ids:
            marks = ",".join("?" for _ in purged_ids)
            if connection.execute(
                f"SELECT 1 FROM memories WHERE id IN ({marks}) LIMIT 1", purged_ids,
            ).fetchone():
                return _fail(result, "receipt_named_memory_present")
            if connection.execute(
                f"SELECT 1 FROM prov_edges WHERE child IN ({marks}) OR parent IN ({marks}) LIMIT 1",
                tuple(purged_ids) + tuple(purged_ids),
            ).fetchone():
                return _fail(result, "receipt_named_provenance_edge_present")
        checked["purged_ids_absent"] = True
        checked["provenance_edges_absent"] = True
        for row in connection.execute(
            "SELECT subject,subject_ids_json FROM memories WHERE tenant=?", (tenant,),
        ):
            try:
                aliases = json.loads(row["subject_ids_json"] or "[]")
            except Exception:
                return _fail(result, "subject_alias_json_invalid")
            if row["subject"] == subject or subject in aliases:
                # @fail-closed(erasure-exact-subject)
                return _fail(result, "subject_rows_present")
        checked["subject_rows_absent"] = True
        if connection.execute(
            "SELECT 1 FROM deletion_lineage WHERE tenant=? AND subject=? LIMIT 1",
            (tenant, subject),
        ).fetchone():
            return _fail(result, "subject_lineage_present")
        if purged_ids:
            marks = ",".join("?" for _ in purged_ids)
            if connection.execute(
                f"SELECT 1 FROM deletion_lineage WHERE artifact_id IN ({marks}) LIMIT 1",
                purged_ids,
            ).fetchone():
                return _fail(result, "receipt_named_lineage_present")
        checked["lineage_rows_absent"] = True
        if root_present is False:
            from .key_lifecycle import prove_crypto_erase_store

            class ReadOnlyKeyStore:
                def iter_keys(self, requested_tenant):
                    return [
                        {
                            "tenant": requested_tenant, "subject": row["subject"],
                            "dek": bytes(row["dek"]) if row["dek"] is not None else None,
                            "state": row["state"],
                        }
                        for row in connection.execute(
                            "SELECT subject,dek,state FROM keys WHERE tenant=?",
                            (requested_tenant,),
                        )
                    ]

            proof = prove_crypto_erase_store(
                ReadOnlyKeyStore(), tenant=tenant, root_present=False,
                db_path=str(path),
            )
            if proof.content_unrecoverable is not True:
                return _fail(result, "tenant_raw_dek_present")
            checked["root_absence_asserted"] = True
            checked["tenant_no_raw_deks"] = True
        return {**result, "status": "PASS", "ok": True, "first_failure": None}
    finally:
        connection.close()


def verify_erasure_against_store(
    receipt: dict[str, Any], *, trusted_root_fingerprints: Iterable[str] = (),
    audit_bundle: str | None = None, expected_latest_anchor_id: str | None = None,
    db_path: str | Path, root_present: bool | None = None,
) -> dict[str, Any]:
    receipt_result = verify_erasure_receipt(
        receipt, trusted_root_fingerprints=trusted_root_fingerprints,
        audit_bundle=audit_bundle,
        expected_latest_anchor_id=expected_latest_anchor_id,
    )
    if receipt_result.get("ok") is not True:
        checked = {
            "receipt_verified": False, "key_shredded": False,
            "purged_ids_absent": False, "provenance_edges_absent": False,
            "subject_rows_absent": False, "lineage_rows_absent": False,
            "root_absence_asserted": None, "tenant_no_raw_deks": None,
        }
        return {
            "status": receipt_result["status"], "ok": False,
            "first_failure": receipt_result["first_failure"],
            "receipt_id": receipt_result.get("receipt_id"), "checked": checked,
        }
    return verify_erasure_store(receipt, db_path=db_path, root_present=root_present)


def _roots(values: list[str] | None) -> list[str]:
    roots = []
    for value in values or []:
        roots.extend(item.strip() for item in value.split(",") if item.strip())
    return roots


def _load_results(path: str | None) -> list[dict[str, Any]] | None:
    if path is None:
        return None
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(value, dict) and "results" in value:
        value = value["results"]
    if not isinstance(value, list):
        raise ReceiptError("results_file_must_be_array")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m heartwood.receipts")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("receipt")
    verify.add_argument("--root", action="append", default=[])
    verify.add_argument("--results")
    verify.add_argument("--audit-bundle")
    verify.add_argument("--expected-latest-anchor-id")
    verify.add_argument("--db")
    verify.add_argument("--root-present", choices=("true", "false"))
    verify.add_argument("--explain", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = load_json_strict(args.receipt)
        roots = _roots(args.root)
        if receipt.get("schema") == RECALL_SCHEMA:
            result = verify_recall_receipt(
                receipt, trusted_root_fingerprints=roots,
                results=_load_results(args.results), audit_bundle=args.audit_bundle,
                expected_latest_anchor_id=args.expected_latest_anchor_id,
            )
            kind = "recall"
        elif receipt.get("schema") == ERASURE_SCHEMA:
            result = verify_erasure_receipt(
                receipt, trusted_root_fingerprints=roots,
                audit_bundle=args.audit_bundle,
                expected_latest_anchor_id=args.expected_latest_anchor_id,
            )
            kind = "erasure"
            if result.get("ok") is True and args.db:
                root_present = None if args.root_present is None else args.root_present == "true"
                result["store"] = verify_erasure_store(
                    receipt, db_path=args.db, root_present=root_present,
                )
                if result["store"].get("ok") is not True:
                    result.update({
                        "status": "FAIL", "ok": False,
                        "first_failure": result["store"]["first_failure"],
                    })
        else:
            raise ReceiptError("receipt_schema_invalid")
        if args.explain:
            result.update(EXPLAIN_BLOCKS[kind])
    except Exception as exc:
        result = {
            "status": "FAIL", "ok": False,
            "first_failure": str(exc) if isinstance(exc, ReceiptError) else "verification_internal_error",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # The module CLI is intended for shell assertions: any recognized failure is 1.
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    sys.exit(main())
