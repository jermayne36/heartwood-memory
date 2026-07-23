"""Strict provenance enforcement and snapshot-sealed legacy cutover support."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import tempfile
from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .audit import AuditLog
from .envelope import hash_content
from .key_custody import LocalKmsCustodian, is_wrapped_key
from .provenance import Signer, verify_meta

_REPORT_DOMAIN = "heartwood.strict-preflight-report.v1"
_MANIFEST_DOMAIN = "heartwood.strict-cutover.v1"
_MANIFEST_SIGNATURE_DOMAIN = b"heartwood.strict-cutover.signature.v1\x00"
_PAYLOAD_IDENTITY_DOMAIN = b"heartwood.memory-provenance-payload.v1\x00"
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_VALID_BUCKET = "valid_ed25519"
_CANDIDATE_BUCKETS = {
    "unverifiable_hmac",
    "unverifiable_missing_key",
}
_FAILURE_BUCKETS = {
    "algorithm_downgrade",
    "bad_signature",
    "content_hash_mismatch",
    "decrypt_failure",
    "malformed_row",
}


class StrictMode(str, Enum):
    OFF = "off"
    FILTER = "filter"
    ENFORCE = "enforce"


class StrictConfigurationError(RuntimeError):
    """Strict mode cannot safely start with the supplied store/configuration."""


class StrictSignatureError(RuntimeError):
    """One or more otherwise-returnable records failed strict verification."""

    def __init__(self, failures: list[dict[str, str]]):
        self.failures = tuple(dict(item) for item in failures)
        self.ids = tuple(item["id"] for item in failures)
        self.reason_buckets = dict(Counter(item["reason"] for item in failures))
        reasons = ", ".join(
            f"{reason}={count}" for reason, count in sorted(self.reason_buckets.items())
        )
        super().__init__(
            f"strict signature enforcement rejected {len(failures)} returned "
            f"record(s): {reasons}"
        )


def resolve_strict_mode(value: StrictMode | str | None) -> StrictMode:
    raw = os.environ.get("HEARTWOOD_STRICT_SIGNATURES", StrictMode.OFF.value)
    if value is not None:
        raw = value.value if isinstance(value, StrictMode) else str(value)
    try:
        return StrictMode(raw.strip().lower())
    except ValueError as exc:
        raise StrictConfigurationError(
            "HEARTWOOD_STRICT_SIGNATURES must be one of: off, filter, enforce"
        ) from exc


def resolve_legacy_exemption(value: str | None) -> str:
    raw = (
        str(value)
        if value is not None
        else os.environ.get("HEARTWOOD_STRICT_LEGACY_EXEMPTION", "off")
    )
    normalized = raw.strip().lower()
    if normalized not in {"off", "manifest"}:
        raise StrictConfigurationError(
            "HEARTWOOD_STRICT_LEGACY_EXEMPTION must be one of: off, manifest"
        )
    return normalized


def require_durable_strict_custody(mode: StrictMode, custodian: Any) -> None:
    if mode is StrictMode.OFF:
        return
    if not isinstance(custodian, LocalKmsCustodian):
        raise StrictConfigurationError(
            "strict signature mode requires durable Ed25519 identity custody; "
            "set HEARTWOOD_KEY_CUSTODY_ROOT_B64 and HEARTWOOD_KEY_CUSTODY_KEY_ID "
            "before enabling FILTER or ENFORCE"
        )


def provenance_payload_hash(
    mem_id: str,
    content_hash_value: str,
    source_uri: str | None,
    created_by: str,
    epistemic: str,
) -> str:
    """Length-safe identity for every field in the current signed payload."""
    payload = _canonical_bytes(
        [mem_id, content_hash_value, source_uri, created_by, epistemic]
    )
    digest = hashlib.sha256(_PAYLOAD_IDENTITY_DOMAIN + payload).hexdigest()
    return "sha256:" + digest


def signature_fingerprint(signature: str) -> str:
    """Fingerprint the exact UTF-8 bytes of the stored signature string."""
    return "sha256:" + hashlib.sha256(signature.encode("utf-8")).hexdigest()


def strict_failure_reason(
    *,
    content_hash_match: bool,
    content_signature_valid: bool,
) -> str:
    if content_hash_match is not True:
        return "content_hash_mismatch"
    if content_signature_valid is not True:
        return "signature_invalid"
    raise ValueError("strict_failure_reason requires an invalid integrity result")


class StrictCutoverResolver:
    """Pinned, activated cutover allowlist used only after live verification fails."""

    def __init__(
        self,
        store,
        path: str | Path,
        expected_digest: str | None,
        *,
        anchor_writer=None,
    ):
        self.store = store
        self.path = Path(path)
        self.expected_digest = (
            _validated_digest(expected_digest) if expected_digest is not None else None
        )
        self.anchor_writer = anchor_writer
        self.manifest: dict[str, Any] = {}
        self.by_id: dict[str, dict[str, str]] = {}
        self._file_identity: tuple[int, int, int, int] | None = None
        self._reload()

    @property
    def manifest_id(self) -> str:
        return str(self.manifest["manifest_id"])

    def match(
        self,
        *,
        meta: dict,
        actual_content_hash: str,
    ) -> bool:
        self._ensure_current()
        entry = self.by_id.get(str(meta.get("id")))
        if entry is None or entry["tenant"] != meta.get("tenant"):
            return False
        signature = meta.get("producer_sig")
        created_by = meta.get("created_by")
        epistemic = meta.get("epistemic")
        source_uri = (meta.get("source") or {}).get("uri")
        if not all(isinstance(value, str) for value in (signature, created_by, epistemic)):
            return False
        return (
            actual_content_hash == entry["content_hash"]
            and provenance_payload_hash(
                str(meta["id"]),
                actual_content_hash,
                source_uri,
                created_by,
                epistemic,
            )
            == entry["signed_payload_hash"]
            and signature_fingerprint(signature) == entry["signature_fingerprint"]
        )

    def _ensure_current(self) -> None:
        try:
            stat = self.path.stat()
        except OSError as exc:
            raise StrictConfigurationError(
                "strict cutover manifest became unavailable; refusing legacy exemptions"
            ) from exc
        identity = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
        if identity != self._file_identity:
            self._reload()

    def _reload(self) -> None:
        raw, identity = _read_once(self.path)
        actual_digest = _digest_bytes(raw)
        if self.anchor_writer is None:
            expected_digest = self.expected_digest
            if expected_digest is not None and actual_digest != expected_digest:
                raise StrictConfigurationError(
                    "strict cutover manifest digest does not match its trusted pin"
                )
            manifest = parse_strict_cutover_manifest(raw)
        else:
            manifest = parse_strict_cutover_manifest(raw)
            expected_digest = self.anchor_writer.resolve_manifest_digest(
                manifest["manifest_id"]
            )
        if expected_digest is None:
            raise StrictConfigurationError(
                "strict cutover manifest has no AnchorSink or operator-config digest pin"
            )
        if actual_digest != expected_digest:
            raise StrictConfigurationError(
                "strict cutover manifest digest does not match its trusted pin"
            )
        if not verify_strict_cutover_manifest_signature(manifest):
            raise StrictConfigurationError("strict cutover manifest signature is invalid")
        _validate_manifest_activation(self.store, manifest, actual_digest)
        self.manifest = manifest
        self.by_id = {entry["id"]: entry for entry in manifest["exempt"]}
        self._file_identity = identity


class StrictCutoverManager:
    """Preflight, seal, and activate a store-global strict cutover."""

    def __init__(self, *, store, key_store, cipher, anchor_writer=None):
        self.store = store
        self.key_store = key_store
        self.cipher = cipher
        self.anchor_writer = anchor_writer

    def preflight(self) -> dict[str, Any]:
        try:
            self.store.conn.execute("BEGIN")
            report = self._scan_current()
            self.store.conn.commit()
        except Exception:
            self.store.conn.rollback()
            raise
        return _public_report(report)

    def seal(
        self,
        *,
        approved_report_digest: str,
        manifest_path: str | Path,
        operator: str,
        reason: str,
    ) -> dict[str, Any]:
        _require_operator(operator)
        approved_digest = _validated_digest(approved_report_digest)
        custodian = self.key_store.custodian
        require_durable_strict_custody(StrictMode.ENFORCE, custodian)
        path = Path(manifest_path)
        if path.exists():
            raise StrictConfigurationError(
                f"strict cutover artifact already exists: {path}"
            )

        staged_path: Path | None = None
        committed = False
        try:
            self.store.conn.execute("BEGIN IMMEDIATE")
            report = self._scan_current()
            if report["report_digest"] != approved_digest:
                raise StrictConfigurationError(
                    "strict preflight changed after approval; rerun and approve the new report digest"
                )
            if report["tamper_or_error_count"]:
                raise StrictConfigurationError(
                    "strict cutover sealing refused because preflight contains "
                    "tamper/integrity/error buckets"
                )
            if report["chain_ok"] is not True:
                raise StrictConfigurationError(
                    "strict cutover sealing refused because the audit chain is invalid"
                )

            manifest_id = "sct_" + secrets.token_hex(12)
            unsigned = {
                "domain": _MANIFEST_DOMAIN,
                "schema_version": 1,
                "manifest_id": manifest_id,
                "chain_id": report["chain_id"],
                "tenant_scope": "store-global",
                "snapshot": {
                    **report["snapshot"],
                    "candidate_report_digest": report["report_digest"],
                },
                "sealed_at_utc": datetime.now(timezone.utc).isoformat(),
                "reason": str(reason),
                "producer": operator,
                "exempt": list(report["trust_import_candidates"]),
                "exempt_count": len(report["trust_import_candidates"]),
            }
            manifest = sign_strict_cutover_manifest(unsigned, custodian)
            raw = _canonical_bytes(manifest) + b"\n"
            manifest_digest = _digest_bytes(raw)
            staged_path = _stage_artifact(path, raw)

            detail = {
                "manifest_id": manifest_id,
                "manifest_digest": manifest_digest,
                "candidate_report_digest": report["report_digest"],
                "pre_seal_head_seq": report["snapshot"]["audit_head_seq"],
                "pre_seal_head_hash": report["snapshot"]["audit_head_hash"],
                "row_count_total": report["snapshot"]["row_count_total"],
            }
            transition = self.store.append_audit_in_transaction(
                "store-global",
                operator,
                "strict_cutover_sealed",
                manifest_id,
                _audit_body(
                    "store-global",
                    operator,
                    "strict_cutover_sealed",
                    manifest_id,
                    detail,
                ),
            )
            expected_seq = report["snapshot"]["audit_head_seq"] + 1
            if (
                transition["seq"] != expected_seq
                or transition["prev_hash"] != report["snapshot"]["audit_head_hash"]
            ):
                raise RuntimeError("strict cutover seal transition did not extend the snapshot head")
            self.store.conn.commit()
            committed = True

            _publish_staged_artifact(staged_path, path)
            staged_path = None
            readback, _identity = _read_once(path)
            if readback != raw or _digest_bytes(readback) != manifest_digest:
                raise RuntimeError("strict cutover artifact failed read-back verification")
            pin_receipt = (
                self.anchor_writer.pin_manifest(manifest_id, manifest_digest)
                if self.anchor_writer is not None
                else {
                    "pin_source": "operator_config",
                    "manifest_id": manifest_id,
                    "manifest_digest": manifest_digest,
                }
            )
            anchor_receipt = (
                self.anchor_writer.anchor()
                if self.anchor_writer is not None
                else None
            )
            return {
                "ok": True,
                "status": "sealed_not_active",
                "manifest_id": manifest_id,
                "manifest_path": str(path),
                "manifest_digest": manifest_digest,
                "candidate_report_digest": report["report_digest"],
                "exempt_count": manifest["exempt_count"],
                "seal_transition": transition,
                "pin": pin_receipt,
                "anchor": anchor_receipt,
            }
        except Exception:
            if self.store.conn.in_transaction:
                self.store.conn.rollback()
            if staged_path is not None and not committed:
                staged_path.unlink(missing_ok=True)
            raise

    def activate(
        self,
        *,
        manifest_path: str | Path,
        manifest_digest: str | None,
        operator: str,
    ) -> dict[str, Any]:
        _require_operator(operator)
        require_durable_strict_custody(
            StrictMode.ENFORCE,
            self.key_store.custodian,
        )
        raw, _identity = _read_once(Path(manifest_path))
        manifest = parse_strict_cutover_manifest(raw)
        expected_digest = (
            self.anchor_writer.resolve_manifest_digest(manifest["manifest_id"])
            if self.anchor_writer is not None
            else _validated_digest(manifest_digest or "")
        )
        if _digest_bytes(raw) != expected_digest:
            raise StrictConfigurationError(
                "strict cutover manifest digest does not match its trusted pin"
            )
        if not verify_strict_cutover_manifest_signature(manifest):
            raise StrictConfigurationError("strict cutover manifest signature is invalid")

        try:
            self.store.conn.execute("BEGIN IMMEDIATE")
            transitions = _validate_manifest_seal(
                self.store,
                manifest,
                expected_digest,
            )
            existing_activation = transitions.get("activation")
            if existing_activation is not None:
                self.store.conn.commit()
                result = {
                    "ok": True,
                    "status": "already_active",
                    "manifest_id": manifest["manifest_id"],
                    "manifest_digest": expected_digest,
                    "seal_transition": transitions["seal"],
                    "activation_transition": existing_activation,
                }
                if self.anchor_writer is not None:
                    result["anchor"] = self.anchor_writer.anchor()
                    result["pin_source"] = "anchor_sink"
                else:
                    result["pin_source"] = "operator_config"
                return result

            seal = transitions["seal"]
            if self.store.audit_head() != {
                "seq": seal["seq"],
                "row_hash": seal["row_hash"],
                "prev_hash": seal["prev_hash"],
            }:
                raise StrictConfigurationError(
                    "strict cutover activation refused because the audit head advanced after sealing"
                )
            if self.store.memory_count() != manifest["snapshot"]["row_count_total"]:
                raise StrictConfigurationError(
                    "strict cutover activation refused because the memory row count changed"
                )

            detail = {
                "manifest_id": manifest["manifest_id"],
                "manifest_digest": expected_digest,
                "seal_seq": seal["seq"],
                "seal_row_hash": seal["row_hash"],
                "seal_prev_hash": seal["prev_hash"],
            }
            activation = self.store.append_audit_in_transaction(
                "store-global",
                operator,
                "strict_cutover_activated",
                manifest["manifest_id"],
                _audit_body(
                    "store-global",
                    operator,
                    "strict_cutover_activated",
                    manifest["manifest_id"],
                    detail,
                ),
            )
            if (
                activation["seq"] != seal["seq"] + 1
                or activation["prev_hash"] != seal["row_hash"]
            ):
                raise RuntimeError(
                    "strict cutover activation did not extend the exact seal transition"
                )
            self.store.conn.commit()
            result = {
                "ok": True,
                "status": "active",
                "manifest_id": manifest["manifest_id"],
                "manifest_digest": expected_digest,
                "seal_transition": seal,
                "activation_transition": activation,
            }
            if self.anchor_writer is not None:
                result["anchor"] = self.anchor_writer.anchor()
                result["pin_source"] = "anchor_sink"
            else:
                result["pin_source"] = "operator_config"
            return result
        except Exception:
            self.store.conn.rollback()
            raise

    def _scan_current(self) -> dict[str, Any]:
        if not self.store.conn.in_transaction:
            raise RuntimeError("strict preflight scan requires a consistent SQLite transaction")
        chain_id = self.store.chain_id()
        head = self.store.audit_head()
        rows = self.store.conn.execute("SELECT * FROM memories ORDER BY id").fetchall()
        records = [self._classify_row(row) for row in rows]
        buckets = Counter(record["reason"] for record in records)
        for bucket in {_VALID_BUCKET, *_CANDIDATE_BUCKETS, *_FAILURE_BUCKETS}:
            buckets.setdefault(bucket, 0)
        if len(records) != sum(buckets.values()):
            raise RuntimeError("strict preflight terminal buckets do not reconcile")
        candidates = [
            {
                "id": record["id"],
                "tenant": record["tenant"],
                "reason": record["reason"],
                "content_hash": record["content_hash"],
                "signed_payload_hash": record["signed_payload_hash"],
                "signature_fingerprint": record["signature_fingerprint"],
            }
            for record in records
            if record["reason"] in _CANDIDATE_BUCKETS
        ]
        candidates.sort(key=lambda item: (item["tenant"], item["id"]))
        anchor_status = (
            self.anchor_writer.verify()
            if self.anchor_writer is not None
            else {"ok": False, "anchor_status": "not_configured"}
        )
        stable_anchor_status = {
            key: anchor_status.get(key)
            for key in (
                "ok",
                "anchor_status",
                "chain_ok",
                "anchors_ok",
                "anchor_fresh",
                "sink_healthy",
                "last_success_seq",
                "current_seq",
                "rows_since_success",
                "anchor_due",
                "first_failure",
                "last_sanitized_error_class",
            )
            if key in anchor_status
        }
        body = {
            "domain": _REPORT_DOMAIN,
            "schema_version": 1,
            "chain_id": chain_id,
            "snapshot": {
                "audit_head_seq": head["seq"],
                "audit_head_hash": head["row_hash"],
                "audit_head_prev_hash": head["prev_hash"],
                "row_count_total": len(records),
            },
            "buckets": dict(sorted(buckets.items())),
            "records": records,
            "trust_import_candidates": candidates,
            "chain_ok": AuditLog(self.store).verify_chain(),
            "anchor_status": stable_anchor_status,
            "prior_deletion_completeness": "not_established_without_earlier_external_anchor",
        }
        report_digest = _digest_bytes(_canonical_bytes(body))
        return {
            **body,
            "report_digest": report_digest,
            "tamper_or_error_count": sum(
                count for bucket, count in buckets.items() if bucket in _FAILURE_BUCKETS
            ),
        }

    def _classify_row(self, row) -> dict[str, Any]:
        base = {
            "id": str(row["id"]) if row["id"] is not None else "",
            "tenant": str(row["tenant"]) if row["tenant"] is not None else "",
            "reason": "malformed_row",
            "content_hash": None,
            "signed_payload_hash": None,
            "signature_fingerprint": None,
        }
        try:
            mem_id = row["id"]
            tenant = row["tenant"]
            created_by = row["created_by"]
            epistemic = row["epistemic"]
            stored_content_hash = row["content_hash"]
            signature = row["producer_sig"]
            subject = row["subject"]
            source = _strict_json_object(row["source_json"] or "{}")
            source_uri = source.get("uri")
            if not all(
                isinstance(value, str) and value
                for value in (
                    mem_id,
                    tenant,
                    created_by,
                    epistemic,
                    stored_content_hash,
                    signature,
                    subject,
                )
            ):
                return base
            if source_uri is not None and not isinstance(source_uri, str):
                return base

            try:
                envelope, state = self.store.get_key(tenant, subject)
                if state == "shredded" or envelope is None:
                    raise ValueError("memory key unavailable")
                key = (
                    self.key_store.custodian.unwrap(
                        tenant=tenant,
                        subject=subject,
                        envelope=envelope,
                    )
                    if is_wrapped_key(envelope)
                    else bytes(envelope)
                )
                content = self.cipher.decrypt(row["content_enc"], key)
            except Exception:
                return {**base, "id": mem_id, "tenant": tenant, "reason": "decrypt_failure"}
            actual_content_hash = hash_content(content)
            identity = {
                "id": mem_id,
                "tenant": tenant,
                "content_hash": actual_content_hash,
                "signed_payload_hash": provenance_payload_hash(
                    mem_id,
                    actual_content_hash,
                    source_uri,
                    created_by,
                    epistemic,
                ),
                "signature_fingerprint": signature_fingerprint(signature),
            }
            if actual_content_hash != stored_content_hash:
                return {**identity, "reason": "content_hash_mismatch"}

            registered = self.store.get_principal_keys(tenant, created_by)
            algorithms = {item["algorithm"] for item in registered}
            if signature.startswith("hmac-sha256:"):
                reason = (
                    "algorithm_downgrade"
                    if "ed25519" in algorithms and "hmac-sha256" not in algorithms
                    else "unverifiable_hmac"
                )
                return {**identity, "reason": reason}
            if not signature.startswith("ed25519:"):
                return {**identity, "reason": "malformed_row"}
            if "ed25519" not in algorithms:
                return {**identity, "reason": "unverifiable_missing_key"}

            meta = {
                "id": mem_id,
                "tenant": tenant,
                "content_hash": stored_content_hash,
                "source": source,
                "created_by": created_by,
                "epistemic": epistemic,
                "producer_sig": signature,
            }
            signer = Signer(
                self.store,
                tenant,
                key_custodian=self.key_store.custodian,
            )
            reason = _VALID_BUCKET if verify_meta(signer, meta, content) else "bad_signature"
            return {**identity, "reason": reason}
        except Exception:
            return base


def sign_strict_cutover_manifest(
    unsigned_manifest: dict[str, Any],
    custodian: LocalKmsCustodian,
) -> dict[str, Any]:
    """Dedicated Ed25519 signature over the canonical strict-manifest body."""
    if not isinstance(custodian, LocalKmsCustodian):
        raise StrictConfigurationError(
            "strict cutover manifests require durable Ed25519 custody"
        )
    chain_id = str(unsigned_manifest.get("chain_id") or "")
    producer = str(unsigned_manifest.get("producer") or "")
    private_key = _strict_manifest_private_key(custodian, chain_id, producer)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    body = {
        **unsigned_manifest,
        "signing": {
            "algorithm": "ed25519",
            "key_id": custodian.key_id,
            "public_key": _b64e(public_key),
        },
    }
    digest = hashlib.sha256(_canonical_bytes(body)).digest()
    signature = private_key.sign(_MANIFEST_SIGNATURE_DOMAIN + digest)
    return {**body, "signature": _b64e(signature)}


def verify_strict_cutover_manifest_signature(manifest: dict[str, Any]) -> bool:
    try:
        signature = _b64d(manifest["signature"])
        public_key = _b64d(manifest["signing"]["public_key"])
        body = {key: value for key, value in manifest.items() if key != "signature"}
        digest = hashlib.sha256(_canonical_bytes(body)).digest()
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            _MANIFEST_SIGNATURE_DOMAIN + digest,
        )
        return True
    except Exception:
        return False


def parse_strict_cutover_manifest(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > _MAX_MANIFEST_BYTES:
        raise StrictConfigurationError("strict cutover manifest is empty or over the size limit")
    try:
        manifest = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise StrictConfigurationError("strict cutover manifest is malformed") from exc
    if not isinstance(manifest, dict):
        raise StrictConfigurationError("strict cutover manifest root must be an object")
    if raw != _canonical_bytes(manifest) + b"\n":
        raise StrictConfigurationError(
            "strict cutover manifest must use the canonical JSON encoding"
        )
    _require_exact_keys(
        manifest,
        {
            "domain",
            "schema_version",
            "manifest_id",
            "chain_id",
            "tenant_scope",
            "snapshot",
            "sealed_at_utc",
            "reason",
            "producer",
            "exempt",
            "exempt_count",
            "signing",
            "signature",
        },
        "manifest",
    )
    if manifest["domain"] != _MANIFEST_DOMAIN or manifest["schema_version"] != 1:
        raise StrictConfigurationError("strict cutover manifest domain/version is unsupported")
    for key in ("manifest_id", "chain_id", "sealed_at_utc", "reason", "producer", "signature"):
        if not isinstance(manifest[key], str):
            raise StrictConfigurationError(f"strict cutover manifest {key} must be a string")
    if not re.fullmatch(r"sct_[0-9a-f]{24}", manifest["manifest_id"]):
        raise StrictConfigurationError("strict cutover manifest id is invalid")
    if not re.fullmatch(r"chain_[0-9a-f]{32}", manifest["chain_id"]):
        raise StrictConfigurationError("strict cutover chain id is invalid")
    if manifest["tenant_scope"] != "store-global":
        raise StrictConfigurationError("strict cutover manifest tenant_scope must be store-global")

    snapshot = manifest["snapshot"]
    if not isinstance(snapshot, dict):
        raise StrictConfigurationError("strict cutover manifest snapshot must be an object")
    _require_exact_keys(
        snapshot,
        {
            "audit_head_seq",
            "audit_head_hash",
            "audit_head_prev_hash",
            "row_count_total",
            "candidate_report_digest",
        },
        "snapshot",
    )
    for key in ("audit_head_seq", "row_count_total"):
        if not _is_nonnegative_int(snapshot[key]):
            raise StrictConfigurationError(f"strict cutover snapshot {key} is invalid")
    if not isinstance(snapshot["audit_head_hash"], str):
        raise StrictConfigurationError("strict cutover snapshot audit_head_hash is invalid")
    if snapshot["audit_head_prev_hash"] is not None and not isinstance(
        snapshot["audit_head_prev_hash"], str
    ):
        raise StrictConfigurationError("strict cutover snapshot audit_head_prev_hash is invalid")
    _validated_digest(snapshot["candidate_report_digest"])

    signing = manifest["signing"]
    if not isinstance(signing, dict):
        raise StrictConfigurationError("strict cutover signing must be an object")
    _require_exact_keys(signing, {"algorithm", "key_id", "public_key"}, "signing")
    if signing["algorithm"] != "ed25519":
        raise StrictConfigurationError("strict cutover signing algorithm must be ed25519")
    if not all(isinstance(signing[key], str) and signing[key] for key in ("key_id", "public_key")):
        raise StrictConfigurationError("strict cutover signing fields are invalid")
    try:
        if len(_b64d(signing["public_key"])) != 32 or len(_b64d(manifest["signature"])) != 64:
            raise ValueError
    except Exception as exc:
        raise StrictConfigurationError("strict cutover signature encoding is invalid") from exc

    exempt = manifest["exempt"]
    if not isinstance(exempt, list):
        raise StrictConfigurationError("strict cutover exempt must be an array")
    if not _is_nonnegative_int(manifest["exempt_count"]):
        raise StrictConfigurationError("strict cutover exempt_count is invalid")
    if manifest["exempt_count"] != len(exempt):
        raise StrictConfigurationError("strict cutover exempt_count does not match entries")
    seen_ids = set()
    expected_order = []
    for entry in exempt:
        if not isinstance(entry, dict):
            raise StrictConfigurationError("strict cutover exempt entry must be an object")
        _require_exact_keys(
            entry,
            {
                "id",
                "tenant",
                "reason",
                "content_hash",
                "signed_payload_hash",
                "signature_fingerprint",
            },
            "exempt entry",
        )
        if not all(isinstance(entry[key], str) and entry[key] for key in entry):
            raise StrictConfigurationError("strict cutover exempt entry fields must be strings")
        if entry["reason"] not in _CANDIDATE_BUCKETS:
            raise StrictConfigurationError("strict cutover entry has a non-candidate reason")
        for key in ("content_hash", "signed_payload_hash", "signature_fingerprint"):
            _validated_digest(entry[key])
        if entry["id"] in seen_ids:
            raise StrictConfigurationError("strict cutover manifest contains duplicate ids")
        seen_ids.add(entry["id"])
        expected_order.append((entry["tenant"], entry["id"]))
    if expected_order != sorted(expected_order):
        raise StrictConfigurationError("strict cutover exempt entries must be canonically sorted")
    return manifest


def _validate_manifest_activation(store, manifest: dict, manifest_digest: str) -> None:
    transitions = _validate_manifest_seal(store, manifest, manifest_digest)
    if transitions.get("activation") is None:
        raise StrictConfigurationError(
            "strict cutover manifest is sealed but not activated"
        )


def _validate_manifest_seal(
    store,
    manifest: dict,
    manifest_digest: str,
) -> dict[str, dict | None]:
    if store.chain_id() != manifest["chain_id"]:
        raise StrictConfigurationError("strict cutover manifest belongs to another store")
    if not AuditLog(store).verify_chain():
        raise StrictConfigurationError("strict cutover audit chain is invalid")
    rows = store.audit_rows_for_target(manifest["manifest_id"])
    seals = [row for row in rows if row["action"] == "strict_cutover_sealed"]
    activations = [row for row in rows if row["action"] == "strict_cutover_activated"]
    if len(seals) != 1 or len(activations) > 1:
        raise StrictConfigurationError("strict cutover transition rows are missing or ambiguous")
    seal = seals[0]
    if seal["tenant"] != "store-global" or seal["principal"] != manifest["producer"]:
        raise StrictConfigurationError(
            "strict cutover seal attribution does not match the manifest"
        )
    snapshot = manifest["snapshot"]
    if (
        seal["seq"] != snapshot["audit_head_seq"] + 1
        or seal["prev_hash"] != snapshot["audit_head_hash"]
    ):
        raise StrictConfigurationError(
            "strict cutover seal does not extend the exact pre-seal head"
        )
    if snapshot["audit_head_seq"]:
        pre_seal = store.audit_row(snapshot["audit_head_seq"])
        if pre_seal is None or (
            pre_seal["row_hash"] != snapshot["audit_head_hash"]
            or pre_seal["prev_hash"] != snapshot["audit_head_prev_hash"]
        ):
            raise StrictConfigurationError("strict cutover pre-seal head tuple is invalid")
    elif (
        snapshot["audit_head_hash"] != "genesis"
        or snapshot["audit_head_prev_hash"] is not None
    ):
        raise StrictConfigurationError("strict cutover genesis snapshot is invalid")
    _validate_audit_hash(seal)
    seal_detail = _audit_detail(seal)
    expected_seal_detail = {
        "manifest_id": manifest["manifest_id"],
        "manifest_digest": manifest_digest,
        "candidate_report_digest": snapshot["candidate_report_digest"],
        "pre_seal_head_seq": snapshot["audit_head_seq"],
        "pre_seal_head_hash": snapshot["audit_head_hash"],
        "row_count_total": snapshot["row_count_total"],
    }
    if seal_detail != expected_seal_detail:
        raise StrictConfigurationError("strict cutover seal detail does not bind the manifest")

    activation = activations[0] if activations else None
    if activation is not None:
        if activation["tenant"] != "store-global":
            raise StrictConfigurationError(
                "strict cutover activation must use the store-global audit scope"
            )
        if (
            activation["seq"] != seal["seq"] + 1
            or activation["prev_hash"] != seal["row_hash"]
        ):
            raise StrictConfigurationError(
                "strict cutover activation does not extend the exact seal head"
            )
        _validate_audit_hash(activation)
        expected_activation_detail = {
            "manifest_id": manifest["manifest_id"],
            "manifest_digest": manifest_digest,
            "seal_seq": seal["seq"],
            "seal_row_hash": seal["row_hash"],
            "seal_prev_hash": seal["prev_hash"],
        }
        if _audit_detail(activation) != expected_activation_detail:
            raise StrictConfigurationError(
                "strict cutover activation detail does not bind the seal transition"
            )
    return {"seal": seal, "activation": activation}


def _validate_audit_hash(row: dict) -> None:
    expected = hashlib.sha256(
        (row["prev_hash"] + row["body"] + repr(row["ts"])).encode()
    ).hexdigest()
    if expected != row["row_hash"]:
        raise StrictConfigurationError("strict cutover audit transition hash is invalid")


def _audit_detail(row: dict) -> dict:
    try:
        body = json.loads(
            row["body"],
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise StrictConfigurationError("strict cutover audit body is malformed") from exc
    if not isinstance(body, dict):
        raise StrictConfigurationError("strict cutover audit body must be an object")
    _require_exact_keys(
        body,
        {"tenant", "principal", "action", "target", "detail"},
        "audit body",
    )
    if (
        body["tenant"] != row["tenant"]
        or body["principal"] != row["principal"]
        or body["action"] != row["action"]
        or body["target"] != row["target"]
        or not isinstance(body["detail"], dict)
    ):
        raise StrictConfigurationError(
            "strict cutover audit columns do not match the hash-bound body"
        )
    if row["body"] != _canonical_bytes(body).decode("utf-8"):
        raise StrictConfigurationError("strict cutover audit body is not canonical")
    return body["detail"]


def _strict_manifest_private_key(
    custodian: LocalKmsCustodian,
    chain_id: str,
    producer: str,
):
    seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"heartwood:strict-cutover-manifest:v1",
        info=(
            f"chain:{chain_id}:producer:{producer}:key:{custodian.key_id}"
        ).encode("utf-8"),
    ).derive(custodian.root_key)
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def _public_report(report: dict[str, Any]) -> dict[str, Any]:
    return {
        **report,
        "reported_at_utc": datetime.now(timezone.utc).isoformat(),
        "candidate_taxonomy": (
            "HMAC and missing-key rows are unverifiable operator trust-import "
            "candidates, not cryptographically verified legacy records."
        ),
    }


def _audit_body(tenant: str, principal: str, action: str, target: str, detail: dict) -> str:
    return _canonical_bytes(
        {
            "tenant": tenant,
            "principal": principal,
            "action": action,
            "target": target,
            "detail": detail,
        }
    ).decode("utf-8")


def _stage_artifact(path: Path, raw: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    staged = Path(name)
    try:
        os.chmod(staged, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        return staged
    except Exception:
        staged.unlink(missing_ok=True)
        raise


def _publish_staged_artifact(staged: Path, path: Path) -> None:
    os.link(staged, path)
    staged.unlink()
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _read_once(path: Path) -> tuple[bytes, tuple[int, int, int, int]]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_MANIFEST_BYTES + 1)
            stat = os.fstat(handle.fileno())
    except OSError as exc:
        raise StrictConfigurationError(
            f"strict cutover manifest is unavailable: {path}"
        ) from exc
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise StrictConfigurationError("strict cutover manifest exceeds the size limit")
    return raw, (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _strict_json_object(raw: str) -> dict:
    value = json.loads(
        raw,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validated_digest(value: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise StrictConfigurationError("expected one canonical sha256:<hex> digest")
    return value


def _require_exact_keys(value: dict, expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        unknown = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise StrictConfigurationError(
            f"strict cutover {label} fields mismatch; unknown={unknown}, missing={missing}"
        )


def _reject_duplicate_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str):
    raise ValueError(f"non-finite JSON number: {value}")


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _require_operator(operator: str) -> None:
    if not isinstance(operator, str) or not operator.strip():
        raise StrictConfigurationError("strict cutover operator must be a non-empty string")


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)
