"""Portable, offline-verifiable exports of Heartwood's signed audit chain.

The bundle is a read-only snapshot of the store-global audit chain through its
latest signed anchor. It intentionally excludes memories, encryption keys, and
derived indexes. A future WORM/SIEM sink can retain or forward the exact bundle
bytes without changing the verification contract defined here.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .anchors import LocalFileAnchorSink, verify_chain_against_anchors

_SCHEMA = "heartwood.audit-bundle.v1"
_MEMBERS = ("manifest.json", "audit.jsonl", "anchors.jsonl")
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_DATA_MEMBER_BYTES = 1024 * 1024 * 1024


class AuditBundleError(RuntimeError):
    """An audit bundle could not be exported or verified safely."""


class _BundleSink:
    def __init__(self, sink_id: str, records: list[dict[str, Any]]):
        self._sink_id = sink_id
        self._records = records

    @property
    def sink_id(self) -> str:
        return self._sink_id

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        raise AuditBundleError("offline bundle sink is read-only")

    def read_records(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._records]


class _BundleStore:
    def __init__(
        self,
        *,
        chain_id: str,
        rows: list[dict[str, Any]],
        sink_id: str,
        sink_head: str,
    ):
        self._chain_id = chain_id
        self._rows = rows
        self._by_seq = {int(row["seq"]): row for row in rows}
        self._sink_id = sink_id
        self._sink_head = sink_head

    def chain_id(self) -> str:
        return self._chain_id

    def iter_audit(self):
        yield from self._rows

    def audit_row(self, seq: int) -> dict[str, Any] | None:
        return self._by_seq.get(int(seq))

    def audit_head_snapshot(self) -> dict[str, Any]:
        if not self._rows:
            return {"seq": 0, "row_hash": "genesis", "prev_hash": None, "ts": None}
        row = self._rows[-1]
        return {
            "seq": int(row["seq"]),
            "row_hash": row["row_hash"],
            "prev_hash": row["prev_hash"],
            "ts": float(row["ts"]),
        }

    def anchor_sink_head(self, sink_id: str) -> str | None:
        return self._sink_head if sink_id == self._sink_id else None


def export_audit_bundle(
    *,
    db_path: str | Path,
    anchors_path: str | Path,
    out_path: str | Path,
    trusted_root_fingerprints: str | Iterable[str],
    anchor_sink_id: str | None = None,
) -> dict[str, Any]:
    """Export the fully anchored audit prefix without mutating source state."""
    db_path = Path(db_path)
    out_path = Path(out_path)
    sink = LocalFileAnchorSink(anchors_path, sink_id=anchor_sink_id)
    roots = _root_list(trusted_root_fingerprints)
    if not roots:
        raise AuditBundleError("at least one trusted anchor root fingerprint is required")

    records = sink.read_records()
    anchors = [record for record in records if record.get("record_type") == "audit_anchor"]
    if not anchors:
        raise AuditBundleError("anchor sink contains no audit anchors")
    try:
        export_through_seq = max(int(record["seq"]) for record in anchors)
    except (KeyError, TypeError, ValueError) as exc:
        raise AuditBundleError("anchor sink contains an invalid audit sequence") from exc

    connection = _open_read_only(db_path)
    try:
        connection.execute("BEGIN")
        chain_id = _metadata(connection, "chain_id")
        sink_head_key = "anchor_sink_head:" + hashlib.sha256(
            sink.sink_id.encode("utf-8")
        ).hexdigest()
        sink_head = _metadata(connection, sink_head_key)
        current_head = connection.execute(
            "SELECT seq FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        current_seq = int(current_head["seq"]) if current_head is not None else 0
        rows = [
            _audit_row(row)
            for row in connection.execute(
                "SELECT * FROM audit_log WHERE seq <= ? ORDER BY seq",
                (export_through_seq,),
            )
        ]
        connection.rollback()
    finally:
        connection.close()

    store = _BundleStore(
        chain_id=chain_id,
        rows=rows,
        sink_id=sink.sink_id,
        sink_head=sink_head,
    )
    source_receipt = verify_chain_against_anchors(
        store,
        _BundleSink(sink.sink_id, records),
        trusted_root_fingerprints=roots,
    )
    if source_receipt.get("ok") is not True:
        raise AuditBundleError(
            "source snapshot is not a closed signed chain: "
            + str(source_receipt.get("first_failure") or "verification_failed")
        )

    audit_bytes = _jsonl_bytes(rows)
    anchor_bytes = _jsonl_bytes(records)
    latest_anchor = max(anchors, key=lambda record: int(record["seq"]))
    manifest = {
        "schema": _SCHEMA,
        "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "chain": {
            "chain_id": chain_id,
            "first_seq": int(rows[0]["seq"]),
            "last_seq": int(rows[-1]["seq"]),
            "row_count": len(rows),
            "first_prev_hash": rows[0]["prev_hash"],
            "last_row_hash": rows[-1]["row_hash"],
            "source_current_seq": current_seq,
            "excluded_unanchored_rows": current_seq - int(rows[-1]["seq"]),
        },
        "anchors": {
            "sink_id": sink.sink_id,
            "sink_head_digest": sink_head,
            "records_count": len(records),
            "latest_anchor_id": latest_anchor["anchor_id"],
            "latest_anchor_seq": int(latest_anchor["seq"]),
            "trusted_root_fingerprints": roots,
        },
        "files": {
            "audit.jsonl": _file_receipt(audit_bytes),
            "anchors.jsonl": _file_receipt(anchor_bytes),
        },
        "semantics": {
            "scope": "store-global audit chain through the latest signed anchor",
            "source_mutation": False,
            "memory_content_included": False,
            "encryption_keys_included": False,
            "retention_contract": "immutable self-contained snapshot; lifecycle is operator-managed",
        },
    }
    manifest_bytes = _canonical_bytes(manifest) + b"\n"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _write_archive_atomic(
        out_path,
        {
            "manifest.json": manifest_bytes,
            "audit.jsonl": audit_bytes,
            "anchors.jsonl": anchor_bytes,
        },
    )
    return {
        "status": "PASS",
        "ok": True,
        "bundle": str(out_path),
        "chain_range": f"{rows[0]['seq']}-{rows[-1]['seq']}",
        "row_count": len(rows),
        "anchor_fingerprints": roots,
        "latest_anchor_id": latest_anchor["anchor_id"],
        "latest_anchor_seq": int(latest_anchor["seq"]),
        "excluded_unanchored_rows": manifest["chain"]["excluded_unanchored_rows"],
        "source_mutated": False,
    }


def verify_audit_bundle(
    bundle_path: str | Path,
    *,
    trusted_root_fingerprints: str | Iterable[str] | None = None,
    expected_latest_anchor_id: str | None = None,
) -> dict[str, Any]:
    """Verify a bundle from local bytes against external trust and freshness pins."""
    try:
        members = _read_archive(Path(bundle_path))
        manifest = _load_canonical_json(members["manifest.json"], "manifest.json")
        if manifest.get("schema") != _SCHEMA:
            raise AuditBundleError("unsupported audit bundle schema")
        for name in ("audit.jsonl", "anchors.jsonl"):
            expected = manifest.get("files", {}).get(name)
            if not isinstance(expected, dict):
                raise AuditBundleError(f"manifest is missing {name} receipt")
            actual = _file_receipt(members[name])
            if actual != expected:
                raise AuditBundleError(f"{name} checksum or size mismatch")

        rows = _parse_jsonl(members["audit.jsonl"], "audit.jsonl")
        records = _parse_jsonl(members["anchors.jsonl"], "anchors.jsonl")
        chain = manifest.get("chain")
        anchors = manifest.get("anchors")
        if not isinstance(chain, dict) or not isinstance(anchors, dict) or not rows:
            raise AuditBundleError("manifest chain or anchor metadata is invalid")
        _validate_manifest_range(chain, rows)
        external_roots = _root_list(trusted_root_fingerprints or ())
        roots = external_roots or _root_list(
            anchors.get("trusted_root_fingerprints", ())
        )
        if not roots:
            raise AuditBundleError("no trusted anchor root fingerprint was supplied")

        store = _BundleStore(
            chain_id=str(chain["chain_id"]),
            rows=rows,
            sink_id=str(anchors["sink_id"]),
            sink_head=str(anchors["sink_head_digest"]),
        )
        receipt = verify_chain_against_anchors(
            store,
            _BundleSink(str(anchors["sink_id"]), records),
            trusted_root_fingerprints=roots,
        )
        if receipt.get("ok") is not True:
            raise AuditBundleError(
                str(receipt.get("first_failure") or "signed_chain_verification_failed")
            )
        checked = sorted(
            {
                str(record["verification_root_fingerprint"])
                for record in records
                if record.get("record_type") == "audit_anchor"
            }
        )
        latest_anchor_id = receipt["last_success_anchor_id"]
        if not external_roots:
            # @fail-closed(audit-bundle-external-trust)
            return {
                "status": "UNTRUSTED_SELF_CONSISTENT",
                "ok": False,
                "chain_id": chain["chain_id"],
                "chain_range": f"{chain['first_seq']}-{chain['last_seq']}",
                "row_count": chain["row_count"],
                "anchors_checked": receipt["anchors_checked"],
                "anchor_fingerprints": checked,
                "trust_source": "bundle_manifest",
                "latest_anchor_id": latest_anchor_id,
                "first_failure": "external_trust_root_required",
            }
        if expected_latest_anchor_id is None:
            # @fail-closed(audit-bundle-checkpoint)
            return {
                "status": "FRESHNESS_UNVERIFIED",
                "ok": False,
                "chain_id": chain["chain_id"],
                "chain_range": f"{chain['first_seq']}-{chain['last_seq']}",
                "row_count": chain["row_count"],
                "anchors_checked": receipt["anchors_checked"],
                "anchor_fingerprints": checked,
                "trust_source": "external",
                "latest_anchor_id": latest_anchor_id,
                "first_failure": "external_latest_anchor_checkpoint_required",
            }
        if latest_anchor_id != expected_latest_anchor_id:
            return {
                "status": "FAIL",
                "ok": False,
                "chain_id": chain["chain_id"],
                "chain_range": f"{chain['first_seq']}-{chain['last_seq']}",
                "row_count": chain["row_count"],
                "anchors_checked": receipt["anchors_checked"],
                "anchor_fingerprints": checked,
                "trust_source": "external",
                "latest_anchor_id": latest_anchor_id,
                "first_failure": "expected_latest_anchor_checkpoint_mismatch",
            }
        return {
            "status": "PASS",
            "ok": True,
            "chain_id": chain["chain_id"],
            "chain_range": f"{chain['first_seq']}-{chain['last_seq']}",
            "row_count": chain["row_count"],
            "anchors_checked": receipt["anchors_checked"],
            "anchor_fingerprints": checked,
            "trust_source": "external",
            "latest_anchor_id": latest_anchor_id,
            "freshness_source": "external_latest_anchor_checkpoint",
        }
    except Exception as exc:
        # @fail-closed(audit-bundle-verification)
        return {
            "status": "FAIL",
            "ok": False,
            "first_failure": "bundle_verification_failed",
            "error_class": type(exc).__name__,
        }


def _open_read_only(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise AuditBundleError(f"audit database does not exist: {path}")
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _metadata(connection: sqlite3.Connection, key: str) -> str:
    row = connection.execute(
        "SELECT value FROM store_metadata WHERE key=?", (key,)
    ).fetchone()
    if row is None or not isinstance(row["value"], str) or not row["value"]:
        raise AuditBundleError(f"required audit metadata is missing: {key}")
    return row["value"]


def _audit_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "seq": int(row["seq"]),
        "ts": row["ts"],
        "tenant": row["tenant"],
        "principal": row["principal"],
        "action": row["action"],
        "target": row["target"],
        "body": row["body"],
        "prev_hash": row["prev_hash"],
        "row_hash": row["row_hash"],
    }


def _root_list(value: str | Iterable[str]) -> list[str]:
    raw = value.split(",") if isinstance(value, str) else list(value)
    return sorted({str(item).strip().lower() for item in raw if str(item).strip()})


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _jsonl_bytes(values: list[dict[str, Any]]) -> bytes:
    return b"".join(_canonical_bytes(value) + b"\n" for value in values)


def _file_receipt(data: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _write_archive_atomic(path: Path, members: dict[str, bytes]) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with temp_path.open("wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    for name in _MEMBERS:
                        data = members[name]
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        info.mode = 0o644
                        info.mtime = 0
                        archive.addfile(info, io.BytesIO(data))
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def _read_archive(path: Path) -> dict[str, bytes]:
    if not path.is_file():
        raise AuditBundleError("audit bundle does not exist")
    found: dict[str, bytes] = {}
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive.getmembers():
            if member.name not in _MEMBERS or member.name in found or not member.isfile():
                raise AuditBundleError("bundle contains an unexpected or duplicate member")
            limit = (
                _MAX_MANIFEST_BYTES
                if member.name == "manifest.json"
                else _MAX_DATA_MEMBER_BYTES
            )
            if member.size < 0 or member.size > limit:
                raise AuditBundleError("bundle member exceeds the verification size limit")
            stream = archive.extractfile(member)
            if stream is None:
                raise AuditBundleError("bundle member could not be read")
            data = stream.read(limit + 1)
            if len(data) != member.size:
                raise AuditBundleError("bundle member size does not match its header")
            found[member.name] = data
    if set(found) != set(_MEMBERS):
        raise AuditBundleError("bundle is missing a required member")
    return found


def _load_canonical_json(data: bytes, name: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditBundleError(f"{name} is not valid JSON") from exc
    if not isinstance(value, dict) or data != _canonical_bytes(value) + b"\n":
        raise AuditBundleError(f"{name} is not canonical JSON")
    return value


def _parse_jsonl(data: bytes, name: str) -> list[dict[str, Any]]:
    if not data or not data.endswith(b"\n"):
        raise AuditBundleError(f"{name} must be non-empty canonical JSONL")
    values = []
    for line in data.splitlines():
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditBundleError(f"{name} contains invalid JSON") from exc
        if not isinstance(value, dict) or line != _canonical_bytes(value):
            raise AuditBundleError(f"{name} contains non-canonical JSON")
        values.append(value)
    return values


def _validate_manifest_range(chain: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    expected_sequences = list(range(1, len(rows) + 1))
    actual_sequences = [int(row["seq"]) for row in rows]
    if actual_sequences != expected_sequences:
        raise AuditBundleError("audit rows must be a complete contiguous chain from sequence 1")
    expected = {
        "first_seq": actual_sequences[0],
        "last_seq": actual_sequences[-1],
        "row_count": len(rows),
        "first_prev_hash": rows[0]["prev_hash"],
        "last_row_hash": rows[-1]["row_hash"],
    }
    if any(chain.get(key) != value for key, value in expected.items()):
        raise AuditBundleError("manifest chain range does not match audit.jsonl")
    if rows[0]["prev_hash"] != "genesis":
        raise AuditBundleError("audit bundle does not start at genesis")
