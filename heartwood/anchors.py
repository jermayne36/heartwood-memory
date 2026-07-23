"""Signed, out-of-database anchors for Heartwood's store-global audit chain.

The local-file sink is an out-of-database anchor. It is not an independent
timestamp and is not a separate failure domain unless the operator places and
protects it that way. Anchoring detects truncation at or below a persisted
anchor; rows written after the latest anchor remain the open detection window.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .audit import AuditLog
from .key_custody import LocalKmsCustodian

_ANCHOR_DOMAIN = "heartwood.audit-anchor.v1"
_MANIFEST_PIN_DOMAIN = "heartwood.strict-cutover-pin.v1"
_ANCHOR_SIGNATURE_DOMAIN = b"heartwood.audit-anchor.signature.v1\x00"
_MANIFEST_PIN_SIGNATURE_DOMAIN = b"heartwood.strict-cutover-pin.signature.v1\x00"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHAIN_ID_RE = re.compile(r"^chain_[0-9a-f]{32}$")
_ANCHOR_ID_RE = re.compile(r"^anc_[0-9a-f]{24}$")
_PIN_ID_RE = re.compile(r"^pin_[0-9a-f]{24}$")
_MANIFEST_ID_RE = re.compile(r"^sct_[0-9a-f]{24}$")
_DEFAULT_INTERVAL_S = 300.0
_DEFAULT_EVERY_N_ROWS = 1000


class AnchorError(RuntimeError):
    """Base class for anchor configuration, persistence, and verification errors."""


class AnchorConfigurationError(AnchorError):
    """Anchoring cannot safely start with the supplied configuration."""


class AnchorSinkError(AnchorError):
    """The configured anchor sink could not be read or durably written."""


class AnchorWriteError(AnchorError):
    """An explicit or close-time anchor write failed loudly."""

    def __init__(self, message: str, receipt: dict[str, Any]):
        self.receipt = dict(receipt)
        super().__init__(message)


@runtime_checkable
class AnchorSink(Protocol):
    """Custody adapter for signed anchor and manifest-pin records."""

    @property
    def sink_id(self) -> str:
        """Return the stable identity bound into every signed sink record."""

    def append(self, record: dict[str, Any]) -> dict[str, Any] | None:
        """Durably append one complete record and return the persisted record."""

    def read_records(self) -> list[dict[str, Any]]:
        """Return every complete record in append order or raise."""


class LocalFileAnchorSink:
    """Locked, fsync'd canonical-JSONL anchor sink with mode ``0600``.

    Cooperative writers serialize appends with an OS file lock. A partial final
    line is always an error: it is never ignored as if the sink were empty.
    """

    def __init__(self, path: str | Path, *, sink_id: str | None = None):
        self.path = Path(path)
        resolved = str(self.path.expanduser().resolve())
        self._sink_id = sink_id or (
            "local-file:" + hashlib.sha256(resolved.encode("utf-8")).hexdigest()
        )
        if not self._sink_id or any(ch.isspace() for ch in self._sink_id):
            raise AnchorConfigurationError("anchor sink_id must be a non-empty token")

    @property
    def sink_id(self) -> str:
        return self._sink_id

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        raw = _canonical_bytes(record) + b"\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        created = not self.path.exists()
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        fd = os.open(self.path, flags, 0o600)
        try:
            with _file_lock(fd, exclusive=True):
                mode = stat.S_IMODE(os.fstat(fd).st_mode)
                if mode & 0o077:
                    raise AnchorSinkError(
                        "local anchor sink permissions must not grant group/other access"
                    )
                size = os.lseek(fd, 0, os.SEEK_END)
                existing = []
                if size:
                    os.lseek(fd, 0, os.SEEK_SET)
                    chunks = []
                    while True:
                        chunk = os.read(fd, 1024 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    current = b"".join(chunks)
                    if not current.endswith(b"\n"):
                        raise AnchorSinkError(
                            "local anchor sink has a partial final record"
                        )
                    existing = _parse_record_lines(current)
                    duplicate = _idempotent_existing_record(existing, record)
                    if duplicate is not None:
                        return duplicate
                remaining = memoryview(raw)
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:
                        raise AnchorSinkError("local anchor sink append made no progress")
                    remaining = remaining[written:]
                os.fsync(fd)
        except Exception:
            raise
        finally:
            os.close(fd)
        if created and os.name != "nt":
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return record

    def read_records(self) -> list[dict[str, Any]]:
        fd = os.open(self.path, os.O_RDONLY)
        try:
            with _file_lock(fd, exclusive=False):
                mode = stat.S_IMODE(os.fstat(fd).st_mode)
                if mode & 0o077:
                    raise AnchorSinkError(
                        "local anchor sink permissions must not grant group/other access"
                    )
                chunks = []
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                raw = b"".join(chunks)
        finally:
            os.close(fd)
        if not raw:
            return []
        if not raw.endswith(b"\n"):
            raise AnchorSinkError("local anchor sink has a partial final record")
        return _parse_record_lines(raw)


class AnchorWriter:
    """Signed anchor cadence, verification, health, and manifest-pin coordinator."""

    def __init__(
        self,
        *,
        store,
        sink: AnchorSink,
        custodian: LocalKmsCustodian,
        trusted_root_fingerprints: str | Iterable[str],
        interval_s: float | None = None,
        every_n_rows: int | None = None,
        clock: Callable[[], float] = time.time,
        retry_backoff_s: float = 1.0,
        retry_backoff_max_s: float = 60.0,
        background_time_cadence: bool = False,
    ):
        if not isinstance(custodian, LocalKmsCustodian):
            raise AnchorConfigurationError(
                "audit anchoring requires durable Ed25519 custody"
            )
        if not isinstance(sink, AnchorSink):
            raise AnchorConfigurationError("anchor_sink does not implement AnchorSink")
        self.store = store
        self.sink = sink
        self.custodian = custodian
        self.clock = clock
        self.interval_s = _positive_float(
            interval_s,
            _float_env("HEARTWOOD_ANCHOR_INTERVAL_S", _DEFAULT_INTERVAL_S),
            "anchor interval",
        )
        self.every_n_rows = _positive_int(
            every_n_rows,
            _int_env("HEARTWOOD_ANCHOR_EVERY_N_ROWS", _DEFAULT_EVERY_N_ROWS),
            "anchor row cadence",
        )
        self.retry_backoff_s = _positive_float(
            retry_backoff_s, 1.0, "anchor retry backoff"
        )
        self.retry_backoff_max_s = _positive_float(
            retry_backoff_max_s, 60.0, "anchor retry maximum"
        )
        if self.retry_backoff_max_s < self.retry_backoff_s:
            raise AnchorConfigurationError(
                "anchor retry maximum must be at least the initial backoff"
            )
        self.chain_id = self.store.chain_id()
        self.trusted_root_fingerprints = _normalize_fingerprints(
            trusted_root_fingerprints
        )
        self._private_key = _anchor_private_key(
            custodian,
            chain_id=self.chain_id,
            sink_id=self.sink.sink_id,
        )
        self._public_key = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.root_fingerprint = _fingerprint(self._public_key)
        if self.root_fingerprint not in self.trusted_root_fingerprints:
            raise AnchorConfigurationError(
                "derived anchor verification root is not present in the external pin set"
            )
        self.last_failure: dict[str, Any] | None = self.store.anchor_failure(
            self.sink.sink_id
        )
        self._consecutive_failures = 0
        self._next_retry_at = 0.0
        self._background_time_cadence = bool(
            background_time_cadence and self.store.path != ":memory:"
        )
        self._timer_lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._closed = False

    def provisioning_receipt(self) -> dict[str, Any]:
        """Return non-secret values an operator pins before the first anchor."""
        return {
            "chain_id": self.chain_id,
            "sink_id": self.sink.sink_id,
            "signing_key_id": self.custodian.key_id,
            "verification_root_fingerprint": self.root_fingerprint,
        }

    def anchor(self) -> dict[str, Any]:
        """Persist, read back, verify, and match the current non-empty audit head."""
        head = self.store.audit_head_snapshot()
        if head["seq"] == 0:
            raise self._write_error(
                AnchorConfigurationError("cannot anchor an empty audit chain"),
                current_head=head,
            )
        try:
            records = self._records_for_write()
            valid = _validate_sink_records(
                records,
                sink_id=self.sink.sink_id,
                chain_id=self.chain_id,
                trusted_root_fingerprints=self.trusted_root_fingerprints,
            )
            latest = _latest_anchor(valid)
            if (
                latest is not None
                and latest["seq"] == head["seq"]
                and latest["row_hash"] == head["row_hash"]
            ):
                receipt = self.verify()
                if receipt["ok"]:
                    self._clear_failure()
                return {**receipt, "wrote_anchor": False, "anchor_id": latest["anchor_id"]}

            record = self._signed_record(
                {
                    "domain": _ANCHOR_DOMAIN,
                    "schema_version": 1,
                    "record_type": "audit_anchor",
                    "chain_id": self.chain_id,
                    "anchor_id": "anc_" + secrets.token_hex(12),
                    "seq": head["seq"],
                    "row_hash": head["row_hash"],
                    "created_at_utc": _utc_iso(self.clock()),
                    "sink_id": self.sink.sink_id,
                    "signing_key_id": self.custodian.key_id,
                    "signing_public_key": _b64e(self._public_key),
                    "verification_root_fingerprint": self.root_fingerprint,
                },
                signature_domain=_ANCHOR_SIGNATURE_DOMAIN,
            )
            persisted = self.sink.append(record) or record
            self.store.set_anchor_sink_head(
                self.sink.sink_id,
                _record_digest(persisted),
            )
            receipt = self.verify(include_prior_failure=False)
            if (
                not receipt["ok"]
                or receipt["last_success_anchor_id"] != persisted["anchor_id"]
                or receipt["last_success_seq"] != head["seq"]
            ):
                raise AnchorSinkError(
                    "anchor read-back did not verify against the captured database head"
                )
            self._clear_failure()
            self._cancel_timer()
            return {
                **receipt,
                "wrote_anchor": persisted["anchor_id"] == record["anchor_id"],
                "anchor_id": persisted["anchor_id"],
            }
        except AnchorWriteError:
            raise
        except Exception as exc:
            raise self._write_error(exc, current_head=head) from exc

    def maybe_anchor(self) -> dict[str, Any]:
        """Apply count/time cadence without failing the main audit write path."""
        status = self.verify()
        if not status["anchor_due"]:
            self._schedule_time_anchor(status)
            return status
        now = self.clock()
        if now < self._next_retry_at:
            return {
                **status,
                "ok": False,
                "anchor_status": "degraded",
                "retry_after_seconds": max(0.0, self._next_retry_at - now),
            }
        try:
            return self.anchor()
        except AnchorWriteError as exc:
            self._schedule_retry(exc.receipt.get("retry_after_seconds"))
            return dict(exc.receipt)

    def verify(self, *, include_prior_failure: bool = True) -> dict[str, Any]:
        if include_prior_failure:
            self.last_failure = self.store.anchor_failure(self.sink.sink_id)
        return verify_chain_against_anchors(
            self.store,
            self.sink,
            trusted_root_fingerprints=self.trusted_root_fingerprints,
            interval_s=self.interval_s,
            every_n_rows=self.every_n_rows,
            now=self.clock(),
            last_error_class=(
                self.last_failure["error_class"]
                if include_prior_failure and self.last_failure
                else None
            ),
        )

    def pin_manifest(self, manifest_id: str, manifest_digest: str) -> dict[str, Any]:
        """Append a signed, monotonic strict-manifest digest pin to the sink."""
        if not _MANIFEST_ID_RE.fullmatch(str(manifest_id)):
            raise AnchorConfigurationError("strict manifest id is invalid")
        if not _DIGEST_RE.fullmatch(str(manifest_digest)):
            raise AnchorConfigurationError("strict manifest digest is invalid")
        try:
            records = self._records_for_write()
            valid = _validate_sink_records(
                records,
                sink_id=self.sink.sink_id,
                chain_id=self.chain_id,
                trusted_root_fingerprints=self.trusted_root_fingerprints,
            )
            existing = [
                record
                for record in valid
                if record["record_type"] == "strict_cutover_manifest_pin"
                and record["manifest_id"] == manifest_id
            ]
            if existing:
                if existing[-1]["manifest_digest"] != manifest_digest:
                    raise AnchorSinkError(
                        "strict manifest id is already pinned to another digest"
                    )
                return {
                    "pin_source": "anchor_sink",
                    "pin_id": existing[-1]["pin_id"],
                    "manifest_id": manifest_id,
                    "manifest_digest": manifest_digest,
                    "wrote_pin": False,
                }
            record = self._signed_record(
                {
                    "domain": _MANIFEST_PIN_DOMAIN,
                    "schema_version": 1,
                    "record_type": "strict_cutover_manifest_pin",
                    "chain_id": self.chain_id,
                    "pin_id": "pin_" + secrets.token_hex(12),
                    "manifest_id": manifest_id,
                    "manifest_digest": manifest_digest,
                    "created_at_utc": _utc_iso(self.clock()),
                    "sink_id": self.sink.sink_id,
                    "signing_key_id": self.custodian.key_id,
                    "signing_public_key": _b64e(self._public_key),
                    "verification_root_fingerprint": self.root_fingerprint,
                },
                signature_domain=_MANIFEST_PIN_SIGNATURE_DOMAIN,
            )
            persisted = self.sink.append(record) or record
            self.store.set_anchor_sink_head(
                self.sink.sink_id,
                _record_digest(persisted),
            )
            if self.resolve_manifest_digest(manifest_id) != manifest_digest:
                raise AnchorSinkError("strict manifest pin failed read-back verification")
            return {
                "pin_source": "anchor_sink",
                "pin_id": persisted["pin_id"],
                "manifest_id": manifest_id,
                "manifest_digest": manifest_digest,
                "wrote_pin": persisted["pin_id"] == record["pin_id"],
            }
        except Exception as exc:
            raise self._write_error(exc) from exc

    def resolve_manifest_digest(self, manifest_id: str) -> str:
        records = self.sink.read_records()
        valid = _validate_sink_records(
            records,
            sink_id=self.sink.sink_id,
            chain_id=self.chain_id,
            trusted_root_fingerprints=self.trusted_root_fingerprints,
        )
        sink_head = self.store.anchor_sink_head(self.sink.sink_id)
        if not valid or sink_head != _record_digest(valid[-1]):
            raise AnchorSinkError("anchor sink head is missing or rolled back")
        pins = [
            record
            for record in valid
            if record["record_type"] == "strict_cutover_manifest_pin"
            and record["manifest_id"] == manifest_id
        ]
        if not pins:
            raise AnchorSinkError("strict manifest digest is not pinned in the anchor sink")
        digests = {record["manifest_digest"] for record in pins}
        if len(digests) != 1 or len(pins) != 1:
            raise AnchorSinkError("strict manifest pin is duplicated or conflicting")
        return pins[0]["manifest_digest"]

    def close(self) -> dict[str, Any]:
        """Force a final anchor for a non-empty chain; failures raise after receipt."""
        self._closed = True
        self._cancel_timer()
        if self.store.audit_head()["seq"] == 0:
            return self.verify()
        return self.anchor()

    def _signed_record(
        self,
        body: dict[str, Any],
        *,
        signature_domain: bytes,
    ) -> dict[str, Any]:
        signature = self._private_key.sign(signature_domain + _canonical_bytes(body))
        return {**body, "signature": _b64e(signature)}

    def _records_for_write(self) -> list[dict[str, Any]]:
        try:
            records = self.sink.read_records()
        except FileNotFoundError:
            return []
        if records:
            sink_head = self.store.anchor_sink_head(self.sink.sink_id)
            if sink_head != _record_digest(records[-1]):
                raise AnchorSinkError("anchor sink head is missing or rolled back")
        return records

    def _write_error(
        self,
        exc: Exception,
        *,
        current_head: dict[str, Any] | None = None,
    ) -> AnchorWriteError:
        self._consecutive_failures += 1
        delay = min(
            self.retry_backoff_s * (2 ** (self._consecutive_failures - 1)),
            self.retry_backoff_max_s,
        )
        self._next_retry_at = self.clock() + delay
        head = current_head or self.store.audit_head_snapshot()
        self.last_failure = {
            "error_class": type(exc).__name__,
            "failed_at_utc": _utc_iso(self.clock()),
            "current_seq": head["seq"],
            "retry_after_seconds": delay,
        }
        self.store.set_anchor_failure(self.sink.sink_id, self.last_failure)
        receipt = {
            "ok": False,
            "anchor_status": "degraded",
            "chain_id": self.chain_id,
            "sink_id": self.sink.sink_id,
            "sink_healthy": False,
            "anchors_ok": False,
            "anchor_fresh": False,
            "anchor_due": head["seq"] > 0,
            "current_seq": head["seq"],
            "current_row_hash": head["row_hash"],
            "last_sanitized_error_class": type(exc).__name__,
            "retry_after_seconds": delay,
        }
        return AnchorWriteError(
            f"anchor write failed loudly ({type(exc).__name__})",
            receipt,
        )

    def _clear_failure(self) -> None:
        self.last_failure = None
        self.store.clear_anchor_failure(self.sink.sink_id)
        self._consecutive_failures = 0
        self._next_retry_at = 0.0

    def _schedule_time_anchor(self, status: dict[str, Any]) -> None:
        if (
            not self._background_time_cadence
            or self._closed
            or int(status.get("rows_since_success") or 0) <= 0
        ):
            return
        elapsed = float(status.get("seconds_since_success") or 0.0)
        self._schedule_timer(max(0.01, self.interval_s - elapsed))

    def _schedule_retry(self, delay: Any) -> None:
        if not self._background_time_cadence or self._closed:
            return
        self._schedule_timer(max(0.01, float(delay or self.retry_backoff_s)))

    def _schedule_timer(self, delay: float) -> None:
        with self._timer_lock:
            if self._closed or (self._timer is not None and self._timer.is_alive()):
                return
            timer = threading.Timer(delay, self._run_background_time_anchor)
            timer.daemon = True
            self._timer = timer
            timer.start()

    def _cancel_timer(self) -> None:
        with self._timer_lock:
            timer = self._timer
            self._timer = None
        if timer is not None:
            timer.cancel()

    def _run_background_time_anchor(self) -> None:
        from .store import Store

        with self._timer_lock:
            self._timer = None
        if self._closed:
            return
        background_store = Store(self.store.path)
        status: dict[str, Any]
        try:
            writer = AnchorWriter(
                store=background_store,
                sink=self.sink,
                custodian=self.custodian,
                trusted_root_fingerprints=self.trusted_root_fingerprints,
                interval_s=self.interval_s,
                every_n_rows=self.every_n_rows,
                retry_backoff_s=self.retry_backoff_s,
                retry_backoff_max_s=self.retry_backoff_max_s,
                background_time_cadence=False,
            )
            status = writer.maybe_anchor()
        except Exception as exc:
            failure = {
                "error_class": type(exc).__name__,
                "failed_at_utc": _utc_iso(time.time()),
                "current_seq": background_store.audit_head()["seq"],
                "retry_after_seconds": self.retry_backoff_s,
            }
            background_store.set_anchor_failure(self.sink.sink_id, failure)
            status = {
                "ok": False,
                "anchor_due": True,
                "retry_after_seconds": self.retry_backoff_s,
            }
        finally:
            background_store.close()
        if not status.get("ok") and status.get("anchor_due"):
            self._schedule_retry(status.get("retry_after_seconds"))


def anchor_root_fingerprint(
    custodian: LocalKmsCustodian,
    *,
    chain_id: str,
    sink_id: str,
) -> str:
    """Derive the non-secret verification-root fingerprint to pin externally."""
    if not isinstance(custodian, LocalKmsCustodian):
        raise AnchorConfigurationError(
            "audit anchoring requires durable Ed25519 custody"
        )
    public_key = _anchor_private_key(
        custodian,
        chain_id=chain_id,
        sink_id=sink_id,
    ).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _fingerprint(public_key)


def verify_chain_against_anchors(
    store,
    sink: AnchorSink,
    *,
    trusted_root_fingerprints: str | Iterable[str],
    interval_s: float = _DEFAULT_INTERVAL_S,
    every_n_rows: int = _DEFAULT_EVERY_N_ROWS,
    now: float | None = None,
    last_error_class: str | None = None,
) -> dict[str, Any]:
    """Verify the current chain and every signed out-of-database anchor.

    The receipt fails closed for a missing, empty, malformed, forged, reordered,
    stale, or database-mismatched anchor sink. A post-anchor row window is
    reported explicitly and is not described as protected until it is anchored.
    """
    checked_at = time.time() if now is None else float(now)
    interval = _positive_float(interval_s, _DEFAULT_INTERVAL_S, "anchor interval")
    row_cadence = _positive_int(
        every_n_rows, _DEFAULT_EVERY_N_ROWS, "anchor row cadence"
    )
    head = store.audit_head_snapshot()
    chain_ok = AuditLog(store).verify_chain()
    base = {
        "ok": False,
        "anchor_status": "degraded",
        "chain_id": store.chain_id(),
        "sink_id": sink.sink_id,
        "chain_ok": chain_ok,
        "anchors_ok": False,
        "anchor_fresh": False,
        "sink_healthy": False,
        "anchors_checked": 0,
        "last_success_anchor_id": None,
        "last_success_seq": None,
        "last_success_time_utc": None,
        "current_seq": head["seq"],
        "current_time_utc": _utc_iso(checked_at),
        "rows_since_success": head["seq"],
        "seconds_since_success": None,
        "interval_s": interval,
        "every_n_rows": row_cadence,
        "anchor_due": head["seq"] > 0,
        "undetectable_window_rows": head["seq"],
        "first_failure": None,
        "last_sanitized_error_class": last_error_class,
    }
    try:
        records = sink.read_records()
        valid = _validate_sink_records(
            records,
            sink_id=sink.sink_id,
            chain_id=store.chain_id(),
            trusted_root_fingerprints=_normalize_fingerprints(
                trusted_root_fingerprints
            ),
        )
    except FileNotFoundError:
        return {**base, "first_failure": "anchor_sink_missing"}
    except Exception as exc:
        return {
            **base,
            "first_failure": "anchor_sink_unhealthy",
            "last_sanitized_error_class": type(exc).__name__,
        }

    anchors = [record for record in valid if record["record_type"] == "audit_anchor"]
    receipt = {**base, "sink_healthy": True, "anchors_checked": len(anchors)}
    if not anchors:
        return {**receipt, "first_failure": "no_anchors"}

    previous_seq = 0
    seen_ids = set()
    for record in anchors:
        if record["anchor_id"] in seen_ids:
            return {**receipt, "first_failure": "duplicate_anchor_id"}
        seen_ids.add(record["anchor_id"])
        if record["seq"] <= previous_seq:
            return {**receipt, "first_failure": "duplicate_or_reordered_anchor_seq"}
        previous_seq = record["seq"]

    sink_head = store.anchor_sink_head(sink.sink_id)
    if not valid or sink_head is None:
        return {**receipt, "first_failure": "anchor_sink_head_unrecorded"}
    if sink_head != _record_digest(valid[-1]):
        return {
            **receipt,
            "first_failure": "anchor_sink_rollback_or_divergence",
        }

    for record in anchors:
        row = store.audit_row(record["seq"])
        if row is None:
            return {
                **receipt,
                "first_failure": f"anchored_row_missing:{record['anchor_id']}",
            }
        if row["row_hash"] != record["row_hash"]:
            return {
                **receipt,
                "first_failure": f"anchored_row_hash_mismatch:{record['anchor_id']}",
            }

    latest = anchors[-1]
    if head["seq"] < latest["seq"]:
        return {
            **receipt,
            "first_failure": f"current_head_precedes_anchor:{latest['anchor_id']}",
        }
    created_at = _parse_utc(latest["created_at_utc"])
    rows_since = head["seq"] - latest["seq"]
    seconds_since = max(0.0, checked_at - created_at)
    due = rows_since > 0 and (
        rows_since >= row_cadence or seconds_since >= interval
    )
    fresh = not due
    anchors_ok = True
    ok = chain_ok and anchors_ok and fresh and last_error_class is None
    first_failure = None
    if not chain_ok:
        first_failure = "audit_chain_invalid"
    elif due:
        first_failure = "latest_anchor_stale"
    elif last_error_class is not None:
        first_failure = "prior_anchor_write_failed"
    return {
        **receipt,
        "ok": ok,
        "anchor_status": "healthy" if ok else "degraded",
        "anchors_ok": anchors_ok,
        "anchor_fresh": fresh,
        "last_success_anchor_id": latest["anchor_id"],
        "last_success_seq": latest["seq"],
        "last_success_time_utc": latest["created_at_utc"],
        "rows_since_success": rows_since,
        "seconds_since_success": seconds_since,
        "anchor_due": due,
        "undetectable_window_rows": rows_since,
        "first_failure": first_failure,
    }


def _validate_sink_records(
    records: list[dict[str, Any]],
    *,
    sink_id: str,
    chain_id: str,
    trusted_root_fingerprints: set[str],
) -> list[dict[str, Any]]:
    valid = []
    pin_ids = set()
    manifest_ids = set()
    for record in records:
        record_type = record.get("record_type")
        if record_type == "audit_anchor":
            _validate_anchor_record(
                record,
                sink_id=sink_id,
                chain_id=chain_id,
                trusted_root_fingerprints=trusted_root_fingerprints,
            )
        elif record_type == "strict_cutover_manifest_pin":
            _validate_manifest_pin_record(
                record,
                sink_id=sink_id,
                chain_id=chain_id,
                trusted_root_fingerprints=trusted_root_fingerprints,
            )
            if record["pin_id"] in pin_ids or record["manifest_id"] in manifest_ids:
                raise AnchorSinkError("strict manifest pin is duplicated")
            pin_ids.add(record["pin_id"])
            manifest_ids.add(record["manifest_id"])
        else:
            raise AnchorSinkError("anchor sink contains an unsupported record type")
        valid.append(record)
    return valid


def _validate_anchor_record(
    record: dict[str, Any],
    *,
    sink_id: str,
    chain_id: str,
    trusted_root_fingerprints: set[str],
) -> None:
    required = {
        "domain",
        "schema_version",
        "record_type",
        "chain_id",
        "anchor_id",
        "seq",
        "row_hash",
        "created_at_utc",
        "sink_id",
        "signing_key_id",
        "signing_public_key",
        "verification_root_fingerprint",
        "signature",
    }
    if set(record) != required:
        raise AnchorSinkError("audit anchor fields are malformed")
    if record["domain"] != _ANCHOR_DOMAIN or record["schema_version"] != 1:
        raise AnchorSinkError("audit anchor domain/version is unsupported")
    if record["record_type"] != "audit_anchor":
        raise AnchorSinkError("audit anchor record type is invalid")
    if record["chain_id"] != chain_id or not _CHAIN_ID_RE.fullmatch(chain_id):
        raise AnchorSinkError("audit anchor belongs to another chain")
    if record["sink_id"] != sink_id:
        raise AnchorSinkError("audit anchor belongs to another sink")
    if not _ANCHOR_ID_RE.fullmatch(str(record["anchor_id"])):
        raise AnchorSinkError("audit anchor id is invalid")
    if not isinstance(record["seq"], int) or isinstance(record["seq"], bool) or record["seq"] <= 0:
        raise AnchorSinkError("audit anchor seq is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(record["row_hash"])):
        raise AnchorSinkError("audit anchor row hash is invalid")
    _parse_utc(record["created_at_utc"])
    _verify_signed_record(
        record,
        signature_domain=_ANCHOR_SIGNATURE_DOMAIN,
        trusted_root_fingerprints=trusted_root_fingerprints,
    )


def _validate_manifest_pin_record(
    record: dict[str, Any],
    *,
    sink_id: str,
    chain_id: str,
    trusted_root_fingerprints: set[str],
) -> None:
    required = {
        "domain",
        "schema_version",
        "record_type",
        "chain_id",
        "pin_id",
        "manifest_id",
        "manifest_digest",
        "created_at_utc",
        "sink_id",
        "signing_key_id",
        "signing_public_key",
        "verification_root_fingerprint",
        "signature",
    }
    if set(record) != required:
        raise AnchorSinkError("strict manifest pin fields are malformed")
    if record["domain"] != _MANIFEST_PIN_DOMAIN or record["schema_version"] != 1:
        raise AnchorSinkError("strict manifest pin domain/version is unsupported")
    if record["record_type"] != "strict_cutover_manifest_pin":
        raise AnchorSinkError("strict manifest pin record type is invalid")
    if record["chain_id"] != chain_id or not _CHAIN_ID_RE.fullmatch(chain_id):
        raise AnchorSinkError("strict manifest pin belongs to another chain")
    if record["sink_id"] != sink_id:
        raise AnchorSinkError("strict manifest pin belongs to another sink")
    if not _PIN_ID_RE.fullmatch(str(record["pin_id"])):
        raise AnchorSinkError("strict manifest pin id is invalid")
    if not _MANIFEST_ID_RE.fullmatch(str(record["manifest_id"])):
        raise AnchorSinkError("strict manifest id is invalid")
    if not _DIGEST_RE.fullmatch(str(record["manifest_digest"])):
        raise AnchorSinkError("strict manifest digest is invalid")
    _parse_utc(record["created_at_utc"])
    _verify_signed_record(
        record,
        signature_domain=_MANIFEST_PIN_SIGNATURE_DOMAIN,
        trusted_root_fingerprints=trusted_root_fingerprints,
    )


def _verify_signed_record(
    record: dict[str, Any],
    *,
    signature_domain: bytes,
    trusted_root_fingerprints: set[str],
) -> None:
    try:
        public_key = _b64d(record["signing_public_key"])
        signature = _b64d(record["signature"])
    except Exception as exc:
        raise AnchorSinkError("anchor signing material is malformed") from exc
    if len(public_key) != 32 or len(signature) != 64:
        raise AnchorSinkError("anchor signing material has an invalid length")
    fingerprint = _fingerprint(public_key)
    if record["verification_root_fingerprint"] != fingerprint:
        raise AnchorSinkError("anchor verification-root fingerprint is inconsistent")
    if fingerprint not in trusted_root_fingerprints:
        raise AnchorSinkError("anchor verification root is not externally pinned")
    if not isinstance(record["signing_key_id"], str) or not record["signing_key_id"]:
        raise AnchorSinkError("anchor signing key id is invalid")
    body = {key: value for key, value in record.items() if key != "signature"}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            signature_domain + _canonical_bytes(body),
        )
    except InvalidSignature as exc:
        raise AnchorSinkError("anchor signature is invalid") from exc


def _latest_anchor(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    anchors = [record for record in records if record["record_type"] == "audit_anchor"]
    return anchors[-1] if anchors else None


def _anchor_private_key(
    custodian: LocalKmsCustodian,
    *,
    chain_id: str,
    sink_id: str,
):
    if not _CHAIN_ID_RE.fullmatch(str(chain_id)):
        raise AnchorConfigurationError("store chain_id is invalid")
    seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"heartwood:audit-anchor:v1",
        info=(
            f"chain:{chain_id}:sink:{sink_id}:key:{custodian.key_id}"
        ).encode("utf-8"),
    ).derive(custodian.root_key)
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def _normalize_fingerprints(value: str | Iterable[str]) -> set[str]:
    if isinstance(value, str):
        candidates = value.split(",")
    else:
        candidates = list(value)
    fingerprints = {str(item).strip() for item in candidates if str(item).strip()}
    if not fingerprints or any(not _DIGEST_RE.fullmatch(item) for item in fingerprints):
        raise AnchorConfigurationError(
            "trusted anchor root fingerprints must be sha256:<64 lowercase hex>"
        )
    return fingerprints


def _parse_canonical_record(raw: bytes, *, line_number: int) -> dict[str, Any]:
    try:
        record = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AnchorSinkError(
            f"local anchor sink record {line_number} is malformed"
        ) from exc
    if not isinstance(record, dict):
        raise AnchorSinkError(
            f"local anchor sink record {line_number} must be an object"
        )
    if raw != _canonical_bytes(record):
        raise AnchorSinkError(
            f"local anchor sink record {line_number} is not canonical JSON"
        )
    return record


def _parse_record_lines(raw: bytes) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line:
            raise AnchorSinkError(
                f"local anchor sink contains an empty record at line {line_number}"
            )
        records.append(_parse_canonical_record(line, line_number=line_number))
    return records


def _idempotent_existing_record(
    existing: list[dict[str, Any]],
    incoming: dict[str, Any],
) -> dict[str, Any] | None:
    if incoming.get("record_type") == "audit_anchor":
        anchors = [
            record for record in existing if record.get("record_type") == "audit_anchor"
        ]
        if not anchors:
            return None
        latest = anchors[-1]
        if incoming.get("seq") < latest.get("seq", -1):
            raise AnchorSinkError("local anchor sink refuses a reordered anchor")
        if incoming.get("seq") == latest.get("seq"):
            if incoming.get("row_hash") != latest.get("row_hash"):
                raise AnchorSinkError("local anchor sink refuses a conflicting anchor")
            return latest
        return None
    if incoming.get("record_type") == "strict_cutover_manifest_pin":
        for record in reversed(existing):
            if (
                record.get("record_type") == "strict_cutover_manifest_pin"
                and record.get("manifest_id") == incoming.get("manifest_id")
            ):
                if record.get("manifest_digest") != incoming.get("manifest_digest"):
                    raise AnchorSinkError(
                        "local anchor sink refuses a conflicting manifest pin"
                    )
                return record
    return None


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str):
    raise ValueError(f"non-finite JSON value: {value}")


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _fingerprint(public_key: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_key).hexdigest()


def _record_digest(record: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(record)).hexdigest()


def _utc_iso(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _parse_utc(value: Any) -> float:
    if not isinstance(value, str):
        raise AnchorSinkError("anchor created_at_utc is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AnchorSinkError("anchor created_at_utc is invalid") from exc
    if parsed.tzinfo is None:
        raise AnchorSinkError("anchor created_at_utc must include a timezone")
    return parsed.timestamp()


def _positive_float(value: Any, default: float, label: str) -> float:
    candidate = default if value is None else value
    try:
        result = float(candidate)
    except (TypeError, ValueError) as exc:
        raise AnchorConfigurationError(f"{label} must be a positive number") from exc
    if result <= 0:
        raise AnchorConfigurationError(f"{label} must be a positive number")
    return result


def _positive_int(value: Any, default: int, label: str) -> int:
    candidate = default if value is None else value
    if isinstance(candidate, bool):
        raise AnchorConfigurationError(f"{label} must be a positive integer")
    try:
        result = int(candidate)
    except (TypeError, ValueError) as exc:
        raise AnchorConfigurationError(f"{label} must be a positive integer") from exc
    if result <= 0:
        raise AnchorConfigurationError(f"{label} must be a positive integer")
    return result


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return default if raw is None else _positive_float(raw, default, name)


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return default if raw is None else _positive_int(raw, default, name)


@contextmanager
def _file_lock(fd: int, *, exclusive: bool):
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI/operator hosts
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        mode = msvcrt.LK_LOCK if exclusive else msvcrt.LK_RLCK
        msvcrt.locking(fd, mode, 1)
        try:
            yield
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
