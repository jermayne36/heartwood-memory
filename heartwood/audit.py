"""Append-only, hash-chained audit log.

Every remember / recall / forget / approve writes a tamper-evident record.
The chain detects hash-bound edits and dropped interior rows. Tail loss requires
a separately persisted anchor; the non-atomic compatibility append below cannot
provide the same concurrency guarantee as Store.append_audit_atomic().
The erasure *event* is retained even after the payload is crypto-shredded.
"""
from __future__ import annotations

import hashlib
import json


class AuditLog:
    def __init__(self, store, *, after_append=None):
        self.store = store
        self.after_append = after_append

    def append(self, tenant, principal, action, target, detail: dict) -> str:
        body = json.dumps(
            {"tenant": tenant, "principal": principal, "action": action,
             "target": target, "detail": detail},
            sort_keys=True, separators=(",", ":"),
        )
        if hasattr(self.store, "append_audit_atomic"):
            row_hash = self.store.append_audit_atomic(
                tenant, principal, action, target, body
            )
            if self.after_append is not None:
                self.after_append()
            return row_hash

        # Compatibility path for external Store-like implementations.
        import time

        prev_hash = self.store.last_audit_hash() or "genesis"
        ts = time.time()
        row_hash = hashlib.sha256((prev_hash + body + repr(ts)).encode()).hexdigest()
        self.store.append_audit(ts, tenant, principal, action, target, body, prev_hash, row_hash)
        if self.after_append is not None:
            self.after_append()
        return row_hash

    def verify_chain(self) -> bool:
        prev = "genesis"
        for row in self.store.iter_audit():
            if "prev_hash" in row and row["prev_hash"] != prev:
                return False
            if not self._display_columns_match_body(row):
                return False
            expect = hashlib.sha256((prev + row["body"] + repr(row["ts"])).encode()).hexdigest()
            if expect != row["row_hash"]:
                return False
            prev = row["row_hash"]
        return True

    @staticmethod
    def _display_columns_match_body(row: dict) -> bool:
        displayed = ("tenant", "principal", "action", "target")
        present = [key in row for key in displayed]
        if not any(present):
            return True
        if not all(present):
            return False
        try:
            payload = json.loads(row["body"])
        except (TypeError, ValueError):
            return False
        if not isinstance(payload, dict):
            return False
        return all(payload.get(key) == row[key] for key in displayed)
