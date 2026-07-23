"""Append-only, hash-chained audit log.

Every remember / recall / forget / approve writes a tamper-evident record.
The chain (each row hashes the previous row's hash + its own body) makes
silent deletion or edits detectable. The erasure *event* is retained here even
after the payload is crypto-shredded.
"""
from __future__ import annotations

import hashlib
import json


class AuditLog:
    def __init__(self, store):
        self.store = store

    def append(self, tenant, principal, action, target, detail: dict) -> str:
        body = json.dumps(
            {"tenant": tenant, "principal": principal, "action": action,
             "target": target, "detail": detail},
            sort_keys=True, separators=(",", ":"),
        )
        if hasattr(self.store, "append_audit_atomic"):
            return self.store.append_audit_atomic(tenant, principal, action, target, body)

        # Compatibility path for external Store-like implementations.
        import time

        prev_hash = self.store.last_audit_hash() or "genesis"
        ts = time.time()
        row_hash = hashlib.sha256((prev_hash + body + repr(ts)).encode()).hexdigest()
        self.store.append_audit(ts, tenant, principal, action, target, body, prev_hash, row_hash)
        return row_hash

    def verify_chain(self) -> bool:
        prev = "genesis"
        for row in self.store.iter_audit():
            if "prev_hash" in row and row["prev_hash"] != prev:
                return False
            expect = hashlib.sha256((prev + row["body"] + repr(row["ts"])).encode()).hexdigest()
            if expect != row["row_hash"]:
                return False
            prev = row["row_hash"]
        return True
