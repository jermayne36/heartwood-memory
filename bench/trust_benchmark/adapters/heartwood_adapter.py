"""Live adapter for Heartwood Memory (the system under test)."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from heartwood import (
    Heartwood,
    LocalFileAnchorSink,
    LocalKmsCustodian,
    Policy,
    Principal,
    StrictMode,
    StrictSignatureError,
    anchor_root_fingerprint,
    prove_crypto_erase_path,
    verify_chain_against_anchors,
)
from heartwood.anchors import AnchorWriter

from ..fixtures import (
    CUSTODY_KEY_ID,
    TENANT,
    deterministic_models,
    fixture_custody_root,
)
from .base import AdapterNotAvailable, MemoryAdapter, RecallView, Session

_BIG = 10**9  # disable time/row anchor cadence; only explicit anchors fire
_ALLOWED_UNSIGNED_FIELDS = {
    "classification",
    "indexed",
    "roles_json",
    "policy_scope",
    "visibility",
    "kind",
}


class HeartwoodSession(Session):
    def __init__(self, *, path: str, tenant: str, models, strict: str,
                 durable_custody: bool):
        self.tenant = tenant
        embedder, reranker = models
        custodian = (
            LocalKmsCustodian(fixture_custody_root(), key_id=CUSTODY_KEY_ID)
            if durable_custody
            else None
        )
        self._durable_custody = durable_custody
        self.db = Heartwood(
            path=path,
            tenant=tenant,
            embedder=embedder,
            reranker=reranker,
            key_custodian=custodian,
            strict_signatures=_STRICT[strict],
        )
        self._anchor_custodian = LocalKmsCustodian(
            fixture_custody_root(), key_id=CUSTODY_KEY_ID
        )
        self._anchor_sink = None
        self._anchor_writer = None
        self._anchor_fp = None

    # --- governance ----------------------------------------------------- #
    def remember(self, *, memory_id, subject, content, created_by="agent:bench",
                 classification="internal", role_gate=(), indexed=True,
                 review_state=None) -> str:
        policy = Policy(classification=classification, roles=tuple(role_gate))
        return self.db.remember(
            content,
            subject=subject,
            created_by=created_by,
            policy=policy,
            memory_id=memory_id,
            indexed=indexed,
            review_state=review_state,
        )

    def recall(self, cue, *, reader, filters=None) -> RecallView:
        principal = Principal(
            id=reader["id"],
            tenant=self.tenant,
            roles=tuple(reader.get("roles", ())),
            clearance=reader.get("clearance", "internal"),
        )
        try:
            out = self.db.recall(cue, principal=principal, filters=filters or {}, k=8)
        except StrictSignatureError as exc:
            return RecallView(
                raised="StrictSignatureError",
                strict_dropped_ids=list(exc.ids),
            )
        hits = []
        for r in out["results"]:
            prov = r.get("provenance", {})
            hits.append(
                {
                    "id": r["id"],
                    "content": r["content"],
                    "signature_valid": prov.get("signature_valid"),
                    "content_hash_match": prov.get("content_hash_match"),
                    "classification": r.get("classification"),
                }
            )
        view = RecallView(hits=hits, recall_id=out["recall_id"])
        view.audit_detail = self._recall_audit_detail(out["recall_id"])
        if view.audit_detail:
            view.denied = view.audit_detail.get("denied")
        try:
            view.explain = self.db.explain_recall(out["recall_id"])
            dropped = (view.explain or {}).get("strict_dropped") or {}
            view.strict_dropped_ids = list(dropped.get("ids") or [])
        except Exception:
            view.explain = None
        return view

    def verify_audit(self) -> bool:
        return self.db.verify_audit()

    def set_indexed(self, memory_id, indexed, *, actor="agent:bench", reason="") -> None:
        self.db.set_indexed(memory_id, indexed, actor=actor, reason=reason)

    def expire(self, memory_id, at, *, actor="agent:bench", reason="") -> None:
        self.db.expire(memory_id, at, actor=actor, reason=reason)

    def supersede(self, memory_id, *, reviewer, reason="") -> None:
        principal = Principal(
            id=reviewer["id"],
            tenant=self.tenant,
            roles=tuple(reviewer.get("roles", ())),
            clearance=reviewer.get("clearance", "internal"),
        )
        self.db.transition_review(memory_id, "superseded", principal, reason=reason)

    def forget(self, subject, *, actor="agent:bench", reason="") -> dict:
        return self.db.forget(subject, mode="hard", actor=actor, reason=reason)

    def erase_proof(self, *, root_present) -> dict:
        proof = prove_crypto_erase_path(
            self.db.path, tenant=self.tenant, root_present=root_present
        )
        return proof.to_dict()

    def audit_action_present(self, target, action) -> bool:
        cur = self.db.store.conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE target=? AND action=?",
            (target, action),
        )
        return cur.fetchone()[0] > 0

    # --- external anchoring --------------------------------------------- #
    def anchor(self) -> dict:
        writer = self._ensure_anchor_writer()
        return writer.anchor()

    def verify_against_anchors(self) -> dict:
        if self._anchor_sink is None:
            raise AdapterNotAvailable("anchor() must be called before verification")
        return verify_chain_against_anchors(
            self.db.store,
            self._anchor_sink,
            trusted_root_fingerprints=self._anchor_fp,
            interval_s=_BIG,
            every_n_rows=_BIG,
        )

    def _ensure_anchor_writer(self) -> AnchorWriter:
        if self._anchor_writer is None:
            anchor_path = Path(self.db.path).with_suffix(".anchors.jsonl")
            sink = LocalFileAnchorSink(anchor_path)
            self._anchor_fp = anchor_root_fingerprint(
                self._anchor_custodian,
                chain_id=self.db.store.chain_id(),
                sink_id=sink.sink_id,
            )
            self._anchor_sink = sink
            self._anchor_writer = AnchorWriter(
                store=self.db.store,
                sink=sink,
                custodian=self._anchor_custodian,
                trusted_root_fingerprints=self._anchor_fp,
                interval_s=_BIG,
                every_n_rows=_BIG,
                background_time_cadence=False,
            )
        return self._anchor_writer

    # --- adversary simulation (raw SQLite writer = "T2" at-rest attacker) #
    def _conn(self):
        return self.db.store.conn

    def adv_flip_content_hash(self, memory_id) -> None:
        self._conn().execute(
            "UPDATE memories SET content_hash=? WHERE id=?",
            ("sha256:" + "0" * 64, memory_id),
        )
        self._conn().commit()

    def adv_forge_signature(self, memory_id) -> None:
        self._conn().execute(
            "UPDATE memories SET producer_sig=? WHERE id=?",
            ("ed25519:forged-benchmark-key:AAAAAAAA", memory_id),
        )
        self._conn().commit()

    def adv_flip_unsigned_field(self, memory_id, field, value) -> None:
        if field not in _ALLOWED_UNSIGNED_FIELDS:
            raise ValueError(f"unsupported unsigned field for tamper: {field}")
        self._conn().execute(
            f"UPDATE memories SET {field}=? WHERE id=?",  # noqa: S608 - whitelisted
            (value, memory_id),
        )
        self._conn().commit()

    def adv_edit_audit_body_inplace(self) -> None:
        # Edit the earliest audit row's body in place, leaving row_hash stale.
        self._conn().execute(
            "UPDATE audit_log SET body = body || ' ' "
            "WHERE seq = (SELECT MIN(seq) FROM audit_log)"
        )
        self._conn().commit()

    def adv_drop_interior_audit_row(self) -> None:
        # Delete the second row, breaking the prev_hash linkage at the gap.
        self._conn().execute(
            "DELETE FROM audit_log WHERE seq = "
            "(SELECT seq FROM audit_log ORDER BY seq LIMIT 1 OFFSET 1)"
        )
        self._conn().commit()

    def adv_truncate_audit_tail(self, n=1) -> None:
        self._conn().execute(
            "DELETE FROM audit_log WHERE seq > (SELECT MAX(seq) FROM audit_log) - ?",
            (n,),
        )
        self._conn().commit()

    def adv_raw_unindex(self, memory_id) -> None:
        # Bypass set_indexed(): no audit event is written.
        self._conn().execute(
            "UPDATE memories SET indexed=0 WHERE id=?", (memory_id,)
        )
        self._conn().commit()

    # --- introspection / lifecycle -------------------------------------- #
    def _recall_audit_detail(self, recall_id) -> dict | None:
        cur = self._conn().execute(
            "SELECT body FROM audit_log WHERE target=? AND action='recall' "
            "ORDER BY seq DESC LIMIT 1",
            (recall_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0]).get("detail")
        except (TypeError, ValueError):
            return None

    def close(self) -> None:
        try:
            self.db.close()
        except Exception:
            pass


_STRICT = {
    "off": StrictMode.OFF,
    "filter": StrictMode.FILTER,
    "enforce": StrictMode.ENFORCE,
}


class HeartwoodAdapter(MemoryAdapter):
    name = "heartwood"

    def __init__(self, tenant: str = TENANT):
        self.tenant = tenant
        self._models = deterministic_models()
        self._tmp = tempfile.mkdtemp(prefix="heartwood-trust-bench-")
        self._counter = 0

    def capabilities(self) -> dict:
        return {
            "signed_provenance": True,
            "strict_enforcement": True,
            "hash_chained_audit": True,
            "external_anchor": True,
            "policy_before_ranking": True,
            "auditable_retirement": True,
            "key_destruction_receipt": True,
            "crypto_erase_proof": True,
        }

    def session(self, *, strict="off", durable_custody=False, **_ignored) -> HeartwoodSession:
        self._counter += 1
        path = str(Path(self._tmp) / f"store-{self._counter:03d}.db")
        return HeartwoodSession(
            path=path,
            tenant=self.tenant,
            models=self._models,
            strict=strict,
            durable_custody=durable_custody,
        )

    def cleanup(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)
