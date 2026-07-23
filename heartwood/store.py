"""SQLite persistence — the authoritative store.

The vector index and BM25 are DERIVED and rebuildable from here (the external
system-of-record is rebuildable from its source). Production swaps the brute-force
vector scan for sqlite-vec (asg017) — whose metadata-filter bitmap is the native
primitive for policy-pre-filtered ANN. Scaffold uses a numpy brute-force scan
(correct, fine at embedded scale).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time

import numpy as np

from .envelope import default_truth_status

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
  id TEXT PRIMARY KEY, tenant TEXT, kind TEXT, epistemic TEXT, subject TEXT,
  confidence REAL, salience REAL, created_by TEXT, created_at REAL,
  content_hash TEXT,
  truth_status TEXT, policy_scope TEXT, valid_from TEXT, valid_until TEXT,
  subject_ids_json TEXT, entities_json TEXT, source_ids_json TEXT, source_spans_json TEXT,
  source_json TEXT, model_version TEXT,
  visibility TEXT, classification TEXT, pii INTEGER,
  roles_json TEXT, role_groups_json TEXT, attrs_json TEXT, retention TEXT,
  producer_sig TEXT, sig_valid INTEGER,
  review_state TEXT, index_text_enc BLOB,
  content_enc BLOB, emb BLOB, emb_dim INTEGER, indexed INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_mem_tenant ON memories(tenant);
CREATE INDEX IF NOT EXISTS idx_mem_subject ON memories(tenant, subject);
CREATE TABLE IF NOT EXISTS prov_edges (child TEXT, parent TEXT, kind TEXT,
  PRIMARY KEY (child, parent));
CREATE TABLE IF NOT EXISTS deletion_lineage (artifact_id TEXT PRIMARY KEY,
  artifact_kind TEXT, subject TEXT, tenant TEXT);
CREATE TABLE IF NOT EXISTS keys (tenant TEXT, subject TEXT, dek BLOB, state TEXT,
  PRIMARY KEY (tenant, subject));
CREATE TABLE IF NOT EXISTS principal_keys (
  tenant TEXT, principal_id TEXT, algorithm TEXT, public_key BLOB, created_at REAL,
  PRIMARY KEY (tenant, principal_id)
);
CREATE TABLE IF NOT EXISTS principal_key_aliases (
  tenant TEXT, principal_id TEXT, algorithm TEXT, public_key BLOB,
  key_id TEXT, created_at REAL,
  PRIMARY KEY (tenant, principal_id, algorithm, public_key)
);
CREATE TABLE IF NOT EXISTS audit_log (seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, tenant TEXT, principal TEXT, action TEXT, target TEXT,
  body TEXT, prev_hash TEXT, row_hash TEXT);
CREATE TABLE IF NOT EXISTS store_metadata (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);
"""

_MEMORY_META_COLUMNS = (
    "id, tenant, kind, epistemic, subject, confidence, salience, "
    "created_by, created_at, content_hash, truth_status, policy_scope, "
    "valid_from, valid_until, subject_ids_json, entities_json, "
    "source_ids_json, source_spans_json, source_json, model_version, "
    "visibility, classification, pii, roles_json, role_groups_json, "
    "attrs_json, retention, producer_sig, sig_valid, review_state, indexed"
)


class Store:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=30000")
        if path != ":memory:":
            for attempt in range(5):
                try:
                    self.conn.execute("PRAGMA journal_mode=WAL")
                    break
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() or attempt == 4:
                        raise
                    time.sleep(0.05 * (attempt + 1))
        self.conn.executescript(_SCHEMA)
        # forward-compatible migration for stores created before role_groups
        try:
            self.conn.execute("ALTER TABLE memories ADD COLUMN role_groups_json TEXT")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass
        try:
            self.conn.execute("ALTER TABLE memories ADD COLUMN content_hash TEXT")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass
        for ddl in (
            "ALTER TABLE memories ADD COLUMN truth_status TEXT",
            "ALTER TABLE memories ADD COLUMN policy_scope TEXT",
            "ALTER TABLE memories ADD COLUMN valid_from TEXT",
            "ALTER TABLE memories ADD COLUMN valid_until TEXT",
            "ALTER TABLE memories ADD COLUMN subject_ids_json TEXT",
            "ALTER TABLE memories ADD COLUMN entities_json TEXT",
            "ALTER TABLE memories ADD COLUMN source_ids_json TEXT",
            "ALTER TABLE memories ADD COLUMN source_spans_json TEXT",
            "ALTER TABLE memories ADD COLUMN review_state TEXT",
            "ALTER TABLE memories ADD COLUMN index_text_enc BLOB",
        ):
            try:
                self.conn.execute(ddl)
                self.conn.commit()
            except sqlite3.OperationalError:
                pass
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mem_review ON memories(tenant, review_state)"
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO store_metadata (key,value) VALUES ('chain_id',?)",
            ("chain_" + secrets.token_hex(16),),
        )
        self.conn.commit()

    def close(self):
        self.conn.close()

    # -- memories -------------------------------------------------------- #
    def insert_memory(self, m: dict, content_enc: bytes, emb):
        emb_bytes = np.asarray(emb, dtype=np.float32).tobytes() if emb is not None else None
        emb_dim = int(len(emb)) if emb is not None else 0
        self.conn.execute(
            """INSERT INTO memories (id,tenant,kind,epistemic,subject,confidence,salience,
               created_by,created_at,content_hash,truth_status,policy_scope,valid_from,valid_until,
               subject_ids_json,entities_json,source_ids_json,source_spans_json,source_json,model_version,visibility,classification,pii,
               roles_json,role_groups_json,attrs_json,retention,producer_sig,sig_valid,
               review_state,index_text_enc,content_enc,emb,emb_dim,indexed)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
            (m["id"], m["tenant"], m["kind"], m["epistemic"], m["subject"], m["confidence"],
             m["salience"], m["created_by"], m["created_at"], m["content_hash"],
             m.get("truth_status"), m.get("policy_scope", "default"), m.get("valid_from"),
             m.get("valid_until"), json.dumps(list(m.get("subject_ids", (m["subject"],)))),
             json.dumps(list(m.get("entities", ()))),
             json.dumps(list(m.get("source_ids", ()))), json.dumps(list(m.get("source_spans", ()))),
             json.dumps(m["source"]),
             m["model_version"], m["policy"]["visibility"], m["policy"]["classification"],
             int(m["policy"]["pii"]), json.dumps(list(m["policy"]["roles"])),
             json.dumps([list(g) for g in m["policy"].get("role_groups", ())]),
             json.dumps([list(a) for a in m["policy"]["attrs"]]), m["policy"]["retention"],
             m["producer_sig"], int(m["sig_valid"]), m.get("review_state"),
             m.get("index_text_enc"), content_enc, emb_bytes, emb_dim),
        )
        self.conn.commit()

    def get_meta(self, mem_id: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM memories WHERE id=?", (mem_id,)).fetchone()
        return self._row_meta(r) if r else None

    def candidates(self, tenant: str) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM memories WHERE tenant=?", (tenant,)).fetchall()
        return [self._row_full(r) for r in rows]

    def candidate_meta(self, tenant: str) -> list[dict]:
        """Policy-relevant metadata only (no content/embedding) — cheap to scan."""
        rows = self.conn.execute(
            f"SELECT {_MEMORY_META_COLUMNS} FROM memories WHERE tenant=?",
            (tenant,),
        ).fetchall()
        return [self._row_meta(r) for r in rows]

    def memories_by_source_path(
        self,
        tenant: str,
        source_path: str,
        *,
        source_uri: str | None = None,
    ) -> list[dict]:
        """Return tenant memories derived from a markdown source path/URI."""
        matches = []
        for meta in self.candidate_meta(tenant):
            source = meta.get("source") or {}
            source_ids = set(meta.get("source_ids") or ())
            if source.get("path") == source_path:
                matches.append(meta)
                continue
            if source_uri and (
                source.get("uri") == source_uri
                or source.get("source_uri") == source_uri
                or source_uri in source_ids
            ):
                matches.append(meta)
        return matches

    def all_embeddings(self):
        for r in self.conn.execute("SELECT id, tenant, emb, emb_dim FROM memories WHERE emb_dim>0"):
            yield r["id"], r["tenant"], np.frombuffer(r["emb"], dtype=np.float32)

    def memory_counts_by_tenant(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT tenant, COUNT(*) AS count FROM memories GROUP BY tenant ORDER BY tenant"
        ).fetchall()
        return {str(r["tenant"]): int(r["count"]) for r in rows}

    def memory_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0])

    def _row_meta(self, r) -> dict:
        return {
            "id": r["id"], "tenant": r["tenant"], "kind": r["kind"], "epistemic": r["epistemic"],
            "subject": r["subject"], "created_by": r["created_by"], "created_at": r["created_at"],
            "confidence": r["confidence"], "salience": r["salience"],
            "content_hash": r["content_hash"],
            "truth_status": r["truth_status"] or default_truth_status(r["epistemic"]),
            "policy_scope": r["policy_scope"] or "default",
            "valid_from": r["valid_from"],
            "valid_until": r["valid_until"],
            "subject_ids": tuple(json.loads(r["subject_ids_json"] or "[]")) or (r["subject"],),
            "entities": tuple(json.loads(r["entities_json"] or "[]")),
            "source_ids": tuple(json.loads(r["source_ids_json"] or "[]")),
            "source_spans": tuple(json.loads(r["source_spans_json"] or "[]")),
            "source": json.loads(r["source_json"] or "{}"), "model_version": r["model_version"],
            "visibility": r["visibility"], "classification": r["classification"],
            "pii": bool(r["pii"]), "roles": tuple(json.loads(r["roles_json"] or "[]")),
            "role_groups": tuple(tuple(g) for g in json.loads(r["role_groups_json"] or "[]")),
            "attrs": tuple(tuple(a) for a in json.loads(r["attrs_json"] or "[]")),
            "retention": r["retention"], "producer_sig": r["producer_sig"],
            "review_state": r["review_state"],
            "sig_valid_cached": bool(r["sig_valid"]), "indexed": bool(r["indexed"]),
        }

    def _row_full(self, r) -> dict:
        meta = self._row_meta(r)
        meta["content_enc"] = r["content_enc"]
        meta["emb"] = (np.frombuffer(r["emb"], dtype=np.float32) if r["emb_dim"] else None)
        return meta

    def get_content_enc(self, mem_id: str):
        r = self.conn.execute("SELECT content_enc, subject FROM memories WHERE id=?",
                              (mem_id,)).fetchone()
        return (r["content_enc"], r["subject"]) if r else (None, None)

    def get_text_encs(self, mem_id: str):
        r = self.conn.execute(
            "SELECT content_enc, index_text_enc, subject FROM memories WHERE id=?",
            (mem_id,),
        ).fetchone()
        return (r["content_enc"], r["index_text_enc"], r["subject"]) if r else (None, None, None)

    def delete_memory(self, mem_id: str):
        self.conn.execute("DELETE FROM memories WHERE id=?", (mem_id,))
        self.conn.execute("DELETE FROM prov_edges WHERE child=? OR parent=?", (mem_id, mem_id))
        self.conn.execute(
            "DELETE FROM deletion_lineage WHERE artifact_id IN (?,?)",
            (mem_id, f"emb:{mem_id}"),
        )
        self.conn.commit()

    def update_epistemic(self, mem_id: str, epistemic: str, *,
                         created_by: str | None = None,
                         producer_sig: str | None = None,
                         sig_valid: bool | None = None,
                         truth_status: str | None = None):
        fields = ["epistemic=?"]
        values: list = [epistemic]
        if truth_status is not None:
            fields.append("truth_status=?")
            values.append(truth_status)
        if created_by is not None:
            fields.append("created_by=?")
            values.append(created_by)
        if producer_sig is not None:
            fields.append("producer_sig=?")
            values.append(producer_sig)
        if sig_valid is not None:
            fields.append("sig_valid=?")
            values.append(int(sig_valid))
        values.append(mem_id)
        self.conn.execute(
            f"UPDATE memories SET {', '.join(fields)} WHERE id=?",
            tuple(values),
        )
        self.conn.commit()

    def update_review_state(self, mem_id: str, to_state: str, *, expected_from: str | None) -> bool:
        cur = self.conn.execute(
            "UPDATE memories SET review_state=? "
            "WHERE id=? AND (review_state IS ? OR review_state=?)",
            (to_state, mem_id, expected_from, expected_from),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def update_indexed(self, mem_id: str, indexed: bool, *, expected_from: bool) -> bool:
        # COALESCE matches how `_row_meta` reads the column: a legacy NULL is
        # False. Without it the compare-and-swap can never match such a row, and
        # the audited verb would report an unresolvable "changed during update".
        cur = self.conn.execute(
            "UPDATE memories SET indexed=? WHERE id=? AND COALESCE(indexed, 0)=?",
            (int(indexed), mem_id, int(expected_from)),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def update_valid_until(self, mem_id: str, valid_until: str | None, *,
                           expected_from: str | None) -> bool:
        cur = self.conn.execute(
            "UPDATE memories SET valid_until=? "
            "WHERE id=? AND (valid_until IS ? OR valid_until=?)",
            (valid_until, mem_id, expected_from, expected_from),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def review_queue(self, tenant: str, state: str | None) -> list[dict]:
        state = getattr(state, "value", state)
        rows = self.conn.execute(
            "SELECT * FROM memories WHERE tenant=? AND (review_state IS ? OR review_state=?) "
            "ORDER BY created_at ASC",
            (tenant, state, state),
        ).fetchall()
        return [self._row_meta(r) for r in rows]

    def index_lag(self, tenant: str) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM memories WHERE tenant=? AND indexed=0", (tenant,)
        ).fetchone()[0]

    # -- provenance / lineage ------------------------------------------- #
    def add_edge(self, child: str, parent: str, kind: str = "derived_from"):
        self.conn.execute("INSERT OR IGNORE INTO prov_edges VALUES (?,?,?)", (child, parent, kind))
        self.conn.commit()

    def parents(self, mem_id: str) -> list[str]:
        return [r["parent"] for r in
                self.conn.execute("SELECT parent FROM prov_edges WHERE child=?", (mem_id,))]

    def register_lineage(self, artifact_id, kind, subject, tenant):
        self.conn.execute("INSERT OR REPLACE INTO deletion_lineage VALUES (?,?,?,?)",
                          (artifact_id, kind, subject, tenant))
        self.conn.commit()

    def get_principal_key(self, tenant: str, principal_id: str) -> dict | None:
        r = self.conn.execute(
            "SELECT algorithm, public_key, created_at FROM principal_keys "
            "WHERE tenant=? AND principal_id=?",
            (tenant, principal_id),
        ).fetchone()
        if not r:
            return None
        return {
            "algorithm": r["algorithm"],
            "public_key": bytes(r["public_key"]),
            "created_at": r["created_at"],
        }

    def get_principal_keys(self, tenant: str, principal_id: str) -> list[dict]:
        keys = []
        primary = self.get_principal_key(tenant, principal_id)
        if primary is not None:
            keys.append({**primary, "key_id": "primary"})
        rows = self.conn.execute(
            "SELECT algorithm, public_key, key_id, created_at FROM principal_key_aliases "
            "WHERE tenant=? AND principal_id=? ORDER BY created_at ASC",
            (tenant, principal_id),
        ).fetchall()
        for r in rows:
            keys.append(
                {
                    "algorithm": r["algorithm"],
                    "public_key": bytes(r["public_key"]),
                    "key_id": r["key_id"],
                    "created_at": r["created_at"],
                }
            )
        return keys

    def iter_principal_keys(self, tenant: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT principal_id, algorithm, public_key, created_at FROM principal_keys "
            "WHERE tenant=? ORDER BY principal_id",
            (tenant,),
        ).fetchall()
        return [
            {
                "principal_id": r["principal_id"],
                "algorithm": r["algorithm"],
                "public_key": bytes(r["public_key"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def principal_key_alias_count(self, tenant: str, principal_id: str) -> int:
        return int(
            self.conn.execute(
                "SELECT COUNT(*) FROM principal_key_aliases "
                "WHERE tenant=? AND principal_id=?",
                (tenant, principal_id),
            ).fetchone()[0]
        )

    def register_principal_key(self, tenant: str, principal_id: str,
                               algorithm: str, public_key: bytes) -> bytes:
        existing = self.get_principal_key(tenant, principal_id)
        if existing:
            if existing["algorithm"] != algorithm or existing["public_key"] != public_key:
                raise ValueError(f"principal key already registered for {principal_id}")
            return existing["public_key"]
        self.conn.execute(
            "INSERT INTO principal_keys (tenant,principal_id,algorithm,public_key,created_at) "
            "VALUES (?,?,?,?,?)",
            (tenant, principal_id, algorithm, public_key, time.time()),
        )
        self.conn.commit()
        return public_key

    def register_principal_key_alias(self, tenant: str, principal_id: str,
                                     algorithm: str, public_key: bytes,
                                     key_id: str) -> bytes:
        self.conn.execute(
            "INSERT OR IGNORE INTO principal_key_aliases "
            "(tenant,principal_id,algorithm,public_key,key_id,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (tenant, principal_id, algorithm, public_key, key_id, time.time()),
        )
        self.conn.commit()
        return public_key

    def lineage_memory_ids(self, tenant: str, subject: str) -> list[str]:
        return [
            r["artifact_id"] for r in self.conn.execute(
                "SELECT artifact_id FROM deletion_lineage "
                "WHERE tenant=? AND subject=? AND artifact_kind='memory'",
                (tenant, subject),
            )
        ]

    def subject_ids(self, tenant: str, subject: str) -> list[str]:
        return [r["id"] for r in self.conn.execute(
            "SELECT id FROM memories WHERE tenant=? AND subject=?", (tenant, subject))]

    def descendants(self, seed_ids) -> set[str]:
        """All memories transitively derived from the seeds (via prov_edges).
        This is the deletion-lineage cascade: erasing a subject must also reach
        derived artifacts (summaries/answers) that contain the subject's data."""
        seen, frontier, out = set(seed_ids), list(seed_ids), set()
        while frontier:
            node = frontier.pop()
            for r in self.conn.execute("SELECT child FROM prov_edges WHERE parent=?", (node,)):
                c = r["child"]
                if c not in seen:
                    seen.add(c)
                    out.add(c)
                    frontier.append(c)
        return out

    def delete_subject(self, tenant: str, subject: str) -> int:
        ids = [r["id"] for r in self.conn.execute(
            "SELECT id FROM memories WHERE tenant=? AND subject=?", (tenant, subject))]
        self.conn.execute("DELETE FROM memories WHERE tenant=? AND subject=?", (tenant, subject))
        for i in ids:
            self.conn.execute("DELETE FROM prov_edges WHERE child=? OR parent=?", (i, i))
        self.conn.execute("DELETE FROM deletion_lineage WHERE tenant=? AND subject=?",
                          (tenant, subject))
        self.conn.commit()
        return len(ids)

    # -- keys (crypto-shred) -------------------------------------------- #
    def get_key(self, tenant, subject):
        r = self.conn.execute("SELECT dek,state FROM keys WHERE tenant=? AND subject=?",
                              (tenant, subject)).fetchone()
        return (None, None) if not r else (r["dek"], r["state"])

    def iter_keys(self, tenant) -> list[dict]:
        rows = self.conn.execute(
            "SELECT tenant, subject, dek, state FROM keys WHERE tenant=? ORDER BY subject",
            (tenant,),
        ).fetchall()
        return [
            {
                "tenant": r["tenant"],
                "subject": r["subject"],
                "dek": bytes(r["dek"]) if r["dek"] is not None else None,
                "state": r["state"],
            }
            for r in rows
        ]

    def put_key(self, tenant, subject, key: bytes):
        self.conn.execute("INSERT OR REPLACE INTO keys VALUES (?,?,?,?)",
                          (tenant, subject, key, "active"))
        self.conn.commit()

    def shred_key(self, tenant, subject):
        self.conn.execute("UPDATE keys SET dek=NULL, state='shredded' WHERE tenant=? AND subject=?",
                          (tenant, subject))
        self.conn.commit()

    # -- audit ----------------------------------------------------------- #
    def chain_id(self) -> str:
        row = self.conn.execute(
            "SELECT value FROM store_metadata WHERE key='chain_id'"
        ).fetchone()
        if row is None or not row["value"]:
            raise RuntimeError("Heartwood store is missing its chain_id")
        return str(row["value"])

    def audit_head(self) -> dict:
        row = self.conn.execute(
            "SELECT seq,row_hash,prev_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return {"seq": 0, "row_hash": "genesis", "prev_hash": None}
        return {
            "seq": int(row["seq"]),
            "row_hash": str(row["row_hash"]),
            "prev_hash": str(row["prev_hash"]),
        }

    def audit_row(self, seq: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM audit_log WHERE seq=?",
            (int(seq),),
        ).fetchone()
        return self._audit_row(row) if row is not None else None

    def audit_rows_for_target(self, target: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM audit_log WHERE target=? ORDER BY seq",
            (target,),
        ).fetchall()
        return [self._audit_row(row) for row in rows]

    def last_audit_hash(self):
        head = self.audit_head()
        return None if head["seq"] == 0 else head["row_hash"]

    def append_audit(self, ts, tenant, principal, action, target, body, prev_hash, row_hash):
        self.conn.execute(
            "INSERT INTO audit_log (ts,tenant,principal,action,target,body,prev_hash,row_hash) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (ts, tenant, principal, action, target, body, prev_hash, row_hash))
        self.conn.commit()

    def append_audit_atomic(self, tenant, principal, action, target, body) -> str:
        """Append one audit row while holding SQLite's write lock.

        Concurrent writers must not compute their row hash from the same
        previous hash. BEGIN IMMEDIATE serializes the read of the chain tail and
        the insert that extends it.
        """
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            transition = self.append_audit_in_transaction(
                tenant,
                principal,
                action,
                target,
                body,
            )
            self.conn.commit()
            return transition["row_hash"]
        except Exception:
            self.conn.rollback()
            raise

    def append_audit_in_transaction(self, tenant, principal, action, target, body) -> dict:
        """Append while the caller owns an active SQLite write transaction."""
        if not self.conn.in_transaction:
            raise RuntimeError("append_audit_in_transaction requires an active transaction")
        head = self.audit_head()
        ts = time.time()
        prev_hash = head["row_hash"]
        row_hash = hashlib.sha256((prev_hash + body + repr(ts)).encode()).hexdigest()
        cursor = self.conn.execute(
            "INSERT INTO audit_log (ts,tenant,principal,action,target,body,prev_hash,row_hash) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (ts, tenant, principal, action, target, body, prev_hash, row_hash),
        )
        return {
            "seq": int(cursor.lastrowid),
            "ts": ts,
            "prev_hash": prev_hash,
            "row_hash": row_hash,
        }

    def iter_audit(self):
        for r in self.conn.execute("SELECT * FROM audit_log ORDER BY seq"):
            yield self._audit_row(r)

    @staticmethod
    def _audit_row(row) -> dict:
        return {
            "seq": int(row["seq"]),
            "ts": row["ts"],
            "tenant": row["tenant"],
            "body": row["body"],
            "prev_hash": row["prev_hash"],
            "row_hash": row["row_hash"],
            "action": row["action"],
            "target": row["target"],
            "principal": row["principal"],
        }
