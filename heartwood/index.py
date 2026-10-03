"""Pluggable vector index — the DERIVED, rebuildable dense-retrieval layer.

Two implementations behind one interface so the engine API is unchanged:
  - NumpyVectorIndex   : in-memory brute force. Default; zero deps; exact.
  - SqliteVecIndex     : sqlite-vec (asg017) — SQLite-native ANN whose metadata
                          column is the primitive for policy-pre-filtered search.

The index holds only vectors (derived); it is rebuildable from the authoritative
SQLite store at any time. Policy is still enforced by the caller before results
are returned (allowed_ids passed into search()).
"""
from __future__ import annotations

import json

import numpy as np


class VectorIndex:
    name = "abstract"

    def add(self, mem_id: str, tenant: str, vector) -> None: ...
    def remove(self, mem_id: str) -> None: ...
    def search(self, tenant: str, query_vec, n: int, allowed_ids=None) -> list[tuple[str, float]]: ...
    def rebuild(self, store) -> None: ...


class NumpyVectorIndex(VectorIndex):
    name = "numpy-bruteforce"

    def __init__(self):
        self._v: dict[str, tuple[str, np.ndarray]] = {}
        self._matrix_dirty = True
        self._matrix_ids: list[str] = []
        self._matrix_tenants: list[str] = []
        self._matrix: np.ndarray | None = None

    def add(self, mem_id, tenant, vector):
        if vector is not None:
            self._v[mem_id] = (tenant, np.asarray(vector, dtype=np.float32))
            self._matrix_dirty = True

    def remove(self, mem_id):
        if self._v.pop(mem_id, None) is not None:
            self._matrix_dirty = True

    def _refresh_matrix(self):
        if not self._matrix_dirty:
            return
        items = list(self._v.items())
        self._matrix_ids = [mem_id for mem_id, _ in items]
        self._matrix_tenants = [tenant for _, (tenant, _) in items]
        self._matrix = (
            np.vstack([vector for _, (_, vector) in items]).astype(np.float32, copy=False)
            if items else None
        )
        self._matrix_dirty = False

    def search(self, tenant, query_vec, n, allowed_ids=None):
        qv = np.asarray(query_vec, dtype=np.float32)
        self._refresh_matrix()
        if self._matrix is None:
            return []
        allowed = set(allowed_ids) if allowed_ids is not None else None
        selected = [
            offset for offset, mem_id in enumerate(self._matrix_ids)
            if self._matrix_tenants[offset] == tenant and (allowed is None or mem_id in allowed)
        ]
        if not selected:
            return []
        ids = [self._matrix_ids[offset] for offset in selected]
        sims = self._matrix[selected] @ qv
        order = np.argsort(-sims)[:n]
        return [(ids[k], float(sims[k])) for k in order]

    def rebuild(self, store):
        self._v.clear()
        for mid, tenant, emb in store.all_embeddings():
            self._v[mid] = (tenant, emb)
        self._matrix_dirty = True


class SqliteVecIndex(VectorIndex):
    name = "sqlite-vec"
    # Longest allow-list served by primary-key lookups; longer lists walk the table.
    POINT_LOOKUP_LIMIT = 256

    def __init__(self, store):
        try:
            import sqlite_vec  # raises if unavailable -> caller falls back in auto mode
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                'sqlite-vec index requires the recall extra. Run: python -m pip install -e ".[recall,mcp]"'
            ) from exc
        self.conn = store.conn
        self.conn.enable_load_extension(True)
        sqlite_vec.load(self.conn)
        self.conn.enable_load_extension(False)
        self._serialize = sqlite_vec.serialize_float32
        self._dim = None

    def _ensure(self, dim):
        if self._dim is not None:
            return
        self._dim = dim
        self.conn.execute(
            f"CREATE VIRTUAL TABLE IF NOT EXISTS heartwood_vec USING "
            f"vec0(memid TEXT PRIMARY KEY, tenant TEXT, emb float[{dim}])")
        self.conn.commit()

    def add(self, mem_id, tenant, vector):
        if vector is None:
            return
        v = np.asarray(vector, dtype=np.float32)
        self._ensure(len(v))
        self.conn.execute("INSERT OR REPLACE INTO heartwood_vec(memid,tenant,emb) VALUES (?,?,?)",
                          (mem_id, tenant, self._serialize(v.tolist())))
        self.conn.commit()

    def remove(self, mem_id):
        if self._dim is not None:
            self.conn.execute("DELETE FROM heartwood_vec WHERE memid=?", (mem_id,))
            self.conn.commit()

    def search(self, tenant, query_vec, n, allowed_ids=None):
        if self._dim is None or n <= 0 or (allowed_ids is not None and not allowed_ids):
            return []
        q = self._serialize(np.asarray(query_vec, dtype=np.float32).tolist())
        if allowed_ids is not None:
            # Both statements score only rows that pass the id and tenant tests.
            ids = list(set(allowed_ids))
            if len(ids) <= self.POINT_LOOKUP_LIMIT:
                # Few ids: one primary-key lookup each, so the work follows the
                # allow-list and not the size of the table.
                sql = ("SELECT v.memid, vec_distance_l2(v.emb, ?) AS distance "
                       "FROM json_each(?) AS a CROSS JOIN heartwood_vec AS v ON v.memid=a.value "
                       "WHERE v.tenant=? ORDER BY distance, v.memid LIMIT ?")
            else:
                # Many ids: one walk of the table costs less than a lookup per
                # id. Testing the id first skips the tenant read for other rows.
                sql = ("SELECT memid, vec_distance_l2(emb, ?) AS distance FROM heartwood_vec "
                       "WHERE memid IN (SELECT value FROM json_each(?)) AND tenant=? "
                       "ORDER BY distance, memid LIMIT ?")
            rows = self.conn.execute(sql, (q, json.dumps(ids), tenant, n)).fetchall()
        else:
            rows = []
            if n < 4096:
                # vec0 rejects a second KNN sort key. Materialize first, then
                # sort ties by id. One extra hit detects a tie at the cutoff.
                rows = self.conn.execute(
                    "WITH nearest AS MATERIALIZED ("
                    "SELECT memid, distance FROM heartwood_vec WHERE tenant=? AND emb MATCH ? AND k=?) "
                    "SELECT memid, distance FROM nearest ORDER BY distance, memid",
                    (tenant, q, n + 1)).fetchall()
            if n >= 4096 or (len(rows) > n and rows[n - 1][1] == rows[n][1]):
                # KNN may omit a smaller id at a tied cutoff. The exact scan
                # also handles requests beyond vec0's 4096 KNN limit.
                rows = self.conn.execute(
                    "SELECT memid, vec_distance_l2(emb, ?) AS distance FROM heartwood_vec "
                    "WHERE tenant=? ORDER BY distance, memid LIMIT ?", (q, tenant, n)).fetchall()
        return [(memid, -float(distance)) for memid, distance in rows[:n]]   # similarity rank = -L2 distance

    def rebuild(self, store):
        if self._dim is not None:
            self.conn.execute("DELETE FROM heartwood_vec")
            self.conn.commit()
        for mid, tenant, emb in store.all_embeddings():
            self.add(mid, tenant, emb)


def make_index(spec, store) -> VectorIndex:
    """spec: a VectorIndex instance, or 'numpy' | 'sqlite-vec' | 'auto'."""
    if isinstance(spec, VectorIndex):
        return spec
    if spec == "sqlite-vec":
        return SqliteVecIndex(store)
    if spec == "auto":
        try:
            return SqliteVecIndex(store)
        except Exception:
            return NumpyVectorIndex()
    return NumpyVectorIndex()
