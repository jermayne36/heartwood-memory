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
        if self._dim is None:
            return []
        q = self._serialize(np.asarray(query_vec, dtype=np.float32).tolist())
        # tenant filter is a native vec0 metadata constraint; over-fetch then
        # apply the fine-grained policy allow-list in Python.
        k = n if allowed_ids is None else max(n * 5, n + 50)
        rows = self.conn.execute(
            "SELECT memid, distance FROM heartwood_vec WHERE tenant=? AND emb MATCH ? AND k=? "
            "ORDER BY distance", (tenant, q, k)).fetchall()
        out = []
        for memid, distance in rows:
            if allowed_ids is not None and memid not in allowed_ids:
                continue
            out.append((memid, -float(distance)))   # similarity rank = -L2 distance
            if len(out) >= n:
                break
        return out

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
