# Public sqlite-vec allowed-first handback

Status: BLOCKED_BEFORE_PR. No commit or PR was created.
Base: `d4463fb5c2821649c13adc3220681ea174f09cf9`.

## Scope conflict

The requested whole-class reference at `b0f3ca2` includes a lifecycle change beyond allowed-first search. Public `rebuild()` gates `DELETE FROM heartwood_vec` on `self._dim is not None`; the reference gates it on table existence instead. With a fresh index object and an existing vector table, the public guard skips deletion and the reference enters deletion. `_ensure()` also changes when `_dim` becomes established.

The applicable deletion-safety rule requires stopping when a flag being changed is consumed by a destructive path. This was discovered after the initial local port and tests. Public `_ensure()`, `rebuild()` and `remove()` now match main exactly; the deletion-related changes were backed out. No customer store was used. The table is a derived vector index; no claim of authoritative-memory loss is made.

The allowed-first search and two test files remain as uncommitted work. The caller comment matches the reference. Proceeding requires narrowing whole-class equality to permit preserving the public lifecycle methods, or separately resolving the deletion-gate change. No tasks or reviewers were dispatched.

## Adaptations and remaining differences

- Add the standard-library `json` import needed by allowed-list SQL parameters.
- Use `conn.commit()` instead of the unavailable public `Store.commit()`; omit the unused `self.store` reference.
- In the first-search test helper, use `index.conn.commit()` instead of `index.store.commit()`.
- Imports already use the public `heartwood` layout; no import rewrite was necessary. The backfill test file is unchanged from the reference.
- Preserve public `_ensure()` and `rebuild()` while stopped. These are additional scope differences, not claimed as approved layout adaptations.

## Current class diff

```diff
--- reference/SqliteVecIndex
+++ current/SqliteVecIndex
@@ -11,7 +11,6 @@
                 'sqlite-vec index requires the recall extra. Run: python -m pip install -e ".[recall,mcp]"'
             ) from exc
         self.conn = store.conn
-        self.store = store
         self.conn.enable_load_extension(True)
         sqlite_vec.load(self.conn)
         self.conn.enable_load_extension(False)
@@ -19,15 +18,13 @@
         self._dim = None
 
     def _ensure(self, dim):
-        if self._dim is not None and self.conn.execute(
-            "SELECT 1 FROM sqlite_master WHERE name='heartwood_vec'"
-        ).fetchone():
+        if self._dim is not None:
             return
+        self._dim = dim
         self.conn.execute(
             f"CREATE VIRTUAL TABLE IF NOT EXISTS heartwood_vec USING "
             f"vec0(memid TEXT PRIMARY KEY, tenant TEXT, emb float[{dim}])")
-        self._dim = dim
-        self.store.commit()
+        self.conn.commit()
 
     def add(self, mem_id, tenant, vector):
         if vector is None:
@@ -36,12 +33,12 @@
         self._ensure(len(v))
         self.conn.execute("INSERT OR REPLACE INTO heartwood_vec(memid,tenant,emb) VALUES (?,?,?)",
                           (mem_id, tenant, self._serialize(v.tolist())))
-        self.store.commit()
+        self.conn.commit()
 
     def remove(self, mem_id):
         if self._dim is not None:
             self.conn.execute("DELETE FROM heartwood_vec WHERE memid=?", (mem_id,))
-            self.store.commit()
+            self.conn.commit()
 
     def search(self, tenant, query_vec, n, allowed_ids=None):
         if self._dim is None or n <= 0 or (allowed_ids is not None and not allowed_ids):
@@ -82,8 +79,8 @@
         return [(memid, -float(distance)) for memid, distance in rows[:n]]   # similarity rank = -L2 distance
 
     def rebuild(self, store):
-        if self.conn.execute("SELECT 1 FROM sqlite_master WHERE name='heartwood_vec'").fetchone():
+        if self._dim is not None:
             self.conn.execute("DELETE FROM heartwood_vec")
-            self.store.commit()
+            self.conn.commit()
         for mid, tenant, emb in store.all_embeddings():
             self.add(mid, tenant, emb)```

## Verification receipts

These tests ran on the initial literal class port, BEFORE restoring public lifecycle methods. They are not certification of the final uncommitted tree.

```text
$ python3.11 -m ruff check .
All checks passed!
$ python3.11 -m pytest -q --tb=short tests/test_sqlite_vec_allowed_first.py -k denied_rows_are_never_scored
# Separate git-archive snapshot of public main plus the ported tests:
8 failed, 19 deselected in 0.45s
# All failures reached the expected Counter(scored) assertion; no setup failures.
$ python3.11 -m pytest -q -s tests/test_sqlite_vec_allowed_backfill.py tests/test_sqlite_vec_allowed_first.py
40 passed in 2.65s
$ bash scripts/check.sh
All checks passed!
415 passed, 2 skipped in 35.78s
```

After restoring lifecycle methods, AST-extracted source comparisons returned:

```text
Public _ensure, rebuild, remove methods match main: PASS
Allowed-first search matches approved reference: PASS
$ git diff --check
(no output; exit 0)
```

## Not verified

No final-tree suite rerun, package build, remote CI, PR-head equality, live deployment, or benchmark. No version bump, release, tag, merge, publication, credential operation, private runtime, or operator code was included.

## Lessons Learned

Compare a whole-class reference with the target before transplanting it: unrelated lifecycle differences may accompany a search fix and require a separate scope decision.
