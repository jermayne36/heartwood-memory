# Public sqlite-vec allowed-first search

Prepared 2026-10-03 PDT. Local verification passed; hosted CI is recorded on the pull request.
Public base: `d4463fb5c2821649c13adc3220681ea174f09cf9`.

## Behavior

Allowed searches evaluate distances only for matching IDs in the requested tenant. Up to 256 unique IDs use primary-key lookups; larger lists use a filtered table walk. Empty allow-lists and nonpositive limits return immediately. Ranking breaks distance ties by memory ID. Unrestricted searches keep KNN, with an exact fallback for tied cutoffs or requests at/above the 4096 KNN limit.

Only `SqliteVecIndex.search`, its `json` import, two test files, and the dense-search comment in `heartwood/client.py` changed. The lifecycle methods (`__init__`, `_ensure`, `add`, `remove`, `rebuild`) remain byte-identical to public main. No version, dependencies, release workflow, or persistence behavior changed.

## Reference adaptations

The supplied search reference is `b0f3ca2`.

- Replace `self.POINT_LOOKUP_LIMIT` with its exact value `256` inside `search`, keeping the change confined to the method and import. No class attribute or lifecycle change is required.
- In the first-search test helper, commit via `index.conn.commit()` because the public index has no `store` attribute. Replace its threshold attribute reference with `256` and update the associated comment.
- Both test files already use public imports. The backfill test is byte-identical to the reference.
- The three-line client comment matches the supplied reference verbatim.

### Search-body diff

```diff
--- reference/search
+++ public/search
@@ -5,7 +5,7 @@
         if allowed_ids is not None:
             # Both statements score only rows that pass the id and tenant tests.
             ids = list(set(allowed_ids))
-            if len(ids) <= self.POINT_LOOKUP_LIMIT:
+            if len(ids) <= 256:
                 # Few ids: one primary-key lookup each, so the work follows the
                 # allow-list and not the size of the table.
                 sql = ("SELECT v.memid, vec_distance_l2(v.emb, ?) AS distance "
```

### Lifecycle-method diff against public main

```diff
```

AST was used only to locate source spans; the comparison checks exact original source bytes, not normalized ASTs. All five methods match. Whole-class parity is deliberately not asserted because lifecycle behavior is outside this port.

## Verification

Local environment: Python 3.11.15, SQLite 3.53.1, sqlite-vec 0.1.9, NumPy 2.4.6, pytest 8.4.2, Ruff 0.15.13.

```text
$ python3.11 -m ruff check .
All checks passed!

$ python3.11 -m pytest -q --tb=short tests/test_sqlite_vec_allowed_first.py -k denied_rows_are_never_scored
# Separate git-archive snapshot of public main, with the ported test copied in:
8 failed, 19 deselected in 0.49s
# All eight failures reach Counter(scored), not setup/import failures.

$ python3.11 -m pytest -q -s tests/test_sqlite_vec_allowed_backfill.py tests/test_sqlite_vec_allowed_first.py
40 passed in 2.67s

$ bash scripts/check.sh
All checks passed!
415 passed, 2 skipped in 36.79s

$ python3.11 -m build --wheel --sdist --outdir /tmp/public-vec-port-dist
Successfully built heartwood_memory-0.2.8-py3-none-any.whl and heartwood_memory-0.2.8.tar.gz

$ python3.11 -m twine check /tmp/public-vec-port-dist/heartwood_memory-*.whl /tmp/public-vec-port-dist/heartwood_memory-*.tar.gz
Checking /tmp/public-vec-port-dist/heartwood_memory-0.2.8-py3-none-any.whl: PASSED
Checking /tmp/public-vec-port-dist/heartwood_memory-0.2.8.tar.gz: PASSED

$ git diff --check
(no output; exit 0)
```

The scalar-distance spy observes exactly eight allowed vector evaluations for every combination of 0/300/4200/20000 denied rows and 0/600 absent IDs. Both lookup and walk paths are covered, including a cross-tenant ID in the allow-list. The SQL assertion counts one top-level statement; sqlite-vec internal trace entries vary with the path and corpus size. The baseline KNN bypasses the scalar spy and fails the regression contract; zero scalar calls on that baseline are not evidence that KNN did no distance calculations.

## Verification limits

No timing benchmark or constant-time claim: the large-list path still traverses the table, so denied-row count can affect traversal cost even when no denied vector is scored. Opt-in real-model tests remain skipped by the standard gate. No release, deployment, or published-package verification is part of this change. Hosted CI must be checked on the exact PR head before merge.

## Lessons Learned

Compare method boundaries before porting a class: unrelated lifecycle differences must not accompany a search fix. Snapshot-based regression checks preserve the working tree and the baseline source.
