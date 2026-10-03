"""Allowed sqlite-vec work and deterministic ranks must ignore denied rows."""
from collections import Counter

import numpy as np
import pytest

from heartwood.index import SqliteVecIndex
from heartwood.store import Store


@pytest.fixture
def index(tmp_path):
    pytest.importorskip("sqlite_vec")
    store = Store(str(tmp_path / "vectors.sqlite"))
    index = SqliteVecIndex(store)
    try:
        yield index
    finally:
        store.close()


def add_rows(index, rows):
    index._ensure(len(rows[0][2]))
    index.conn.executemany(
        "INSERT INTO heartwood_vec(memid,tenant,emb) VALUES (?,?,?)",
        [(mid, tenant, index._serialize(vector)) for mid, tenant, vector in rows])
    index.conn.commit()


@pytest.mark.parametrize("absent_ids", [0, 600])
@pytest.mark.parametrize("denied_count", [0, 300, 4200, 20000])
def test_denied_rows_are_never_scored(index, denied_count, absent_ids):
    allowed_vectors = {f"allowed-{i}": [float(i + 1), 0.0] for i in range(8)}
    add_rows(index, [
        (mid, "tenant:a", vector) for mid, vector in allowed_vectors.items()
    ] + [(f"denied-{i}", "tenant:a", [0.0, 0.0]) for i in range(denied_count)] + [
        ("other", "tenant:b", [0.0, 0.0])])
    # 600 absent ids take the allow-list past the 256-id lookup limit, onto the table walk.
    allowed = set(allowed_vectors) | {"other", "missing"} | {f"absent-{i}" for i in range(absent_ids)}
    scored = []

    def distance(vector, query):
        values = np.frombuffer(vector, dtype=np.float32)
        scored.append(tuple(values))
        return float(np.linalg.norm(values - np.frombuffer(query, dtype=np.float32)))

    # Count actual scalar evaluations, not returned rows. On the base the KNN
    # either bypasses this scalar entirely or the fallback scores denied rows.
    index.conn.create_function("vec_distance_l2", 2, distance, deterministic=True)
    statements = []
    index.conn.set_trace_callback(statements.append)
    hits = index.search("tenant:a", [0.0, 0.0], 50, allowed_ids=allowed)
    index.conn.set_trace_callback(None)
    assert Counter(scored) == Counter(tuple(v) for v in allowed_vectors.values())
    assert hits == [(f"allowed-{i}", -float(i + 1)) for i in range(8)]
    assert len([sql for sql in statements if not sql.startswith("--")]) == 1
    assert "MATCH" not in statements[0]
    assert ("CROSS JOIN" in statements[0]) == (len(allowed) <= 256)
    path = "lookups" if "CROSS JOIN" in statements[0] else "walk"
    print(f"denied={denied_count} allowed=8 absent={absent_ids} path={path} scored={len(scored)} "
          f"statements={len(statements)} cross_tenant=0")


def test_allowed_query_uses_primary_key_lookups(index):
    add_rows(index, [("allowed", "tenant:a", [1.0, 0.0]),
                     ("denied", "tenant:a", [0.0, 0.0])])
    sql = []
    index.conn.set_trace_callback(sql.append)
    assert index.search("tenant:a", [0.0, 0.0], 1, {"allowed"}) == [("allowed", -1.0)]
    index.conn.set_trace_callback(None)
    plan = [tuple(row) for row in index.conn.execute("EXPLAIN QUERY PLAN " + sql[0])]
    # vec0's strategy 7 is a point lookup, and 2! binds the TEXT primary key.
    assert any("VIRTUAL TABLE INDEX 7:2!" in row[-1] for row in plan), plan
    assert "json_each" in sql[0], plan
    print("allow_list_query_plan:", plan)


@pytest.mark.parametrize("allowed_ids", [None, set(), {"one"}])
def test_zero_limit_returns_before_serializing_or_querying(index, monkeypatch, allowed_ids):
    index.add("one", "tenant:a", [1.0, 0.0])

    def unexpected_serialization(_):
        pytest.fail("zero-limit search must return before serializing or querying")

    monkeypatch.setattr(index, "_serialize", unexpected_serialization)
    statements = []
    index.conn.set_trace_callback(statements.append)
    assert index.search("tenant:a", [0.0, 0.0], 0, allowed_ids) == []
    assert statements == []


def test_empty_allow_list_does_no_database_work(index):
    index.add("one", "tenant:a", [1.0, 0.0])
    statements = []
    index.conn.set_trace_callback(statements.append)
    assert index.search("tenant:a", [0.0, 0.0], 50, set()) == []
    assert statements == []


@pytest.mark.parametrize("n", [1, 5, 50, 4095, 4096, 5000])
@pytest.mark.parametrize("use_allow_list", [False, True])
def test_exact_ranking_including_ties_and_tenant_isolation(index, n, use_allow_list):
    rng = np.random.default_rng(107)
    vectors = rng.integers(-3, 4, size=(4300, 3)).astype(np.float32)
    ids = [f"row-{i:05}" for i in range(len(vectors))]
    # Insert backwards: an insertion-order tie-break cannot pass this oracle.
    add_rows(index, [(ids[i], "tenant:a", vectors[i].tolist()) for i in reversed(range(len(ids)))] + [
        ("other", "tenant:b", [0.0, 0.0, 0.0])])
    allowed = set(ids[::2]) | {"other", "missing"} if use_allow_list else None
    oracle = sorted(
        [(mid, float(np.linalg.norm(vector))) for mid, vector in zip(ids, vectors)
         if allowed is None or mid in allowed], key=lambda hit: (hit[1], hit[0]))[:n]
    hits = index.search("tenant:a", [0.0, 0.0, 0.0], n, allowed)
    assert [mid for mid, _ in hits] == [mid for mid, _ in oracle]
    assert [score for _, score in hits] == pytest.approx([-distance for _, distance in oracle], abs=1e-6)
    assert all(mid != "other" for mid, _ in hits)


def test_unfiltered_knn_kept_for_distinct_distances(index):
    add_rows(index, [(f"row-{i}", "tenant:a", [float(i), 0.0]) for i in range(10)])
    sql = []
    index.conn.set_trace_callback(sql.append)
    assert index.search("tenant:a", [0.0, 0.0], 3) == [(f"row-{i}", -float(i)) for i in range(3)]
    index.conn.set_trace_callback(None)
    assert len([statement for statement in sql if not statement.startswith("--")]) == 1
    assert "MATCH" in sql[0]


def test_allowed_ids_handle_duplicates_escaped_ids_and_large_lists(index):
    ids = ["quote'", 'double"', "line\nbreak", "é", "comma,", "question?"]
    add_rows(index, [(mid, "tenant:a", [1.0, 0.0]) for mid in reversed(ids)])
    allowed = ids + ids + [f"absent-{i}" for i in range(40000)]
    assert index.search("tenant:a", [0.0, 0.0], 50, allowed) == [(mid, -1.0) for mid in sorted(ids)]
    assert index.search("tenant:a", [0.0, 0.0], 50, ids + ids) == [(mid, -1.0) for mid in sorted(ids)]
    assert index.search("tenant:absent", [0.0, 0.0], 50, allowed) == []
