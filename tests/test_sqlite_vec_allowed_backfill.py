"""Denied nearest neighbors must not crowd allowed sqlite-vec candidates out."""
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


@pytest.mark.parametrize("denied_count", [0, 60, 300, 4200])
@pytest.mark.parametrize("n", [1, 5, 12])
def test_denied_neighbors_do_not_shrink_allowed_hits(index, denied_count, n):
    tenant = "tenant:backfill"
    query = np.array([0.0, 0.0], dtype=np.float32)
    for offset in range(denied_count):
        index.add(f"denied-{offset}", tenant, [0.0, 0.0])
    allowed = {f"allowed-{offset}" for offset in range(8)}
    for offset in range(8):
        index.add(f"allowed-{offset}", tenant, [float(offset + 1), 0.0])
    # A nearer row in another tenant must never be returned, even if allowed.
    index.add("other-tenant", "tenant:other", [0.0, 0.0])
    hits = index.search(tenant, query, n, allowed_ids=allowed | {"other-tenant"})
    assert [mid for mid, _ in hits] == [f"allowed-{offset}" for offset in range(min(n, 8))]
    assert [score for _, score in hits] == [-float(offset + 1) for offset in range(min(n, 8))]
    assert index.search(tenant, query, n, allowed_ids=set()) == []
    assert index.search("tenant:absent", query, n, allowed_ids=allowed) == []


def test_search_without_allow_list_keeps_nearest_tenant_hits(index):
    index.add("far", "tenant:backfill", [2.0, 0.0])
    index.add("near", "tenant:backfill", [1.0, 0.0])
    index.add("other", "tenant:other", [0.0, 0.0])
    assert index.search("tenant:backfill", [0.0, 0.0], 1) == [("near", -1.0)]
    assert index.search("tenant:backfill", [0.0, 0.0], 0) == []
