"""Default-recall validity-window regressions.

Recall enforces `valid_from` / `valid_until` on every query. `effective_at` only
moves the reference time; it is not the switch that turns the filter on.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.retrieval import _hashing_embed, tokenize  # noqa: E402


TENANT = "tenant:recall-validity"

NOW = datetime.now(timezone.utc)
PAST = (NOW - timedelta(days=1)).isoformat()
FUTURE = (NOW + timedelta(days=1)).isoformat()


def _rerank(query, texts):
    q = set(tokenize(query))
    scores = np.zeros(len(texts), dtype=np.float32)
    for index, text in enumerate(texts):
        d = set(tokenize(text))
        scores[index] = len(q & d) / (len(q | d) or 1)
    return scores


def _db() -> Heartwood:
    return Heartwood(
        path=":memory:",
        tenant=TENANT,
        embedder=(_hashing_embed, "test-hashing-embedder"),
        reranker=(_rerank, "test-lexical-reranker"),
    )


def _principal() -> Principal:
    return Principal(id="agent:test", tenant=TENANT, clearance="internal")


def _ids(recalled) -> set[str]:
    return {result["id"] for result in recalled["results"]}


def _seed(db) -> tuple[str, str]:
    """Return (live_id, expired_id) for the same cue."""
    live = db.remember(
        "Gamma retention rule: the live record is current.",
        subject="policy:gamma",
        created_by="agent:test",
    )
    expired = db.remember(
        "Gamma retention rule: the expired record is retired.",
        subject="policy:gamma",
        created_by="agent:test",
        valid_until=PAST,
    )
    return live, expired


def test_default_recall_excludes_expired_memory():
    """The literal production query shape — no filters argument at all."""
    db = _db()
    live, expired = _seed(db)

    # Positional/kwarg shape used by the warm-recall service and every team caller.
    no_filters = db.recall("gamma retention rule", principal=_principal(), k=10, topc=10)
    assert expired not in _ids(no_filters), "expired record leaked into default recall"
    assert live in _ids(no_filters), "validity filter must not drop the live record"

    # `filters={}` and `filters=None` are the other two filter-less call shapes.
    empty_filters = db.recall(
        "gamma retention rule", principal=_principal(), filters={}, k=10, topc=10
    )
    null_filters = db.recall(
        "gamma retention rule", principal=_principal(), filters=None, k=10, topc=10
    )
    assert _ids(empty_filters) == _ids(no_filters) == _ids(null_filters) == {live}


def test_default_recall_excludes_not_yet_valid_memory():
    db = _db()
    live, _expired = _seed(db)
    scheduled = db.remember(
        "Gamma retention rule: the scheduled record is not live yet.",
        subject="policy:gamma",
        created_by="agent:test",
        valid_from=FUTURE,
    )

    default = db.recall("gamma retention rule", principal=_principal(), k=10, topc=10)
    assert scheduled not in _ids(default)
    assert _ids(default) == {live}


def test_effective_at_moves_the_reference_time_without_disabling_the_filter():
    db = _db()
    live, expired = _seed(db)

    # A reference time before expiry still sees the record: back-dated recall works.
    before_expiry = (NOW - timedelta(days=2)).isoformat()
    historical = db.recall(
        "gamma retention rule",
        principal=_principal(),
        filters={"effective_at": before_expiry},
        k=10,
        topc=10,
    )
    assert expired in _ids(historical)

    # A reference time after expiry excludes it — the pre-existing behaviour.
    current = db.recall(
        "gamma retention rule",
        principal=_principal(),
        filters={"effective_at": NOW.isoformat()},
        k=10,
        topc=10,
    )
    assert expired not in _ids(current)
    assert live in _ids(current)


def test_include_expired_is_the_explicit_opt_out():
    db = _db()
    live, expired = _seed(db)

    audit_view = db.recall(
        "gamma retention rule",
        principal=_principal(),
        filters={"include_expired": True},
        k=10,
        topc=10,
    )
    assert _ids(audit_view) == {live, expired}


def test_unparseable_effective_at_does_not_disable_validity_filtering():
    """A malformed reference time falls back to now instead of failing open."""
    db = _db()
    live, expired = _seed(db)

    for bad in ("", "not-a-timestamp", None):
        recalled = db.recall(
            "gamma retention rule",
            principal=_principal(),
            filters={"effective_at": bad},
            k=10,
            topc=10,
        )
        assert expired not in _ids(recalled), f"validity filter failed open for {bad!r}"
        assert live in _ids(recalled)


def test_explain_recall_reports_the_resolved_validity_reference():
    db = _db()
    _live, _expired = _seed(db)

    default = db.recall("gamma retention rule", principal=_principal(), k=10, topc=10)
    explained = db.explain_recall(default["recall_id"])
    assert explained["validity_enforced"] is True
    assert explained["effective_at"], "resolved reference time must be reported"

    opted_out = db.recall(
        "gamma retention rule",
        principal=_principal(),
        filters={"include_expired": True},
        k=10,
        topc=10,
    )
    assert db.explain_recall(opted_out["recall_id"])["validity_enforced"] is False
