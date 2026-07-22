"""Audited recall-visibility verbs: `set_indexed` and `expire`.

`indexed` and `valid_until` are the two columns that decide whether a stored
record still answers "what is true right now?". Before these verbs existed the
only way to move either one was a direct UPDATE, so a record could vanish from
every recall with nothing on the tamper-evident audit log. These tests pin the
audited paths, their fail-closed input handling, and their reversibility.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.retrieval import _hashing_embed, tokenize  # noqa: E402
from heartwood.review import ReviewState  # noqa: E402


TENANT = "tenant:visibility-verbs"
ACTOR = "agent:retirement-operator"

# Whole seconds: an epoch float round-trips exactly, so the normalization test
# below compares instants rather than float rounding.
NOW = datetime.now(timezone.utc).replace(microsecond=0)
PAST = (NOW - timedelta(days=1)).isoformat()
FUTURE = (NOW + timedelta(days=1)).isoformat()

CUE = "delta escalation runbook"


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


def _recall(db, **filters) -> set[str]:
    kwargs = {"filters": filters} if filters else {}
    return _ids(db.recall(CUE, principal=_principal(), k=10, topc=10, **kwargs))


def _seed(db) -> tuple[str, str]:
    """Return (keeper_id, target_id) — two live records answering the same cue."""
    keeper = db.remember(
        "Delta escalation runbook: the record that stays current.",
        subject="policy:delta",
        created_by="agent:test",
    )
    target = db.remember(
        "Delta escalation runbook: the record under retirement.",
        subject="policy:delta",
        created_by="agent:test",
    )
    return keeper, target


def _events(db, action: str) -> list[dict]:
    import json

    return [
        json.loads(row["body"])
        for row in db.store.iter_audit()
        if row["action"] == action
    ]


def _expect_raises(exc_type, fn, message: str):
    try:
        fn()
    except exc_type:
        return
    raise AssertionError(message)


# -- set_indexed ---------------------------------------------------------- #

def test_set_indexed_retires_from_recall_and_writes_an_index_state_event():
    db = _db()
    keeper, target = _seed(db)
    assert _recall(db) == {keeper, target}

    result = db.set_indexed(target, False, actor=ACTOR, reason="owner-authorized retirement")
    assert result == {"id": target, "from": True, "to": False}
    assert db.store.get_meta(target)["indexed"] is False
    assert _recall(db) == {keeper}

    events = _events(db, "index_state")
    assert len(events) == 1
    assert events[0]["principal"] == ACTOR
    assert events[0]["target"] == target
    assert events[0]["detail"] == {
        "from": True,
        "to": False,
        "reason": "owner-authorized retirement",
    }
    assert db.verify_audit() is True


def test_no_recall_filter_reaches_an_unindexed_row():
    """`indexed = 0` is the hardest gate — unlike expiry and review state it has
    no opt-in, which is why flipping it has to be audited."""
    db = _db()
    keeper, target = _seed(db)
    db.set_indexed(target, False, actor=ACTOR)

    every_opt_in = _recall(
        db,
        include_expired=True,
        include_review_states=[state.value for state in ReviewState],
        include_contextual_aux=True,
        effective_at=PAST,
    )
    assert target not in every_opt_in
    assert every_opt_in == {keeper}


def test_set_indexed_is_reversible_with_content_and_provenance_intact():
    db = _db()
    _keeper, target = _seed(db)
    before = db.store.get_meta(target)
    content_before = db.read_content(target)

    db.set_indexed(target, False, actor=ACTOR, reason="retire")
    reinstated = db.set_indexed(target, True, actor=ACTOR, reason="reinstate")

    assert reinstated == {"id": target, "from": False, "to": True}
    assert target in _recall(db)
    after = db.store.get_meta(target)
    assert after["content_hash"] == before["content_hash"]
    assert after["producer_sig"] == before["producer_sig"]
    assert after["sig_valid_cached"] is before["sig_valid_cached"]
    assert db.read_content(target) == content_before
    recalled = db.recall(CUE, principal=_principal(), k=10, topc=10)["results"]
    assert next(r for r in recalled if r["id"] == target)["content"] == content_before


def test_set_indexed_rejects_non_boolean_input_without_touching_the_row():
    """A truthy string must not silently reinstate a retired record."""
    db = _db()
    _keeper, target = _seed(db)
    db.set_indexed(target, False, actor=ACTOR)

    for bad in ("false", "0", 2, -1, None, 1.0):
        _expect_raises(
            TypeError,
            lambda bad=bad: db.set_indexed(target, bad, actor=ACTOR),
            f"set_indexed should reject non-boolean {bad!r}",
        )
    assert db.store.get_meta(target)["indexed"] is False
    assert len(_events(db, "index_state")) == 1, "a rejected input must not be audited"


def test_set_indexed_rejects_unknown_memory_id():
    db = _db()
    _expect_raises(
        KeyError,
        lambda: db.set_indexed("mem_does_not_exist", False, actor=ACTOR),
        "set_indexed should reject an unknown memory id",
    )
    assert _events(db, "index_state") == []


def test_set_indexed_reasserting_current_state_is_an_audited_no_op():
    """The property that lets an out-of-band change be recorded after the fact."""
    db = _db()
    _keeper, target = _seed(db)
    db.set_indexed(target, False, actor=ACTOR, reason="first")

    again = db.set_indexed(target, False, actor=ACTOR, reason="recording a prior raw UPDATE")
    assert again == {"id": target, "from": False, "to": False}
    assert db.store.get_meta(target)["indexed"] is False
    reasons = [event["detail"]["reason"] for event in _events(db, "index_state")]
    assert reasons == ["first", "recording a prior raw UPDATE"]
    assert db.verify_audit() is True


def test_set_indexed_can_reinstate_a_legacy_row_whose_indexed_column_is_null():
    """A NULL `indexed` reads as False, so the swap has to match it as False.

    Otherwise the compare-and-swap never matches and the verb reports an
    unresolvable "expected False, got False" — sending the operator back to the
    raw UPDATE this verb exists to replace.
    """
    db = _db()
    keeper, target = _seed(db)
    db.store.conn.execute("UPDATE memories SET indexed=NULL WHERE id=?", (target,))
    db.store.conn.commit()
    assert db.store.get_meta(target)["indexed"] is False
    assert _recall(db) == {keeper}

    assert db.set_indexed(target, True, actor=ACTOR, reason="repair") == {
        "id": target, "from": False, "to": True,
    }
    assert _recall(db) == {keeper, target}


def test_set_indexed_surfaces_a_lost_compare_and_swap():
    db = _db()
    _keeper, target = _seed(db)
    original_update = db.store.update_indexed

    def stale_update(mem_id, indexed, *, expected_from):
        return False

    db.store.update_indexed = stale_update
    try:
        _expect_raises(
            RuntimeError,
            lambda: db.set_indexed(target, False, actor=ACTOR),
            "set_indexed should surface a concurrent-update CAS miss",
        )
    finally:
        db.store.update_indexed = original_update
    assert _events(db, "index_state") == []


# -- expire --------------------------------------------------------------- #

def test_expire_retires_from_default_recall_and_writes_an_expire_event():
    db = _db()
    keeper, target = _seed(db)
    assert db.store.get_meta(target)["valid_until"] is None

    result = db.expire(target, NOW, actor=ACTOR, reason="superseded by the 07-22 snapshot")
    assert result["id"] == target
    assert result["from"] is None
    assert result["valid_now"] is False
    assert result["to"] == NOW.isoformat()

    assert _recall(db) == {keeper}
    assert _recall(db, include_expired=True) == {keeper, target}
    assert _recall(db, effective_at=PAST) == {keeper, target}

    events = _events(db, "expire")
    assert len(events) == 1
    assert events[0]["principal"] == ACTOR
    assert events[0]["target"] == target
    assert events[0]["detail"] == {
        "from": None,
        "to": NOW.isoformat(),
        "reason": "superseded by the 07-22 snapshot",
    }
    assert db.verify_audit() is True


def test_expire_normalizes_the_instant_so_recall_can_parse_it():
    """Epoch seconds and naive timestamps are stored as ISO-8601 UTC.

    Recall reads `valid_until` back out of a TEXT column and parses it with
    `datetime.fromisoformat`; an un-normalized epoch would be unparseable there
    and read as "no expiry".
    """
    db = _db()
    for supplied in (NOW.timestamp(), NOW.replace(tzinfo=None).isoformat(),
                     NOW.isoformat().replace("+00:00", "Z")):
        _keeper, target = _seed(db)
        stored = db.expire(target, supplied, actor=ACTOR)["to"]
        assert stored == db.store.get_meta(target)["valid_until"]
        assert datetime.fromisoformat(stored) == NOW, f"{supplied!r} normalized to {stored!r}"
        assert target not in _recall(db), f"{supplied!r} failed open"


def test_an_unnormalized_epoch_written_directly_would_fail_open():
    """Positive control: the normalization above is load-bearing, not cosmetic."""
    db = _db()
    _keeper, target = _seed(db)
    db.store.conn.execute(
        "UPDATE memories SET valid_until=? WHERE id=?", (str(NOW.timestamp()), target)
    )
    db.store.conn.commit()
    assert db.store.get_meta(target)["valid_until"] == str(NOW.timestamp())
    assert target in _recall(db), "expected the raw-epoch write to fail open"


def test_expire_rejects_an_unparseable_instant_rather_than_failing_open():
    db = _db()
    _keeper, target = _seed(db)
    db.expire(target, NOW, actor=ACTOR)
    retired = db.store.get_meta(target)["valid_until"]

    for bad in ("", "not-a-timestamp", "2026-13-45", object()):
        _expect_raises(
            ValueError,
            lambda bad=bad: db.expire(target, bad, actor=ACTOR),
            f"expire should reject unparseable instant {bad!r}",
        )
    assert db.store.get_meta(target)["valid_until"] == retired
    assert target not in _recall(db), "a rejected expire must not lift the window"
    assert len(_events(db, "expire")) == 1


def test_expire_none_lifts_the_window_and_reinstates_the_record():
    db = _db()
    keeper, target = _seed(db)
    db.expire(target, PAST, actor=ACTOR, reason="time-boxed")
    assert _recall(db) == {keeper}

    lifted = db.expire(target, None, actor=ACTOR, reason="retirement rescinded")
    assert lifted["from"] == datetime.fromisoformat(PAST).astimezone(timezone.utc).isoformat()
    assert lifted["to"] is None
    assert lifted["valid_now"] is True
    assert db.store.get_meta(target)["valid_until"] is None
    assert _recall(db) == {keeper, target}
    assert [event["detail"]["to"] for event in _events(db, "expire")][-1] is None


def test_expire_can_schedule_a_future_retirement():
    db = _db()
    keeper, target = _seed(db)
    scheduled = db.expire(target, FUTURE, actor=ACTOR, reason="expires tomorrow")

    assert scheduled["valid_now"] is True
    assert _recall(db) == {keeper, target}
    assert _recall(db, effective_at=FUTURE) == {keeper}


def test_expire_reasserting_the_current_window_is_an_audited_no_op():
    """Same after-the-fact recording property as `set_indexed`."""
    db = _db()
    _keeper, target = _seed(db)
    db.expire(target, PAST, actor=ACTOR, reason="first")
    stored = db.store.get_meta(target)["valid_until"]

    again = db.expire(target, PAST, actor=ACTOR, reason="recording a prior raw UPDATE")
    assert again["from"] == stored
    assert again["to"] == stored
    assert db.store.get_meta(target)["valid_until"] == stored
    reasons = [event["detail"]["reason"] for event in _events(db, "expire")]
    assert reasons == ["first", "recording a prior raw UPDATE"]
    assert db.verify_audit() is True


def test_expire_rejects_unknown_memory_id():
    db = _db()
    _expect_raises(
        KeyError,
        lambda: db.expire("mem_does_not_exist", NOW, actor=ACTOR),
        "expire should reject an unknown memory id",
    )
    assert _events(db, "expire") == []


def test_expire_surfaces_a_lost_compare_and_swap():
    db = _db()
    _keeper, target = _seed(db)
    original_update = db.store.update_valid_until

    def stale_update(mem_id, valid_until, *, expected_from):
        return False

    db.store.update_valid_until = stale_update
    try:
        _expect_raises(
            RuntimeError,
            lambda: db.expire(target, NOW, actor=ACTOR),
            "expire should surface a concurrent-update CAS miss",
        )
    finally:
        db.store.update_valid_until = original_update
    assert _events(db, "expire") == []


def test_both_verbs_keep_the_audit_chain_verifiable_together():
    db = _db()
    _keeper, target = _seed(db)
    db.expire(target, NOW, actor=ACTOR, reason="time-boxed")
    db.set_indexed(target, False, actor=ACTOR, reason="fully retired")
    db.set_indexed(target, True, actor=ACTOR, reason="reinstated")
    db.expire(target, None, actor=ACTOR, reason="window lifted")

    actions = [row["action"] for row in db.store.iter_audit()]
    assert actions.count("expire") == 2
    assert actions.count("index_state") == 2
    assert db.verify_audit() is True
    assert target in _recall(db)
