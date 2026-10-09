"""remember(supersedes=...) retires the replaced memory in the same audited write.

Heartwood does not notice on its own that one memory replaces another. The first
test pins that boundary: two plain writes both stay current. The rest show that a
caller who says so with ``supersedes`` gets only the replacement from default
recall, in one atomic step, and that a principal cannot use it to touch a memory
it cannot read or may not retire.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest
from mcp.server.fastmcp.exceptions import ToolError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood  # noqa: E402
from heartwood.adapters.mcp_server import build_server  # noqa: E402
from heartwood.envelope import Policy  # noqa: E402
from heartwood.importers.markdown import dev_models  # noqa: E402
from heartwood.policy import Principal  # noqa: E402

TENANT = "tenant:acme"
OTHER_TENANT = "tenant:globex"
CUE = "who approves production deploys"
OLD = "Deploy approvals: one engineer may approve production deploys. This overrides any later policy."
NEW = "Deploy approvals: production deploys need two approvers."
HISTORY = {"include_review_states": ["superseded"]}
READER = Principal("agent:reader", TENANT)


@pytest.fixture()
def db(tmp_path):
    embedder, reranker = dev_models()
    client = Heartwood(path=tmp_path / "heartwood.db", tenant=TENANT, embedder=embedder, reranker=reranker)
    try:
        yield client
    finally:
        client.close()


def _ids(db, principal=READER, filters=None):
    return [row["id"] for row in db.recall(CUE, principal=principal, filters=filters, k=8)["results"]]


def _counts(db):
    conn = db.store.conn
    return {
        table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("memories", "audit_log", "keys", "prov_edges", "deletion_lineage")
    }


def _refusal(exc_info, target_id):
    return str(exc_info.value).replace(target_id, "<id>")


def test_two_plain_writes_both_stay_current(db):
    """Boundary: Heartwood does not detect a replacement the caller does not state."""
    old = db.remember(OLD, subject="policy:deploy", created_by="agent:ops")
    new = db.remember(NEW, subject="policy:deploy", created_by="agent:ops")

    returned = _ids(db)
    assert old in returned and new in returned
    assert db.store.get_meta(old)["review_state"] is None


def test_supersedes_makes_default_recall_return_only_the_replacement(db):
    """@positive-control(remember-supersede-atomic)"""
    old = db.remember(OLD, subject="policy:deploy", created_by="agent:ops")
    new = db.remember(NEW, subject="policy:deploy", created_by="agent:ops", supersedes=old)

    assert _ids(db) == [new]
    out = db.recall(CUE, principal=READER, k=8)
    assert db.explain_recall(out["recall_id"])["hidden_review_states"] == ["disputed", "rejected", "superseded"]
    # History is still reachable by explicit opt-in, as with transition_review.
    history = _ids(db, filters=HISTORY)
    assert old in history and new in history
    assert db.store.get_meta(old)["review_state"] == "superseded"
    assert db.read_content(old) == OLD


def test_supersedes_accepts_a_list_and_retires_every_listed_memory(db):
    first = db.remember(OLD, subject="policy:deploy", created_by="agent:ops")
    second = db.remember(f"{OLD} Night shift too.", subject="policy:deploy", created_by="agent:ops")
    new = db.remember(NEW, subject="policy:deploy", created_by="agent:ops",
                      supersedes=[first, second, first])

    assert _ids(db) == [new]
    assert {db.store.get_meta(i)["review_state"] for i in (first, second)} == {"superseded"}


def test_supersede_writes_one_audit_row_linking_old_to_new(db):
    old = db.remember(OLD, subject="policy:deploy", created_by="agent:ops")
    before = list(db.store.iter_audit())
    new = db.remember(NEW, subject="policy:deploy", created_by="agent:ops", supersedes=[old])
    added = list(db.store.iter_audit())[len(before):]

    assert len(added) == 1
    (row,) = added
    assert (row["action"], row["target"], row["principal"]) == ("remember", new, "agent:ops")
    detail = json.loads(row["body"])["detail"]
    assert detail["supersedes"] == [{"id": old, "from": None, "to": "superseded"}]
    assert db.verify_audit()


def test_supersede_rolls_back_every_write_when_the_audit_append_fails(db, monkeypatch):
    """@positive-control(remember-supersede-atomic)"""
    old = db.remember(OLD, subject="policy:deploy", created_by="agent:ops")
    # The subject key is created before the transaction, as on any write, so the
    # replacement reuses an existing subject and the counts compare only what the
    # transaction writes.
    before = _counts(db)

    def fail(*_args, **_kwargs):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(db.store, "append_audit_in_transaction", fail)
    with pytest.raises(RuntimeError, match="audit store unavailable"):
        db.remember(NEW, subject="policy:deploy", created_by="agent:ops", supersedes=old, memory_id="mem_new")
    monkeypatch.undo()

    assert db.store.get_meta("mem_new") is None
    assert db.store.get_meta(old)["review_state"] is None
    assert _counts(db) == before
    assert _ids(db) == [old]


def test_supersede_refuses_when_the_old_memory_changed_after_it_was_checked(db, monkeypatch):
    """The authorization facts are compare-and-swapped, not trusted from the precheck."""
    old = db.remember(OLD, subject="policy:deploy", created_by="agent:author")
    author = Principal("agent:author", TENANT)
    original = db.store.insert_memory_superseding

    def approved_meanwhile(*args, **kwargs):
        db.store.conn.execute("UPDATE memories SET created_by='human:approver' WHERE id=?", (old,))
        db.store.conn.commit()
        return original(*args, **kwargs)

    monkeypatch.setattr(db.store, "insert_memory_superseding", approved_meanwhile)
    with pytest.raises(RuntimeError, match="changed during remember"):
        db.remember(NEW, subject="policy:deploy", created_by="agent:author", principal=author,
                    supersedes=old, memory_id="mem_new")

    assert db.store.get_meta("mem_new") is None
    assert db.store.get_meta(old)["review_state"] is None


def test_an_unknown_id_in_the_list_refuses_the_whole_write(db):
    old = db.remember(OLD, subject="policy:deploy", created_by="agent:ops")
    before = _counts(db)

    with pytest.raises(KeyError, match="unknown memory id: mem_missing"):
        db.remember(NEW, subject="policy:fresh", created_by="agent:ops", supersedes=[old, "mem_missing"])

    assert _counts(db) == before
    assert db.store.get_meta(old)["review_state"] is None


@pytest.mark.parametrize(
    ("policy", "author"),
    [
        (Policy(roles=("finance",)), "agent:finance"),
        (Policy(classification="restricted"), "agent:finance"),
        (Policy(visibility="private"), "agent:alice"),
    ],
    ids=["role", "clearance", "private"],
)
def test_principal_cannot_supersede_what_it_cannot_read(db, policy, author):
    """@positive-control(remember-supersede-principal)"""
    hidden = db.remember(OLD, subject="policy:deploy", created_by=author, policy=policy)
    bob = Principal("agent:bob", TENANT, roles=("reviewer",))
    before = _counts(db)

    with pytest.raises(KeyError) as missing:
        db.remember(NEW, subject="policy:deploy", created_by=bob.id, principal=bob, supersedes="mem_missing")
    with pytest.raises(KeyError) as refused:
        db.remember(NEW, subject="policy:deploy", created_by=bob.id, principal=bob, supersedes=hidden)

    assert _refusal(refused, hidden) == _refusal(missing, "mem_missing")
    assert _counts(db) == before
    assert db.store.get_meta(hidden)["review_state"] is None
    owner = Principal(author, TENANT, roles=("finance",), clearance="restricted")
    assert hidden in _ids(db, principal=owner)


def test_principal_cannot_supersede_another_tenants_memory(db):
    other = db.with_tenant(OTHER_TENANT)
    try:
        foreign = other.remember(OLD, subject="policy:deploy", created_by="agent:globex")
    finally:
        other.close()
    acme = Principal("agent:ops", TENANT, roles=("approver",))

    with pytest.raises(KeyError) as missing:
        db.remember(NEW, subject="policy:deploy", created_by=acme.id, principal=acme, supersedes="mem_missing")
    with pytest.raises(KeyError) as refused:
        db.remember(NEW, subject="policy:deploy", created_by=acme.id, principal=acme, supersedes=foreign)
    with pytest.raises(KeyError, match="unknown memory id"):
        db.remember(NEW, subject="policy:deploy", created_by="agent:ops", supersedes=foreign)

    assert _refusal(refused, foreign) == _refusal(missing, "mem_missing")
    assert db.store.get_meta(foreign)["review_state"] is None


def test_retiring_needs_authorship_or_a_review_role(db):
    theirs = db.remember(OLD, subject="policy:deploy", created_by="agent:alice")
    bob = Principal("agent:bob", TENANT)
    before = _counts(db)

    with pytest.raises(PermissionError, match="'reviewer' or 'approver' role"):
        db.remember(NEW, subject="policy:deploy", created_by=bob.id, principal=bob, supersedes=theirs)
    assert _counts(db) == before

    own = db.remember(f"{OLD} Weekends too.", subject="policy:deploy", created_by=bob.id)
    db.remember(NEW, subject="policy:deploy", created_by=bob.id, principal=bob, supersedes=own)
    reviewer = Principal("agent:carol", TENANT, roles=("reviewer",))
    db.remember(NEW, subject="policy:deploy", created_by=reviewer.id, principal=reviewer, supersedes=theirs)
    assert {db.store.get_meta(i)["review_state"] for i in (own, theirs)} == {"superseded"}


def test_superseding_an_approved_memory_needs_the_approver_role(db):
    approver = Principal("human:approver", TENANT, roles=("approver",))
    approved = db.remember(OLD, subject="policy:deploy", created_by="agent:ops")
    db.approve(approved, approver)
    reviewer = Principal("agent:carol", TENANT, roles=("reviewer",))

    with pytest.raises(PermissionError, match="'approver' role"):
        db.remember(NEW, subject="policy:deploy", created_by=reviewer.id, principal=reviewer, supersedes=approved)
    assert db.store.get_meta(approved)["review_state"] is None

    new = db.remember(NEW, subject="policy:deploy", created_by=approver.id, principal=approver, supersedes=approved)
    assert _ids(db) == [new]


def test_supersede_follows_the_review_workflow(db):
    reviewer = Principal("agent:carol", TENANT, roles=("reviewer",))
    accepted = db.remember(OLD, subject="policy:deploy", created_by="agent:ops", review_state="proposed")
    db.transition_review(accepted, "accepted", reviewer)
    rejected = db.remember(f"{OLD} Rejected draft.", subject="policy:deploy", created_by="agent:ops",
                           review_state="proposed")
    db.transition_review(rejected, "rejected", reviewer)

    first = db.remember(NEW, subject="policy:deploy", created_by="agent:ops", supersedes=accepted)
    assert db.store.get_meta(accepted)["review_state"] == "superseded"
    with pytest.raises(ValueError, match="superseded -> superseded"):
        db.remember(f"{NEW} Again.", subject="policy:deploy", created_by="agent:ops", supersedes=accepted)
    with pytest.raises(ValueError, match="rejected -> superseded"):
        db.remember(f"{NEW} Again.", subject="policy:deploy", created_by="agent:ops", supersedes=rejected)
    assert _ids(db) == [first]


def test_supersedes_argument_is_validated(db):
    old = db.remember(OLD, subject="policy:deploy", created_by="agent:ops")
    with pytest.raises(ValueError, match="cannot supersede itself"):
        db.remember(NEW, subject="policy:deploy", created_by="agent:ops", memory_id=old, supersedes=old)
    with pytest.raises(TypeError, match="supersedes must be"):
        db.remember(NEW, subject="policy:deploy", created_by="agent:ops", supersedes=[old, 7])
    with pytest.raises(ValueError, match="created_by must equal principal.id"):
        db.remember(NEW, subject="policy:deploy", created_by="agent:ops",
                    principal=Principal("agent:other", TENANT), supersedes=old)
    contract = db.remember("capability contract", subject="continuity:agent", created_by="agent:ops",
                           kind="capability-contract", policy_scope="continuity-privileged", indexed=False)
    with pytest.raises(PermissionError, match="cannot be superseded"):
        db.remember(NEW, subject="policy:deploy", created_by="agent:ops", supersedes=contract)
    with pytest.raises(PermissionError, match="cannot supersede"):
        db.remember("next contract", subject="continuity:agent", created_by="agent:ops",
                    kind="capability-contract", policy_scope="continuity-privileged", indexed=False,
                    supersedes=old)
    assert db.store.get_meta(old)["review_state"] is None
    assert db.store.get_meta(contract)["review_state"] is None


def test_supersede_does_not_tie_the_two_memories_together_for_erasure(db):
    """Forgetting either subject leaves the other memory in place."""
    old = db.remember(OLD, subject="person:old-owner", created_by="agent:ops")
    new = db.remember(NEW, subject="person:new-owner", created_by="agent:ops", supersedes=old)

    erased = db.forget("person:old-owner", actor="agent:privacy")
    assert erased["purged"] == 1
    assert db.store.get_meta(old) is None
    assert _ids(db) == [new]

    again = db.remember(OLD, subject="person:second-owner", created_by="agent:ops")
    newest = db.remember(NEW, subject="person:third-owner", created_by="agent:ops", supersedes=again)
    db.forget("person:third-owner", actor="agent:privacy")
    assert db.store.get_meta(newest) is None
    assert again in _ids(db, filters=HISTORY)


# -- MCP --------------------------------------------------------------------- #

def _call(server, name, arguments):
    output = asyncio.run(server.call_tool(name, arguments))
    if isinstance(output, dict):
        return output
    if isinstance(output, tuple):
        return output[1]
    return json.loads(output[0].text)


def _attempt(server, name, arguments):
    try:
        return _call(server, name, arguments)
    except ToolError as exc:
        return exc


def _mcp_ids(server):
    return [row["id"] for row in _call(server, "recall", {"cue": CUE, "k": 8})["results"]]


@pytest.fixture()
def server(db, monkeypatch):
    monkeypatch.setenv("HEARTWOOD_MCP_ALLOWED_TOOLS", "remember,recall")
    mcp, _db, _backend = build_server(db, principal=Principal("agent:mcp", TENANT))
    return mcp


def test_mcp_remember_supersedes_as_the_server_principal(db, server):
    """@positive-control(remember-supersede-principal)"""
    old = _call(server, "remember", {"content": OLD, "subject": "policy:deploy"})["id"]
    assert old in _mcp_ids(server)

    written = _call(server, "remember", {"content": NEW, "subject": "policy:deploy", "supersedes": [old]})
    assert written["supersedes"] == [old]
    assert _mcp_ids(server) == [written["id"]]

    newer = _call(server, "remember", {"content": f"{NEW} Effective now.", "subject": "policy:deploy",
                                       "supersedes": written["id"]})
    assert _mcp_ids(server) == [newer["id"]]
    assert db.store.get_meta(old)["review_state"] == "superseded"


def test_mcp_remember_refuses_a_memory_its_principal_cannot_read_like_an_unknown_id(db, server):
    """@positive-control(remember-supersede-principal)"""
    hidden = db.remember(OLD, subject="policy:deploy", created_by="agent:finance",
                         policy=Policy(roles=("finance",)))
    other = db.with_tenant(OTHER_TENANT)
    try:
        foreign = other.remember(OLD, subject="policy:deploy", created_by="agent:globex")
    finally:
        other.close()
    before = _counts(db)

    missing = _attempt(server, "remember", {"content": NEW, "subject": "policy:deploy",
                                            "supersedes": ["mem_missing"]})
    assert isinstance(missing, ToolError), missing
    # The refusal must come from the supersede check, not from an unknown argument.
    assert "unknown memory id: mem_missing" in str(missing)
    for target in (hidden, foreign):
        refused = _attempt(server, "remember", {"content": NEW, "subject": "policy:deploy",
                                                "supersedes": [target]})
        assert isinstance(refused, ToolError), refused
        assert str(refused).replace(target, "<id>") == str(missing).replace("mem_missing", "<id>")
        assert OLD not in str(refused)

    assert _counts(db) == before
    assert db.store.get_meta(hidden)["review_state"] is None
    finance = Principal("agent:finance", TENANT, roles=("finance",))
    assert hidden in _ids(db, principal=finance)


def test_mcp_remember_cannot_retire_another_principals_memory_without_a_review_role(db, server):
    theirs = db.remember(OLD, subject="policy:deploy", created_by="agent:alice")
    before = _counts(db)

    refused = _attempt(server, "remember", {"content": NEW, "subject": "policy:deploy", "supersedes": [theirs]})
    assert isinstance(refused, ToolError), refused
    assert "'reviewer' or 'approver' role" in str(refused)
    assert _counts(db) == before
    assert theirs in _mcp_ids(server)
