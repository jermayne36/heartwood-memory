"""Editing or deleting a memory-tool file leaves no old text in default recall.

Every memory-tool edit writes a new version. These tests pin that the earlier
version stops answering default recall in the same write, that a deleted file's
versions stop answering and the file does not come back after a restart, and
that none of this destroys more than delete did before: delete still purges only
the current version, and the earlier ones stay reachable as superseded history.
They also cover the verbs this work touched: Heartwood.supersede, the tenant
guard on transition_review / expire / set_indexed, and egress classification of
a span that resolves from a stored memory.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood  # noqa: E402
from heartwood.adapters.mcp_server import build_server  # noqa: E402
from heartwood.adapters.memory_tool import MemoryToolBackend  # noqa: E402
from heartwood.envelope import Policy, hash_content  # noqa: E402
from heartwood.importers.markdown import dev_models  # noqa: E402
from heartwood.policy import Principal  # noqa: E402

TENANT = "tenant:acme"
OTHER_TENANT = "tenant:globex"
PATH = "/memories/deploy.md"
CUE = "deploy approvals engineers approve production"
V1 = "Deploy approvals: one engineer may approve production deploys. K-OLDVERSION"
V2 = "Deploy approvals: production deploys need two approvers."
HISTORY = {"include_review_states": ["superseded"]}
ALICE = Principal("agent:alice", TENANT)
BOB = Principal("agent:bob", TENANT)
REVIEWER = Principal("agent:rev", TENANT, roles=("reviewer",))
READER = Principal("agent:reader", TENANT, roles=("finance",), clearance="restricted")
RESTRICTED = Policy(classification="restricted", roles=("finance",))


@pytest.fixture()
def db(tmp_path):
    embedder, reranker = dev_models()
    client = Heartwood(path=tmp_path / "heartwood.db", tenant=TENANT, embedder=embedder, reranker=reranker)
    try:
        yield client
    finally:
        client.close()


def _contents(db, filters=None, principal=READER):
    return [row["content"] for row in db.recall(CUE, principal=principal, filters=filters, k=20)["results"]]


def _rows_at(db, path):
    return [m for m in db.store.candidate_meta(TENANT) if (m.get("source") or {}).get("uri") == path]


def _legacy_version(db, content, path=PATH, created_by="agent:memory"):
    """A version written the way the memory tool wrote edits before they superseded."""
    return db.remember(content, subject="memory-tool-user", created_by=created_by, kind="working",
                       epistemic="model-generated", source={"kind": "memfile", "uri": path},
                       policy=Policy(visibility="tenant"), model_version="memory-tool")


def _events(db, action):
    rows = [row for row in db.store.iter_audit() if row["action"] == action]
    return [(row["target"], json.loads(row["body"])["detail"]) for row in rows]


@pytest.mark.parametrize(
    "edit",
    [
        {"command": "str_replace", "old_str": "one engineer may approve production deploys. K-OLDVERSION",
         "new_str": "production deploys need two approvers."},
        {"command": "insert", "insert_line": 0, "insert_text": "Deploy approvals: two approvers now."},
    ],
    ids=["str_replace", "insert"],
)
def test_edit_leaves_only_the_new_text_in_default_recall(db, edit):
    """@positive-control(memory-tool-edit-supersedes)"""
    tool = MemoryToolBackend(db)
    tool.handle({"command": "create", "path": PATH, "file_text": V1})
    out = tool.handle({"path": PATH, **edit})
    assert out.startswith(("The memory file has been edited.", f"The file {PATH} has been edited.")), out

    current = db.read_content(tool.index[PATH])
    returned = _contents(db)
    assert current in returned
    assert V1 not in returned
    # The old version is history, not gone, and the new one derives from it.
    assert V1 in _contents(db, HISTORY)
    old_id = next(m["id"] for m in _rows_at(db, PATH) if m["review_state"] == "superseded")
    assert db.store.parents(tool.index[PATH]) == [old_id]
    assert [detail["supersedes"] for _target, detail in _events(db, "remember") if "supersedes" in detail] == [
        [{"id": old_id, "from": None, "to": "superseded"}]
    ]


@pytest.mark.parametrize(
    "command, path",
    [
        ({"command": "str_replace", "path": PATH, "old_str": "an engineer and a lead approve",
          "new_str": "two approvers approve"}, PATH),
        ({"command": "rename", "old_path": PATH, "new_path": "/memories/final.md"}, "/memories/final.md"),
    ],
    ids=["str_replace", "rename"],
)
def test_edit_supersedes_versions_written_before_edits_did(db, command, path):
    """@positive-control(memory-tool-edit-supersedes)"""
    _legacy_version(db, V1)
    _legacy_version(db, "Deploy approvals: an engineer and a lead approve production deploys.")
    tool = MemoryToolBackend(db)

    assert not tool.handle(command).startswith("Error")

    live = [m["id"] for m in db.store.candidate_meta(TENANT)
            if (m.get("source") or {}).get("kind") == "memfile" and m["review_state"] is None]
    assert live == [tool.index[path]]
    assert _contents(db) == [db.read_content(tool.index[path])]


def test_delete_leaves_nothing_from_the_path_in_default_recall_or_after_a_restart(db):
    """@positive-control(memory-tool-delete-retires)"""
    tool = MemoryToolBackend(db)
    tool.handle({"command": "create", "path": PATH, "file_text": V1})
    tool.handle({"command": "str_replace", "path": PATH, "old_str": "one engineer may", "new_str": "two engineers"})
    assert tool.handle({"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"

    assert _contents(db) == []
    restarted = MemoryToolBackend(db)
    assert restarted.handle({"command": "view", "path": PATH}).startswith(f"The path {PATH} does not exist")
    assert PATH not in restarted.handle({"command": "view", "path": "/memories"})
    for command in ({"command": "str_replace", "path": PATH, "old_str": "K-OLDVERSION", "new_str": "x"},
                    {"command": "delete", "path": PATH},
                    {"command": "rename", "old_path": PATH, "new_path": "/memories/moved.md"}):
        assert restarted.handle(command).startswith("Error"), command
    # The path is free again once its file is deleted.
    assert restarted.handle({"command": "create", "path": PATH, "file_text": V2}).startswith("File created")
    assert _contents(db) == [V2]


def test_delete_purges_only_the_current_version_and_retires_the_rest(db):
    """Pin: delete destroys exactly what it destroyed before, the current
    version, and retires the earlier ones without deleting them.

    @positive-control(memory-tool-delete-retires)"""
    v1 = _legacy_version(db, V1)
    v2 = _legacy_version(db, V2)
    tool = MemoryToolBackend(db)
    before = {m["id"] for m in db.store.candidate_meta(TENANT)}

    assert tool.handle({"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"

    after = {m["id"] for m in db.store.candidate_meta(TENANT)}
    assert before - after == {v2}
    assert db.store.get_meta(v1)["review_state"] == "superseded"
    assert db.read_content(v1) == V1
    assert _contents(db) == []
    assert _contents(db, HISTORY) == [V1]
    assert _events(db, "supersede") == [(v1, {"from": None, "to": "superseded", "reason": "memory tool delete"})]
    assert [target for target, _detail in _events(db, "purge")] == [v2]
    assert db.verify_audit() is True


def test_forget_still_erases_the_superseded_history(db):
    tool = MemoryToolBackend(db, subject="user:jane")
    tool.handle({"command": "create", "path": PATH, "file_text": V1})
    tool.handle({"command": "str_replace", "path": PATH, "old_str": "one engineer may", "new_str": "two engineers"})
    tool.handle({"command": "delete", "path": PATH})

    receipt = db.forget("user:jane", mode="hard", reason="erasure request")
    assert receipt["purged"] == 1
    assert _rows_at(db, PATH) == []
    assert _contents(db, HISTORY) == []


def test_rename_leaves_no_old_version_at_the_old_path(db):
    """@positive-control(memory-tool-edit-supersedes)"""
    tool = MemoryToolBackend(db)
    tool.handle({"command": "create", "path": PATH, "file_text": V1})
    tool.handle({"command": "str_replace", "path": PATH, "old_str": "one engineer may", "new_str": "two engineers"})
    renamed = tool.handle({"command": "rename", "old_path": PATH, "new_path": "/memories/final.md"})
    assert renamed == f"Successfully renamed {PATH} to /memories/final.md"

    assert _contents(db) == [db.read_content(tool.index["/memories/final.md"])]
    restarted = MemoryToolBackend(db)
    assert restarted.handle({"command": "view", "path": PATH}).startswith(f"The path {PATH} does not exist")
    assert restarted.handle({"command": "create", "path": PATH, "file_text": V2}).startswith("File created")


@pytest.mark.parametrize(
    "command",
    [
        {"command": "str_replace", "path": PATH, "old_str": "one engineer may", "new_str": "anyone may"},
        {"command": "insert", "path": PATH, "insert_line": 0, "insert_text": "Anyone may approve."},
        {"command": "rename", "old_path": PATH, "new_path": "/memories/bob.md"},
    ],
    ids=["str_replace", "insert", "rename"],
)
def test_edit_of_another_principals_version_needs_a_review_role(db, command):
    """@positive-control(memory-tool-edit-supersedes)"""
    MemoryToolBackend(db, principal=ALICE).handle({"command": "create", "path": PATH, "file_text": V1})
    alice_id = _rows_at(db, PATH)[0]["id"]
    rows_before = len(db.store.candidate_meta(TENANT))

    out = MemoryToolBackend(db, principal=BOB).handle(command)
    assert out == (f"Error: {command.get('path', PATH)} was not "
                   f"{'renamed' if command['command'] == 'rename' else 'edited'}: superseding another "
                   "principal's memory requires the 'reviewer' or 'approver' role")
    assert len(db.store.candidate_meta(TENANT)) == rows_before
    assert db.store.get_meta(alice_id)["review_state"] is None
    assert _contents(db) == [V1]

    # A reviewer may replace it, and the replacement is the only current text.
    reviewer = MemoryToolBackend(db, principal=REVIEWER)
    out = reviewer.handle(command)
    assert not out.startswith("Error"), out
    if command["command"] == "rename":
        assert db.store.get_meta(alice_id) is None   # rename purges the old path's version, as before
        current = reviewer.index["/memories/bob.md"]
    else:
        assert db.store.get_meta(alice_id)["review_state"] == "superseded"
        current = reviewer.index[PATH]
    assert [row["id"] for row in db.recall(CUE, principal=READER, k=20)["results"]] == [current]


def test_edit_and_delete_leave_a_version_the_principal_cannot_read_alone(db):
    """A version the principal cannot read is neither retired nor named in a refusal."""
    hidden = db.remember("Restricted deploy note.", subject="memory-tool-user", created_by="agent:alice",
                         kind="working", source={"kind": "memfile", "uri": PATH}, policy=RESTRICTED)
    _legacy_version(db, V1, created_by="agent:bob")
    bob = MemoryToolBackend(db, principal=BOB)

    assert bob.handle({"command": "str_replace", "path": PATH, "old_str": "one engineer may",
                       "new_str": "two engineers"}).startswith("The memory file has been edited.")
    assert bob.handle({"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"
    assert db.store.get_meta(hidden)["review_state"] is None
    assert _contents(db) == ["Restricted deploy note."]


def test_a_principal_backend_authors_as_its_principal(db):
    with pytest.raises(ValueError, match="created_by must equal principal.id"):
        MemoryToolBackend(db, principal=ALICE, created_by="agent:someone-else")
    assert MemoryToolBackend(db, principal=ALICE, created_by="agent:alice").created_by == "agent:alice"


def _call(server, name, arguments):
    output = asyncio.run(server.call_tool(name, arguments))
    if isinstance(output, tuple):
        output = output[1]
    if isinstance(output, dict):
        return output["result"] if set(output) == {"result"} else output
    text = output[0].text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def test_mcp_memory_edit_and_delete_leave_no_old_text_in_mcp_recall(db, monkeypatch):
    """@positive-control(memory-tool-edit-supersedes)"""
    monkeypatch.setenv("HEARTWOOD_MCP_ALLOWED_TOOLS", "recall,memory")
    server, _db, _backend = build_server(db)
    _call(server, "memory", {"command": "create", "path": PATH, "file_text": V1})
    _call(server, "memory", {"command": "str_replace", "path": PATH, "old_str": "one engineer may approve",
                             "new_str": "two approvers approve"})

    def recalled():
        return [row["content"] for row in _call(server, "recall", {"cue": CUE, "k": 20})["results"]]

    assert recalled() == [V1.replace("one engineer may approve", "two approvers approve")]
    _call(server, "memory", {"command": "delete", "path": PATH})
    assert recalled() == []


# -- Heartwood.supersede -------------------------------------------------- #

def test_supersede_retires_without_a_new_write_and_audits_each_record(db):
    """@positive-control(supersede-atomic)"""
    old = db.remember(V1, subject="policy:deploy", created_by="agent:alice")
    older = db.remember(V2, subject="policy:deploy", created_by="agent:alice")
    rows_before = len(db.store.candidate_meta(TENANT))

    changes = db.supersede([old, older], actor="agent:alice", principal=ALICE, reason="replaced")

    assert changes == [{"id": old, "from": None, "to": "superseded"},
                       {"id": older, "from": None, "to": "superseded"}]
    assert len(db.store.candidate_meta(TENANT)) == rows_before
    assert _contents(db) == []
    assert sorted(_contents(db, HISTORY)) == sorted([V1, V2])
    assert _events(db, "supersede") == [(old, {"from": None, "to": "superseded", "reason": "replaced"}),
                                        (older, {"from": None, "to": "superseded", "reason": "replaced"})]
    assert db.supersede([], actor="agent:alice") == []


def test_supersede_follows_the_remember_supersedes_rules(db):
    mine = db.remember(V1, subject="policy:deploy", created_by="agent:bob")
    alices = db.remember(V2, subject="policy:deploy", created_by="agent:alice")
    hidden = db.remember("Restricted.", subject="policy:deploy", created_by="agent:bob", policy=RESTRICTED)

    with pytest.raises(ValueError, match="actor must equal principal.id"):
        db.supersede([mine], actor="agent:alice", principal=BOB)
    with pytest.raises(KeyError, match="unknown memory id"):
        db.supersede([mine, hidden], actor="agent:bob", principal=BOB)
    with pytest.raises(PermissionError, match="reviewer"):
        db.supersede([mine, alices], actor="agent:bob", principal=BOB)
    # Each refusal left everything as it was, with no audit row.
    assert {db.store.get_meta(i)["review_state"] for i in (mine, alices, hidden)} == {None}
    assert _events(db, "supersede") == []
    db.supersede([mine], actor="agent:bob", principal=BOB)
    with pytest.raises(ValueError, match="superseded -> superseded"):
        db.supersede([mine], actor="agent:bob", principal=BOB)


def test_supersede_writes_nothing_when_a_record_changed_after_it_was_checked(db):
    first = db.remember(V1, subject="policy:deploy", created_by="agent:alice")
    second = db.remember(V2, subject="policy:deploy", created_by="agent:alice")
    targets = db._superseded_targets([first, second], principal=None, memory_id=None, writing_contract=False)
    targets[1]["expected"]["created_by"] = "agent:someone-else"
    audit_before = len(list(db.store.iter_audit()))

    assert db.store.supersede_audited(TENANT, targets, principal="agent:alice", audit_bodies=["{}", "{}"]) is None
    assert db.store.get_meta(first)["review_state"] is None
    assert len(list(db.store.iter_audit())) == audit_before


# -- tenant guard on the audited retirement verbs ------------------------- #

@pytest.mark.parametrize(
    "verb",
    [
        lambda db, mem_id: db.transition_review(mem_id, "accepted", REVIEWER),
        lambda db, mem_id: db.expire(mem_id, "2020-01-01T00:00:00+00:00", actor="agent:ops"),
        lambda db, mem_id: db.set_indexed(mem_id, False, actor="agent:ops"),
        lambda db, mem_id: db.supersede([mem_id], actor="agent:ops"),
    ],
    ids=["transition_review", "expire", "set_indexed", "supersede"],
)
def test_retirement_verbs_refuse_another_tenants_record(db, verb):
    """@positive-control(retirement-tenant-guard)"""
    other = db.with_tenant(OTHER_TENANT)
    foreign = other.remember(V1, subject="policy:deploy", created_by="agent:globex", review_state="proposed")
    before = db.store.get_meta(foreign)
    audit_before = len(list(db.store.iter_audit()))

    with pytest.raises(KeyError, match="unknown memory id"):
        verb(db, foreign)
    assert db.store.get_meta(foreign) == before
    assert len(list(db.store.iter_audit())) == audit_before
    # The same verb on the owning tenant's client still works.
    verb(other, foreign)


# -- egress: a span from a stored memory is at least that memory's class -- #

MODEL = {"runtime": "external", "provider": "p", "region": "r", "retention": "zero", "training_opt_out": True}
DENY_RESTRICTED = {"allow_external_models": True, "allowed_providers": ["p"], "allowed_regions": ["r"],
                   "deny_classifications": ["restricted"]}
SPAN_TEXT = "K-SPAN restricted ledger line"


def _egress(db, memory_id, principal, **label):
    span = {"span_id": "s", "memory_id": memory_id, "text_ref": "encrypted", "text_index": 0,
            "content_hash": hash_content(SPAN_TEXT), **label}
    return db.evaluate_egress({"request_id": "r", "model": MODEL, "policy": DENY_RESTRICTED,
                               "source_spans": [span]}, principal=principal)


def test_egress_denies_an_unlabelled_span_from_a_restricted_memory(db):
    """@positive-control(egress-stored-classification)"""
    restricted = db.remember("Ledger summary.", subject="ledger", created_by="agent:alice", policy=RESTRICTED,
                             source_spans=({"span_id": "s1", "text": SPAN_TEXT},))
    internal = db.remember("Ledger summary.", subject="ledger", created_by="agent:alice",
                           source_spans=({"span_id": "s1", "text": SPAN_TEXT},))

    labelled = _egress(db, restricted, READER, classification="restricted")
    assert labelled["decision"] == "denied"
    unlabelled = _egress(db, restricted, READER)
    assert unlabelled["decision"] == "denied"
    assert unlabelled["classifications"] == ["restricted"] and unlabelled["payload"] == []
    # A label below the stored class does not lower it either.
    assert _egress(db, restricted, READER, classification="public")["decision"] == "denied"
    # Positive control: the same span from an internal memory still leaves.
    allowed = _egress(db, internal, READER)
    assert allowed["decision"] == "external_model_allowed"
    assert allowed["payload"][0] == {"span_id": "s", "classification": "internal", "pii_labels": [],
                                     "text": SPAN_TEXT}


def test_egress_classification_reveals_nothing_about_a_memory_the_principal_cannot_read(db):
    restricted = db.remember("Ledger summary.", subject="ledger", created_by="agent:alice", policy=RESTRICTED,
                             source_spans=({"span_id": "s1", "text": SPAN_TEXT},))
    outsider = Principal("agent:outsider", TENANT)

    hidden = _egress(db, restricted, outsider)
    unknown = _egress(db, "mem_does_not_exist", outsider)
    assert hidden["decision"] == unknown["decision"] == "external_model_allowed"
    assert hidden["classifications"] == unknown["classifications"] == ["internal"]
    assert hidden["payload"] == unknown["payload"]
    assert SPAN_TEXT not in json.dumps(hidden)
