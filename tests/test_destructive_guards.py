"""Nobody destroys a record they could not edit, and deleted files stay deleted.

These tests pin four guards on the verbs that remove records:

- memory-tool `delete` with a principal purges a file's current version only
  when that principal may supersede it: its author, a `reviewer`, or an
  `approver` for an approved version. A refusal writes nothing and names no id.
- `purge` and `approve` refuse another tenant's record like an unknown id.
- the OpenClaw-style example adapter retires a path's earlier versions when the
  path is rewritten or deleted, so neither search nor a restart brings old text
  back.
- a version a stale second writer superseded does not hide an older live version
  of the same file from the principal who owns it, and delete or rename then
  retires that version instead of purging it.

None of them destroys a record the same call did not destroy before; the pins
compare the destroyed ids directly.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood  # noqa: E402
from heartwood.adapters.mcp_server import build_server  # noqa: E402
from heartwood.adapters.memory_tool import MemoryToolBackend  # noqa: E402
from heartwood.adapters.openclaw import HeartwoodOpenClawMemoryRuntime  # noqa: E402
from heartwood.cli import main as cli_main  # noqa: E402
from heartwood.envelope import Policy  # noqa: E402
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
APPROVER = Principal("agent:approver", TENANT, roles=("approver",))
READER = Principal("agent:reader", TENANT, roles=("finance",), clearance="restricted")
FIN = Principal("agent:fin", TENANT, clearance="restricted")
MEMORY_ID = re.compile(r"mem_[a-z0-9]{6,}")


@pytest.fixture()
def db(tmp_path):
    embedder, reranker = dev_models()
    client = Heartwood(path=tmp_path / "heartwood.db", tenant=TENANT, embedder=embedder, reranker=reranker)
    try:
        yield client
    finally:
        client.close()


def _ids(db, tenant=TENANT):
    return {m["id"] for m in db.store.candidate_meta(tenant)}


def _audit_count(db):
    return len(list(db.store.iter_audit()))


def _contents(db, filters=None, principal=READER):
    return [row["content"] for row in db.recall(CUE, principal=principal, filters=filters, k=20)["results"]]


def _rows_at(db, path):
    return [m for m in db.store.candidate_meta(TENANT) if (m.get("source") or {}).get("uri") == path]


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


# -- memory-tool delete needs the authorship or role an edit needs ---------- #

def test_delete_of_another_principals_file_needs_a_review_role(db):
    """@positive-control(memory-tool-delete-principal)"""
    MemoryToolBackend(db, principal=ALICE).handle({"command": "create", "path": PATH, "file_text": V1})
    alice_id = _rows_at(db, PATH)[0]["id"]
    ids_before, audit_before = _ids(db), _audit_count(db)

    out = MemoryToolBackend(db, principal=BOB).handle({"command": "delete", "path": PATH})
    assert out == (f"Error: {PATH} was not deleted: deleting another principal's memory "
                   "requires the 'reviewer' or 'approver' role")
    assert MEMORY_ID.search(out) is None
    assert _ids(db) == ids_before
    assert _audit_count(db) == audit_before
    assert _contents(db) == [V1]

    # A reviewer may delete it, and so may its author.
    assert MemoryToolBackend(db, principal=REVIEWER).handle(
        {"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"
    assert _ids(db) == ids_before - {alice_id}
    alice = MemoryToolBackend(db, principal=ALICE)
    alice.handle({"command": "create", "path": PATH, "file_text": V2})
    assert alice.handle({"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"
    assert _contents(db) == []


def test_a_refused_directory_delete_deletes_no_file(db):
    """@positive-control(memory-tool-delete-principal)"""
    MemoryToolBackend(db, principal=BOB).handle(
        {"command": "create", "path": "/memories/team/bob.md", "file_text": V2})
    MemoryToolBackend(db, principal=ALICE).handle(
        {"command": "create", "path": "/memories/team/alice.md", "file_text": V1})
    ids_before, audit_before = _ids(db), _audit_count(db)

    out = MemoryToolBackend(db, principal=BOB).handle({"command": "delete", "path": "/memories/team"})
    assert out.startswith("Error: /memories/team was not deleted: deleting another principal's memory")
    assert _ids(db) == ids_before
    assert _audit_count(db) == audit_before


def test_deleting_an_approved_version_needs_the_approver_role(db):
    """@positive-control(memory-tool-delete-principal)"""
    MemoryToolBackend(db, principal=ALICE).handle({"command": "create", "path": PATH, "file_text": V1})
    db.approve(_rows_at(db, PATH)[0]["id"], APPROVER)
    ids_before = _ids(db)

    out = MemoryToolBackend(db, principal=REVIEWER).handle({"command": "delete", "path": PATH})
    assert out == f"Error: {PATH} was not deleted: deleting an approved memory requires the 'approver' role"
    assert _ids(db) == ids_before
    assert MemoryToolBackend(db, principal=APPROVER).handle(
        {"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"


def test_a_backend_without_a_principal_still_deletes_any_file(db):
    """Trusted in-process callers keep the old behavior."""
    MemoryToolBackend(db, principal=ALICE).handle({"command": "create", "path": PATH, "file_text": V1})
    assert MemoryToolBackend(db).handle({"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"
    assert _rows_at(db, PATH) == []


def test_mcp_memory_delete_runs_the_same_check_as_the_servers_principal(db, monkeypatch):
    """@positive-control(memory-tool-delete-principal)"""
    monkeypatch.setenv("HEARTWOOD_MCP_ALLOWED_TOOLS", "recall,memory")
    MemoryToolBackend(db, principal=ALICE).handle({"command": "create", "path": PATH, "file_text": V1})
    alice_id = _rows_at(db, PATH)[0]["id"]

    server, _db, _backend = build_server(db)
    out = _call(server, "memory", {"command": "delete", "path": PATH})
    assert out.startswith(f"Error: {PATH} was not deleted"), out
    assert [m["id"] for m in _rows_at(db, PATH)] == [alice_id]

    reviewer, _db, _backend = build_server(db, principal=Principal("agent:mcp", TENANT, roles=("reviewer",)))
    assert _call(reviewer, "memory", {"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"
    assert _rows_at(db, PATH) == []


# -- purge and approve stay inside the client's tenant --------------------- #

def test_purge_refuses_another_tenants_record(db):
    """@positive-control(purge-tenant)"""
    other = db.with_tenant(OTHER_TENANT)
    foreign = other.remember(V1, subject="policy:deploy", created_by="agent:globex")
    before, audit_before = db.store.get_meta(foreign), _audit_count(db)

    with pytest.raises(KeyError, match="unknown memory id"):
        db.purge(foreign, actor="agent:ops")
    assert db.store.get_meta(foreign) == before
    assert _audit_count(db) == audit_before
    # An unknown id still returns False, and the owning tenant may purge.
    assert db.purge("mem_doesnotexist", actor="agent:ops") is False
    assert other.purge(foreign, actor="agent:globex") is True
    assert db.store.get_meta(foreign) is None


def test_cli_purge_refuses_an_id_from_another_tenant(db, capsys):
    """@positive-control(purge-tenant)"""
    foreign = db.with_tenant(OTHER_TENANT).remember(V1, subject="policy:deploy", created_by="agent:globex")
    args = ["purge", "--db", db.path, "--id", foreign, "--dev-models"]

    with pytest.raises(SystemExit) as refused:
        cli_main([*args, "--tenant", TENANT])
    assert refused.value.code == 1
    assert "unknown memory id" in capsys.readouterr().err
    assert db.store.get_meta(foreign) is not None

    cli_main([*args, "--tenant", OTHER_TENANT])
    assert json.loads(capsys.readouterr().out)["purged"] is True
    assert db.store.get_meta(foreign) is None


def test_approve_refuses_another_tenants_record(db):
    """@positive-control(approve-tenant)"""
    other = db.with_tenant(OTHER_TENANT)
    foreign = other.remember(V1, subject="policy:deploy", created_by="agent:globex")
    before, audit_before = db.store.get_meta(foreign), _audit_count(db)

    with pytest.raises(KeyError, match="unknown memory id"):
        db.approve(foreign, APPROVER)
    assert db.store.get_meta(foreign) == before
    assert _audit_count(db) == audit_before
    other.approve(foreign, Principal("agent:globex-approver", OTHER_TENANT, roles=("approver",)))
    assert db.store.get_meta(foreign)["epistemic"] == "approved-canonical"


# -- the OpenClaw-style example adapter ------------------------------------ #

def _search(runtime):
    return [row["text"] for row in runtime.memory_search(CUE, max_results=20)["results"]]


def _openclaw_legacy(db, content, uri="/memories/notes/deploy.md"):
    """A version written the way the example adapter wrote before rewrites superseded."""
    return db.remember(content, subject="openclaw-memory", created_by="agent:openclaw", kind="working",
                       epistemic="imported-source", source={"kind": "openclaw-memory", "uri": uri},
                       policy=Policy(classification="internal"), model_version="openclaw-memory-runtime")


def test_openclaw_rewrite_leaves_only_the_new_text(db):
    """@positive-control(openclaw-rewrite-supersedes)"""
    runtime = HeartwoodOpenClawMemoryRuntime(db)
    old = runtime.remember_markdown("notes/deploy.md", V1)
    new = runtime.remember_markdown("notes/deploy.md", V2)

    assert _search(runtime) == [V2]
    assert runtime.memory_get("notes/deploy.md")["text"] == V2
    assert db.store.get_meta(old)["review_state"] == "superseded"
    assert db.store.get_meta(new)["review_state"] is None
    assert sorted(_contents(db, HISTORY)) == sorted([V1, V2])


def test_openclaw_delete_leaves_no_old_text_and_the_path_does_not_come_back(db):
    """@positive-control(openclaw-delete-retires)"""
    runtime = HeartwoodOpenClawMemoryRuntime(db)
    runtime.remember_markdown("notes/deploy.md", V1)
    runtime.remember_markdown("notes/deploy.md", V2)
    assert runtime.delete_path("notes/deploy.md") == {"path": "notes/deploy.md", "deleted": 1}

    assert _search(runtime) == []
    restarted = HeartwoodOpenClawMemoryRuntime(db)
    assert restarted.memory_get("notes/deploy.md") == {"text": "", "path": "notes/deploy.md"}
    assert _search(restarted) == []
    # The path can be written again, and only the new text answers.
    restarted.remember_markdown("notes/deploy.md", "Deploy approvals: a release manager approves.")
    assert _search(restarted) == ["Deploy approvals: a release manager approves."]


def test_openclaw_delete_purges_only_the_current_version_and_retires_the_rest(db):
    """Pin: delete destroys exactly what it destroyed before, the current version.

    @positive-control(openclaw-delete-retires)"""
    legacy = _openclaw_legacy(db, V1)
    current = _openclaw_legacy(db, V2)
    runtime = HeartwoodOpenClawMemoryRuntime(db)
    before = _ids(db)

    runtime.delete_path("notes/deploy.md")

    assert before - _ids(db) == {current}
    assert db.store.get_meta(legacy)["review_state"] == "superseded"
    assert _search(runtime) == []
    assert HeartwoodOpenClawMemoryRuntime(db).memory_get("notes/deploy.md")["text"] == ""
    assert db.verify_audit() is True


# -- a stale writer's deleted version does not hide the owner's live file -- #

def _stale_writer_race(db):
    """fin owns a restricted file; bob's backend was built before it existed, so
    bob writes, edits and deletes his own versions at the same path. Returns
    fin's version, which bob can neither read nor retire."""
    bob = MemoryToolBackend(db, principal=BOB)
    MemoryToolBackend(db, principal=FIN, classification="restricted").handle(
        {"command": "create", "path": PATH, "file_text": "Fin deploy plan K-FIN"})
    fins = _rows_at(db, PATH)[0]["id"]
    bob.handle({"command": "create", "path": PATH, "file_text": V1})
    bob.handle({"command": "str_replace", "path": PATH, "old_str": "one engineer may", "new_str": "two may"})
    assert bob.handle({"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"
    assert {m["id"]: m["review_state"] for m in _rows_at(db, PATH)}[fins] is None
    return fins


def test_a_stale_writers_deleted_version_does_not_hide_the_owners_live_file(db):
    """@positive-control(memory-tool-index-live)"""
    fins = _stale_writer_race(db)

    fin = MemoryToolBackend(db, principal=FIN, classification="restricted")
    assert "K-FIN" in fin.handle({"command": "view", "path": PATH})
    assert PATH in fin.handle({"command": "view", "path": "/memories"})
    # bob still cannot read it, and the path stays taken.
    bob = MemoryToolBackend(db, principal=BOB)
    assert bob.handle({"command": "view", "path": PATH}).startswith(f"The path {PATH} does not exist")
    assert bob.handle({"command": "create", "path": PATH, "file_text": "x"}) == f"Error: File {PATH} already exists"
    # fin can edit it, and the edit retires the old version as usual.
    assert fin.handle({"command": "str_replace", "path": PATH, "old_str": "K-FIN",
                       "new_str": "K-FIN-2"}).startswith("The memory file has been edited.")
    assert db.store.get_meta(fins)["review_state"] == "superseded"
    # The edited version is the newest one, so delete purges it as usual.
    edited, before = fin.index[PATH], _ids(db)
    assert fin.handle({"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"
    assert before - _ids(db) == {edited}


@pytest.mark.parametrize(
    "command",
    [{"command": "delete", "path": PATH},
     {"command": "rename", "old_path": PATH, "new_path": "/memories/moved.md"}],
    ids=["delete", "rename"],
)
def test_delete_and_rename_after_a_stale_writer_destroy_nothing_they_did_not_before(db, command):
    """Pin: before this change the superseded version hid fin's file, so delete
    and rename could not purge it. They still do not: they retire it.

    @positive-control(memory-tool-index-live)"""
    fins = _stale_writer_race(db)
    fin = MemoryToolBackend(db, principal=FIN, classification="restricted")
    before = _ids(db)

    fin.handle(command)

    assert before - _ids(db) == set()
    assert db.read_content(fins) == "Fin deploy plan K-FIN"


def test_delete_after_a_stale_writer_retires_the_owners_version(db):
    """@positive-control(memory-tool-index-live)"""
    fins = _stale_writer_race(db)
    fin = MemoryToolBackend(db, principal=FIN, classification="restricted")

    assert fin.handle({"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"
    assert db.store.get_meta(fins)["review_state"] == "superseded"
    assert _contents(db, principal=FIN) == []
    restarted = MemoryToolBackend(db, principal=FIN, classification="restricted")
    assert restarted.handle({"command": "view", "path": PATH}).startswith(f"The path {PATH} does not exist")
    # A file created at the path afterwards is deleted as usual.
    fin.handle({"command": "create", "path": PATH, "file_text": V2})
    created, before = fin.index[PATH], _ids(db)
    assert fin.handle({"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"
    assert before - _ids(db) == {created}


def test_a_deleted_files_rejected_version_does_not_come_back(db):
    """Only a version default recall still returns can reopen a deleted path."""
    rejected = db.remember("Deploy approvals: nobody approves. K-REJECTED", subject="memory-tool-user",
                           created_by="agent:memory", kind="working", source={"kind": "memfile", "uri": PATH},
                           policy=Policy(visibility="tenant"), review_state="proposed")
    db.transition_review(rejected, "rejected", REVIEWER)
    db.remember(V1, subject="memory-tool-user", created_by="agent:memory", kind="working",
                source={"kind": "memfile", "uri": PATH}, policy=Policy(visibility="tenant"))
    tool = MemoryToolBackend(db)
    tool.handle({"command": "str_replace", "path": PATH, "old_str": "one engineer may", "new_str": "two may"})
    assert tool.handle({"command": "delete", "path": PATH}) == f"Successfully deleted {PATH}"

    restarted = MemoryToolBackend(db)
    assert restarted.handle({"command": "view", "path": PATH}).startswith(f"The path {PATH} does not exist")
    assert db.store.get_meta(rejected)["review_state"] == "rejected"
